"""
Centralized JSON error log for the diagnose feature.

Captures ERROR+ from the root logger into logs/errors.jsonl as single-line
JSON objects with Flask request context. Designed to be read by the
/diagnose UI (tail-read, parsed, key-whitelisted).

Sensitive data (API keys, passwords, broker tokens, encryption key) is
redacted before write via SensitiveDataFilter — defense-in-depth so an
accidental logger.error(f"...{api_key}...") never lands on disk.
"""

import json
import logging
import os
import re
import traceback
from datetime import datetime
from pathlib import Path

# Patterns must match the forms the codebase actually emits:
# repr (`'apikey': 'X'`), JSON (`"apikey":"X"`), shell (`apikey="X"`),
# bare assignment (`apikey=X`). Value class excludes whitespace, quotes,
# and JSON/dict structure so JWTs and base64 tokens are fully consumed.
SENSITIVE_PATTERNS = [
    # Bearer header tokens — first so the broader pattern below doesn't
    # leave the bearer suffix exposed when wrapped in quotes.
    (re.compile(r"(Bearer\s+)[\w\-\.]+", re.IGNORECASE), r"\1[REDACTED]"),
    # Common credential keys. Includes broker-specific aliases plus
    # algomirror-specific names: encryption_key, api_key_encrypted, fernet.
    (
        re.compile(
            r"(['\"]?(?:api[_-]?key[_-]?encrypted|api[_-]?key|app[_-]?key|"
            r"encryption[_-]?key|fernet[_-]?key|secret[_-]?key|"
            r"password|passwd|pwd|"
            r"access[_-]?token|refresh[_-]?token|session[_-]?token|"
            r"auth[_-]?token|authorization|enctoken|feed[_-]?token|"
            r"secret|pepper|token)['\"]?\s*[:=]\s*['\"]?)[^\s'\",;}\]]+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
]


class SensitiveDataFilter(logging.Filter):
    """Redact sensitive credentials from log message and args. Modifies the
    record in place; always returns True (does not drop the record)."""

    def filter(self, record):
        try:
            msg = str(record.msg)
            for pattern, replacement in SENSITIVE_PATTERNS:
                msg = pattern.sub(replacement, msg)
            record.msg = msg

            if record.args:
                filtered = []
                for arg in record.args:
                    s = str(arg)
                    for pattern, replacement in SENSITIVE_PATTERNS:
                        s = pattern.sub(replacement, s)
                    filtered.append(s)
                record.args = tuple(filtered)
        except Exception:
            # Never block a log emission because of a filter failure.
            pass
        return True


class JSONErrorFormatter(logging.Formatter):
    """Format an ERROR+ record as single-line JSON for errors.jsonl.

    Schema: ts, level, logger, module, file, message, exception?, request?
    The whitelist of keys is the contract with the /diagnose reader.
    """

    def format(self, record):
        entry = {
            "ts": datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "file": f"{record.pathname}:{record.lineno}",
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = traceback.format_exception(*record.exc_info)

        # Flask request context, if we're inside a request
        try:
            from flask import has_request_context, request

            if has_request_context():
                entry["request"] = {
                    "method": request.method,
                    "path": request.path,
                    "ip": request.remote_addr,
                }
        except Exception:
            pass

        try:
            return json.dumps(entry, default=str)
        except Exception:
            # Last-resort fallback so a single bad record cannot kill the handler.
            return json.dumps({
                "ts": entry["ts"],
                "level": entry["level"],
                "message": "[JSONErrorFormatter: failed to serialize record]",
            })


def ring_trim_jsonl(path, max_lines=1000):
    """Truncate path to the last max_lines on startup. No-op if missing/empty.
    Called once at app boot; cheap (file is normally <10MB)."""
    try:
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        if len(lines) > max_lines:
            with p.open("w", encoding="utf-8") as fh:
                fh.writelines(lines[-max_lines:])
    except Exception:
        # Never block app startup over log rotation.
        pass


def attach_json_error_handler(app, log_dir="logs", filename="errors.jsonl"):
    """Wire a FileHandler(level=ERROR) using JSONErrorFormatter to the ROOT
    logger so every ERROR+ across the codebase lands in errors.jsonl.

    Idempotent — safe to call twice. Applies SensitiveDataFilter to every
    other handler already on root + app loggers so existing log files
    also get redacted output.
    """
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    errors_file = log_path / filename

    ring_trim_jsonl(errors_file, max_lines=1000)

    sensitive_filter = SensitiveDataFilter()

    root = logging.getLogger()

    # Add sensitive filter to every existing handler on root and on app.logger
    for handler in list(root.handlers) + list(app.logger.handlers):
        if not any(isinstance(f, SensitiveDataFilter) for f in handler.filters):
            handler.addFilter(sensitive_filter)

    # Skip if we already attached
    for handler in root.handlers:
        if getattr(handler, "_algomirror_json_error", False):
            return

    json_handler = logging.FileHandler(str(errors_file), encoding="utf-8")
    json_handler.setLevel(logging.ERROR)
    json_handler.setFormatter(JSONErrorFormatter())
    json_handler.addFilter(sensitive_filter)
    json_handler._algomirror_json_error = True  # marker for idempotency

    root.addHandler(json_handler)
    # Ensure root level allows ERROR records through
    if root.level > logging.ERROR or root.level == logging.NOTSET:
        root.setLevel(logging.WARNING)

    return errors_file
