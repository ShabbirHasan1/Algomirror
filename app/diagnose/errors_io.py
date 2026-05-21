"""Read-only access to logs/errors.jsonl.

Defenses:
- Path traversal: resolve and require the file lives inside LOG_DIR.
- OOM: tail-read capped at MAX_TAIL_BYTES (10 MB).
- Key smuggling: ALLOWED_KEYS whitelist on every entry returned.
- Field bloat: per-field cap at MAX_FIELD_BYTES (20 KB).
"""

import hashlib
import json
import os
import re
from pathlib import Path

ALLOWED_KEYS = frozenset({
    "ts", "level", "logger", "module", "file", "message", "exception", "request"
})
ERROR_LEVELS = frozenset({"ERROR", "CRITICAL", "WARNING", "INFO", "DEBUG"})

MAX_LIMIT = 200
MAX_QUERY_LEN = 200
MAX_FIELD_BYTES = 20_000
MAX_TAIL_BYTES = 10 * 1024 * 1024  # 10 MB


def errors_file_path():
    """Resolve logs/errors.jsonl, requiring it stays inside LOG_DIR.
    Returns None if misconfigured."""
    log_dir = Path(os.getenv("LOG_DIR", "logs")).resolve()
    target = (log_dir / "errors.jsonl").resolve()
    try:
        target.relative_to(log_dir)
    except ValueError:
        return None
    return target


def truncate_field(value, max_len=MAX_FIELD_BYTES):
    """Cap field size so a single huge traceback can't bloat the response."""
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + "...[truncated]"
    if isinstance(value, list):
        joined = "\n".join(str(x) for x in value)
        if len(joined) > max_len:
            return [joined[:max_len] + "...[truncated]"]
    return value


def sanitize_entry(entry):
    """Project an errors.jsonl entry onto the whitelist + truncate fields."""
    out = {}
    for key in ALLOWED_KEYS:
        if key in entry:
            out[key] = truncate_field(entry[key])
    return out


def tail_jsonl(path, max_bytes=MAX_TAIL_BYTES):
    """Read up to max_bytes from the end of path. Returns list of raw lines.
    The first line is dropped if it might be partial."""
    if not path or not path.exists():
        return []
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size <= 0:
        return []
    read_size = min(size, max_bytes)
    try:
        with path.open("rb") as f:
            f.seek(size - read_size)
            chunk = f.read(read_size)
    except OSError:
        return []
    text = chunk.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if read_size < size and lines:
        lines = lines[1:]
    return lines


def parse_jsonl_lines(raw_lines):
    """Yield dict entries; skip malformed lines silently."""
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(entry, dict):
            yield entry


_NORM_HEX = re.compile(r"0x[0-9a-fA-F]+")
_NORM_TS = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\b")
_NORM_INT = re.compile(r"\b\d{1,}\b")
_NORM_WS = re.compile(r"\s+")


def normalize_signature(text):
    """Stabilize variable parts so the same error class fingerprints stably."""
    if not isinstance(text, str):
        return ""
    out = _NORM_HEX.sub("0x?", text)
    out = _NORM_TS.sub("<ts>", out)
    out = _NORM_INT.sub("<n>", out)
    out = _NORM_WS.sub(" ", out).strip()
    return out[:300]


def fingerprint_entry(entry):
    """Stable 12-char signature. Same exception type + module = same group."""
    parts = [
        entry.get("level") or "",
        entry.get("logger") or "",
        entry.get("module") or "",
    ]
    exc = entry.get("exception")
    if isinstance(exc, list) and exc:
        # Last frame is "ExceptionType: message" — keep the type
        last = str(exc[-1])
        head = last.split(":", 1)[0] if ":" in last else last
        parts.append(normalize_signature(head))
    elif isinstance(exc, str) and exc:
        parts.append(normalize_signature(exc[:200]))
    else:
        parts.append(normalize_signature(str(entry.get("message") or "")[:200]))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
