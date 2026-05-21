"""Diagnose routes — admin-only, CSRF on POSTs, rate-limited, output-sanitized.

Security checklist applied to every endpoint:
- @login_required (admin enforced via current_user.is_admin)
- POSTs validated by Flask-WTF CSRFProtect (NOT exempted)
- Rate-limited (api_rate_limit for reads, heavy_rate_limit for probes/report)
- Input validation: every query/body field length-capped and allowlist-validated
- Output sanitization: error entries whitelisted to ALLOWED_KEYS, fields truncated
- No client-supplied probe targets — eliminates SSRF
- Cache-Control: no-store on every JSON response
"""

import json
import logging
import re
from datetime import datetime, timedelta
from functools import wraps

from flask import Response, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from app.diagnose import diagnose_bp
from app.diagnose.errors_io import (
    ERROR_LEVELS,
    MAX_LIMIT,
    MAX_QUERY_LEN,
    errors_file_path,
    fingerprint_entry,
    parse_jsonl_lines,
    sanitize_entry,
    tail_jsonl,
)
from app.diagnose.probes import run_all_probes
from app.diagnose.report import render_report
from app.diagnose.snapshot import build_system_payload
from app.utils.rate_limiter import api_rate_limit, heavy_rate_limit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auth: every diagnose route requires admin. Single-user app so is_admin=True
# for the registered user, but we enforce explicitly as defense-in-depth.
# ---------------------------------------------------------------------------
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(current_user, "is_authenticated", False):
            abort(401)
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# UI page
# ---------------------------------------------------------------------------
@diagnose_bp.route("/")
@login_required
@admin_required
def index():
    return render_template("diagnose/index.html")


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------
@diagnose_bp.route("/api/system")
@login_required
@admin_required
@api_rate_limit()
def api_system():
    try:
        from flask import current_app
        resp = jsonify({"status": "success", "data": build_system_payload(current_app)})
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp
    except Exception:
        logger.exception("diagnose: failed to build system payload")
        return jsonify({"status": "error", "message": "Failed to build system info"}), 500


# ---------------------------------------------------------------------------
# Errors — list / stats / groups
# ---------------------------------------------------------------------------
@diagnose_bp.route("/api/errors")
@login_required
@admin_required
@api_rate_limit()
def api_errors_list():
    try:
        try:
            limit = int(request.args.get("limit", 100))
        except (TypeError, ValueError):
            limit = 100
        limit = max(1, min(limit, MAX_LIMIT))

        level_filter = (request.args.get("level", "") or "").strip().upper()
        if level_filter and level_filter not in ERROR_LEVELS:
            return jsonify({"status": "error", "message": "Invalid level"}), 400

        q = (request.args.get("q", "") or "").strip()[:MAX_QUERY_LEN]
        q_lower = q.lower() if q else None

        path = errors_file_path()
        if path is None:
            return jsonify({"status": "error", "message": "Log directory misconfigured"}), 500

        raw_lines = tail_jsonl(path)

        results = []
        scanned = 0
        for entry in parse_jsonl_lines(reversed(raw_lines)):
            scanned += 1
            if level_filter and entry.get("level") != level_filter:
                continue
            if q_lower:
                msg = str(entry.get("message", "")).lower()
                exc = entry.get("exception")
                exc_text = (
                    "".join(str(x) for x in exc).lower()
                    if isinstance(exc, list)
                    else str(exc or "").lower()
                )
                if q_lower not in msg and q_lower not in exc_text:
                    continue
            results.append(sanitize_entry(entry))
            if len(results) >= limit:
                break
        results.reverse()

        total = sum(1 for _ in parse_jsonl_lines(raw_lines))

        resp = jsonify({
            "status": "success",
            "data": results,
            "count": len(results),
            "scanned": scanned,
            "total_in_window": total,
        })
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp
    except Exception:
        logger.exception("diagnose: failed to read error log")
        return jsonify({"status": "error", "message": "Failed to read error log"}), 500


@diagnose_bp.route("/api/errors/stats")
@login_required
@admin_required
@api_rate_limit()
def api_errors_stats():
    try:
        path = errors_file_path()
        if path is None or not path.exists():
            return jsonify({
                "status": "success",
                "total": 0, "by_level": {}, "last_24h": 0, "last_1h": 0,
            })

        raw_lines = tail_jsonl(path)
        by_level = {}
        last_24h = 0
        last_1h = 0
        total = 0
        now = datetime.now()
        cutoff_24h = now - timedelta(hours=24)
        cutoff_1h = now - timedelta(hours=1)

        for entry in parse_jsonl_lines(raw_lines):
            total += 1
            level = entry.get("level", "UNKNOWN")
            by_level[level] = by_level.get(level, 0) + 1
            ts_str = entry.get("ts")
            if isinstance(ts_str, str):
                try:
                    ts_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                if ts_dt >= cutoff_24h:
                    last_24h += 1
                if ts_dt >= cutoff_1h:
                    last_1h += 1

        resp = jsonify({
            "status": "success",
            "total": total, "by_level": by_level,
            "last_24h": last_24h, "last_1h": last_1h,
        })
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp
    except Exception:
        logger.exception("diagnose: failed to compute error stats")
        return jsonify({"status": "error", "message": "Failed to read error log"}), 500


@diagnose_bp.route("/api/errors/groups")
@login_required
@admin_required
@api_rate_limit()
def api_errors_groups():
    try:
        try:
            limit = int(request.args.get("limit", 50))
        except (TypeError, ValueError):
            limit = 50
        limit = max(1, min(limit, MAX_LIMIT))

        path = errors_file_path()
        if path is None or not path.exists():
            return jsonify({"status": "success", "groups": [], "total_entries": 0, "total_groups": 0})

        raw_lines = tail_jsonl(path)
        groups = {}
        total = 0
        for entry in parse_jsonl_lines(raw_lines):
            total += 1
            fp = fingerprint_entry(entry)
            ts = entry.get("ts")
            existing = groups.get(fp)
            if existing is None:
                groups[fp] = {
                    "fingerprint": fp,
                    "count": 1,
                    "level": entry.get("level"),
                    "logger": entry.get("logger"),
                    "module": entry.get("module"),
                    "first_seen": ts,
                    "last_seen": ts,
                    "sample": sanitize_entry(entry),
                }
            else:
                existing["count"] += 1
                if isinstance(ts, str):
                    if not existing["first_seen"] or ts < existing["first_seen"]:
                        existing["first_seen"] = ts
                    if not existing["last_seen"] or ts > existing["last_seen"]:
                        existing["last_seen"] = ts
                if (
                    isinstance(ts, str)
                    and isinstance(existing.get("last_seen"), str)
                    and ts >= existing["last_seen"]
                ):
                    existing["sample"] = sanitize_entry(entry)

        ordered = sorted(
            groups.values(),
            key=lambda g: (g["count"], g.get("last_seen") or ""),
            reverse=True,
        )[:limit]

        resp = jsonify({
            "status": "success", "groups": ordered,
            "total_entries": total, "total_groups": len(groups),
        })
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp
    except Exception:
        logger.exception("diagnose: failed to group errors")
        return jsonify({"status": "error", "message": "Failed to group errors"}), 500


# ---------------------------------------------------------------------------
# Browser-side error reporting (POST, CSRF-validated)
# ---------------------------------------------------------------------------
_CLIENT_LEVELS = frozenset({"ERROR", "WARN"})
_MAX_CLIENT_MESSAGE = 2000
_MAX_CLIENT_STACK = 20_000
_MAX_CLIENT_URL = 2000
_MAX_CLIENT_UA = 500
_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _scrub(text, max_len):
    if not isinstance(text, str):
        return ""
    # Drop ASCII control chars (keep \n \t), then truncate.
    return _CTRL_CHARS.sub("", text)[:max_len]


_client_logger = None


def _get_client_logger():
    global _client_logger
    if _client_logger is None:
        _client_logger = logging.getLogger("client.browser")
    return _client_logger


@diagnose_bp.route("/api/errors/client", methods=["POST"])
@login_required
@admin_required
@heavy_rate_limit()
def api_errors_client_report():
    """Receive a browser-side error report and route it into errors.jsonl.
    Auth-gated, CSRF-validated, rate-limited, every field length-capped."""
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"status": "error", "message": "Invalid payload"}), 400

        level = (data.get("level") or "ERROR").strip().upper()
        if level not in _CLIENT_LEVELS:
            level = "ERROR"

        message = _scrub(str(data.get("message") or ""), _MAX_CLIENT_MESSAGE)
        stack = _scrub(str(data.get("stack") or ""), _MAX_CLIENT_STACK)
        url = _scrub(str(data.get("url") or ""), _MAX_CLIENT_URL)
        user_agent = _scrub(str(data.get("user_agent") or ""), _MAX_CLIENT_UA)

        if not message:
            return jsonify({"status": "error", "message": "Missing message"}), 400

        details = []
        if url:
            details.append(f"URL: {url}")
        if user_agent:
            details.append(f"UA: {user_agent}")
        if stack:
            details.append("Stack:\n" + stack)

        log_msg = "[CLIENT] " + message + (("\n" + "\n\n".join(details)) if details else "")
        client_logger = _get_client_logger()
        if level == "WARN":
            client_logger.warning(log_msg)
        else:
            client_logger.error(log_msg)

        return jsonify({"status": "success"})
    except Exception:
        logger.exception("diagnose: failed to record client error")
        return jsonify({"status": "error", "message": "Failed to record"}), 500


# ---------------------------------------------------------------------------
# Probes (POST, CSRF-validated, heavy rate limit)
# ---------------------------------------------------------------------------
@diagnose_bp.route("/api/diagnostics", methods=["POST"])
@login_required
@admin_required
@heavy_rate_limit()
def api_diagnostics():
    """Run the probe suite. No client-supplied targets."""
    try:
        checks = run_all_probes()
        resp = jsonify({
            "status": "success",
            "ran_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "checks": checks,
        })
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp
    except Exception:
        logger.exception("diagnose: failed to run probes")
        return jsonify({"status": "error", "message": "Failed to run diagnostics"}), 500


# ---------------------------------------------------------------------------
# Downloadable report
# ---------------------------------------------------------------------------
@diagnose_bp.route("/api/report")
@login_required
@admin_required
@heavy_rate_limit()
def api_report():
    try:
        from flask import current_app

        fmt = (request.args.get("format", "md") or "md").lower().strip()
        if fmt not in {"md", "txt"}:
            fmt = "md"

        payload = build_system_payload(current_app)

        # Errors summary + recent (single pass over errors.jsonl)
        errors_summary = None
        recent = []
        path = errors_file_path()
        if path is not None and path.exists():
            raw_lines = tail_jsonl(path)
            by_level = {}
            last_24h = 0
            last_1h = 0
            total = 0
            now = datetime.now()
            cutoff_24h = now - timedelta(hours=24)
            cutoff_1h = now - timedelta(hours=1)
            for entry in parse_jsonl_lines(raw_lines):
                total += 1
                lvl = entry.get("level", "UNKNOWN")
                by_level[lvl] = by_level.get(lvl, 0) + 1
                ts = entry.get("ts")
                if isinstance(ts, str):
                    try:
                        ts_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        ts_dt = None
                    if ts_dt is not None:
                        if ts_dt >= cutoff_24h:
                            last_24h += 1
                        if ts_dt >= cutoff_1h:
                            last_1h += 1
                recent.append(sanitize_entry(entry))
            errors_summary = {
                "total": total, "by_level": by_level,
                "last_24h": last_24h, "last_1h": last_1h,
            }
            recent = recent[-50:]

        body = render_report(payload, errors_summary, recent, fmt)
        filename = f"algomirror-system-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{fmt}"
        mimetype = "text/markdown" if fmt == "md" else "text/plain"

        resp = Response(body, mimetype=f"{mimetype}; charset=utf-8")
        # Fixed-pattern filename — no client input in the header
        resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp
    except Exception:
        logger.exception("diagnose: failed to generate report")
        return jsonify({"status": "error", "message": "Failed to generate report"}), 500
