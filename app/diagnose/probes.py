"""Connectivity / latency probes.

Targets are NEVER user-supplied. Only:
- Local DB (via SQLAlchemy engine pool)
- Loopback HTTP on the app's own port
- Primary trading account's stored host_url (host:port only, TCP connect)
- Primary trading account's stored ws_url (if set, TCP connect)
- Redis (REDIS_URL host:port, if configured)

Each probe has a hard timeout. No payload is sent; we only test reachability.
"""

import os
import socket
import time
from urllib.parse import urlparse


def _ms_since(started):
    return round((time.perf_counter() - started) * 1000, 1)


def check_db_read():
    """SELECT 1 against the SQLAlchemy engine. Works for SQLite + Postgres."""
    started = time.perf_counter()
    try:
        from app import db
        from sqlalchemy import text

        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {
            "name": "Database read",
            "ok": True,
            "ms": _ms_since(started),
            "detail": "SELECT 1 OK",
        }
    except Exception as e:
        return {
            "name": "Database read",
            "ok": False,
            "ms": None,
            "detail": str(e)[:200],
        }


def check_loopback_http():
    """HEAD / on the local Flask app — measures internal request latency."""
    import urllib.request

    started = time.perf_counter()
    port = os.getenv("PORT") or os.getenv("FLASK_PORT") or "8000"
    url = f"http://127.0.0.1:{port}/"
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return {
                "name": f"Loopback HTTP ({port})",
                "ok": resp.status < 500,
                "ms": _ms_since(started),
                "detail": f"HTTP {resp.status}",
            }
    except Exception as e:
        return {
            "name": f"Loopback HTTP ({port})",
            "ok": False,
            "ms": None,
            "detail": str(e)[:200],
        }


def _parse_host_port(url, default_port):
    """Parse host:port from a URL. Returns (host, port) or (None, None) on
    failure. Allows http(s)://host[:port][/path] forms."""
    if not url:
        return None, None
    try:
        # Add scheme if missing so urlparse works on 'host:port' shorthand
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or default_port
        if not host:
            return None, None
        return host, int(port)
    except Exception:
        return None, None


def _tcp_probe(label, host, port, timeout=3.0):
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "name": label,
                "ok": True,
                "ms": _ms_since(started),
                "detail": f"TCP {host}:{port} OK",
            }
    except Exception as e:
        return {
            "name": label,
            "ok": False,
            "ms": None,
            "detail": f"{type(e).__name__}: {str(e)[:160]}",
        }


def check_primary_openalgo_host():
    """TCP-connect to the primary account's OpenAlgo host. No HTTP request,
    no API call — just opens a socket and closes it."""
    try:
        from app.models import TradingAccount

        primary = TradingAccount.query.filter_by(is_primary=True, is_active=True).first()
        if not primary:
            return {
                "name": "Primary OpenAlgo host",
                "ok": False,
                "ms": None,
                "detail": "No primary account configured",
            }
        host, port = _parse_host_port(primary.host_url, default_port=5000)
        if not host:
            return {
                "name": "Primary OpenAlgo host",
                "ok": False,
                "ms": None,
                "detail": f"Unparseable host_url",
            }
        return _tcp_probe(f"Primary OpenAlgo ({host}:{port})", host, port, timeout=3.0)
    except Exception as e:
        return {
            "name": "Primary OpenAlgo host",
            "ok": False,
            "ms": None,
            "detail": str(e)[:200],
        }


def check_primary_websocket():
    """TCP-connect to the primary account's websocket URL, if set."""
    try:
        from app.models import TradingAccount

        primary = TradingAccount.query.filter_by(is_primary=True, is_active=True).first()
        if not primary:
            return {
                "name": "Primary WebSocket",
                "ok": False,
                "ms": None,
                "detail": "No primary account configured",
            }
        ws_url = getattr(primary, "websocket_url", None) or getattr(primary, "ws_url", None)
        if not ws_url:
            return {
                "name": "Primary WebSocket",
                "ok": False,
                "ms": None,
                "detail": "No WebSocket URL configured on primary",
            }
        host, port = _parse_host_port(ws_url, default_port=8765)
        if not host:
            return {
                "name": "Primary WebSocket",
                "ok": False,
                "ms": None,
                "detail": "Unparseable ws_url",
            }
        return _tcp_probe(f"Primary WebSocket ({host}:{port})", host, port, timeout=2.0)
    except Exception as e:
        return {
            "name": "Primary WebSocket",
            "ok": False,
            "ms": None,
            "detail": str(e)[:200],
        }


def check_redis():
    """If REDIS_URL is set, TCP-connect to its host:port. Otherwise skip."""
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        return {
            "name": "Redis",
            "ok": True,
            "ms": None,
            "detail": "Not configured (optional)",
        }
    host, port = _parse_host_port(redis_url, default_port=6379)
    if not host:
        return {
            "name": "Redis",
            "ok": False,
            "ms": None,
            "detail": "Unparseable REDIS_URL",
        }
    return _tcp_probe(f"Redis ({host}:{port})", host, port, timeout=2.0)


def run_all_probes():
    """Execute the full probe suite. Returns list of result dicts."""
    return [
        check_db_read(),
        check_loopback_http(),
        check_primary_openalgo_host(),
        check_primary_websocket(),
        check_redis(),
    ]
