"""System snapshot helpers — host, runtime, hardware, build, config, db, time.

Every helper is wrapped so a partial failure (psutil missing, /proc absent,
DB down) cannot blank the diagnose page. No secret values are ever returned
— only presence booleans.
"""

import os
import platform as _platform
import shutil as _shutil
import sys as _sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# Env var names whose presence we report (never values).
_SECRET_ENV_KEYS = frozenset({
    "SECRET_KEY",
    "ENCRYPTION_KEY",
    "DATABASE_URL",
    "REDIS_URL",
})


def detect_container_and_device():
    info = {
        "in_docker": Path("/.dockerenv").exists(),
        "is_raspberry_pi": False,
        "rpi_model": None,
        "is_termux": bool(os.getenv("TERMUX_VERSION")) or Path("/data/data/com.termux").exists(),
        "is_android": bool(os.getenv("ANDROID_ROOT")),
    }
    try:
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            text = cpuinfo.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if line.lower().startswith("model") and "raspberry pi" in line.lower():
                    info["is_raspberry_pi"] = True
                    info["rpi_model"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return info


def detect_linux_distro():
    try:
        path = Path("/etc/os-release")
        if not path.exists():
            return None
        result = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"')
        return {
            "name": result.get("PRETTY_NAME") or result.get("NAME"),
            "id": result.get("ID"),
            "version_id": result.get("VERSION_ID"),
        }
    except OSError:
        return None


def hardware_snapshot():
    snap = {
        "cpu_count": os.cpu_count(),
        "cpu_model": _platform.processor() or None,
        "memory_total_mb": None,
        "memory_available_mb": None,
        "memory_percent": None,
        "disk_logs": None,
        "disk_instance": None,
    }
    try:
        import psutil

        vm = psutil.virtual_memory()
        snap["memory_total_mb"] = round(vm.total / (1024 * 1024), 1)
        snap["memory_available_mb"] = round(vm.available / (1024 * 1024), 1)
        snap["memory_percent"] = vm.percent
        if _platform.system() == "Linux":
            try:
                cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
                for line in cpuinfo.splitlines():
                    if line.lower().startswith("model name"):
                        snap["cpu_model"] = line.split(":", 1)[1].strip()
                        break
            except OSError:
                pass
    except Exception:
        pass

    for label, target in (("disk_logs", "logs"), ("disk_instance", "instance")):
        try:
            usage = _shutil.disk_usage(target if Path(target).exists() else ".")
            snap[label] = {
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "used_percent": round(100 * (usage.total - usage.free) / usage.total, 1),
            }
        except OSError:
            snap[label] = None
    return snap


def runtime_info():
    info = {
        "python_version": _sys.version.split()[0],
        "python_implementation": _sys.implementation.name,
        "wsgi_hint": "flask-dev",
        "process_uptime_seconds": None,
        "pid": os.getpid(),
    }
    # Detect gunicorn by env / module presence
    try:
        if "gunicorn" in os.environ.get("SERVER_SOFTWARE", "").lower():
            info["wsgi_hint"] = "gunicorn"
        elif "GUNICORN_CMD_ARGS" in os.environ:
            info["wsgi_hint"] = "gunicorn"
    except Exception:
        pass

    try:
        import psutil

        proc = psutil.Process(os.getpid())
        info["process_uptime_seconds"] = int(datetime.now().timestamp() - proc.create_time())
    except Exception:
        pass
    return info


def build_info():
    info = {
        "algomirror_version": None,
        "openalgo_sdk_version": None,
        "git_branch": None,
        "git_commit": None,
    }
    # algomirror version from pyproject.toml (no toml lib needed — just grep)
    try:
        py = Path("pyproject.toml")
        if py.is_file():
            for line in py.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("version") and "=" in line:
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        info["algomirror_version"] = val
                        break
    except OSError:
        pass

    try:
        from importlib import metadata as _metadata

        info["openalgo_sdk_version"] = _metadata.version("openalgo")
    except Exception:
        pass

    # Read .git/HEAD without subprocess. Restrict to repo root + only allow
    # refs/heads/* or refs/tags/* so a manipulated HEAD can't traverse out.
    try:
        repo_root = Path(__file__).resolve().parent.parent.parent
        head_file = (repo_root / ".git" / "HEAD").resolve()
        if head_file.is_file():
            try:
                head_file.relative_to(repo_root)
            except ValueError:
                head_file = None
        else:
            head_file = None
        if head_file is not None:
            head = head_file.read_text(encoding="utf-8", errors="replace").strip()
            if head.startswith("ref: "):
                ref = head[5:].strip()
                if ref.startswith(("refs/heads/", "refs/tags/")) and ".." not in ref:
                    info["git_branch"] = ref.split("/", 2)[-1]
                    ref_path = (repo_root / ".git" / ref).resolve()
                    try:
                        ref_path.relative_to(repo_root)
                    except ValueError:
                        ref_path = None
                    if ref_path is not None and ref_path.is_file():
                        info["git_commit"] = ref_path.read_text(encoding="utf-8").strip()[:12]
            else:
                info["git_commit"] = head[:12]
    except OSError:
        pass

    return info


def _redact_database_url(url):
    """Return a safe display string for DATABASE_URL — no password, no userinfo."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme or "?"
        if scheme.startswith("sqlite"):
            # sqlite:///instance/algomirror.db  → show the file
            return url
        host = parsed.hostname or "?"
        port = f":{parsed.port}" if parsed.port else ""
        dbname = (parsed.path or "/").lstrip("/")
        user = parsed.username or "?"
        return f"{scheme}://{user}:[REDACTED]@{host}{port}/{dbname}"
    except Exception:
        return f"<unparseable DATABASE_URL>"


def _is_strong_secret(value, min_chars=32):
    """A secret is 'strong' if it's long enough and not the .env.example placeholder."""
    if not value:
        return False
    if len(value) < min_chars:
        return False
    # Common placeholder substrings that operators forget to replace.
    placeholders = (
        "change-me",
        "changeme",
        "your-secret-key",
        "your_secret_key",
        "secret-key-here",
        "supersecret",
        "dev-secret",
    )
    lower = value.lower()
    return not any(p in lower for p in placeholders)


def safe_config_snapshot(app=None):
    """Public-safe view: secrets reduced to set/not-set booleans."""
    secrets_present = {key: bool(os.getenv(key)) for key in _SECRET_ENV_KEYS}
    # SECRET_KEY may come from Flask config rather than env.
    if app is not None:
        try:
            secrets_present["SECRET_KEY"] = bool(app.config.get("SECRET_KEY")) or secrets_present.get("SECRET_KEY", False)
        except Exception:
            pass

    # Strength check (placeholder detection) on the values we have at hand.
    strength = {}
    try:
        secret_key_val = (app.config.get("SECRET_KEY") if app else None) or os.getenv("SECRET_KEY") or ""
        strength["SECRET_KEY strong"] = _is_strong_secret(secret_key_val)
    except Exception:
        strength["SECRET_KEY strong"] = False
    try:
        enc_key_val = os.getenv("ENCRYPTION_KEY") or ""
        # ENCRYPTION_KEY is a Fernet key — base64-encoded 32 bytes = 44 chars
        strength["ENCRYPTION_KEY set"] = bool(enc_key_val) and len(enc_key_val) >= 40
    except Exception:
        strength["ENCRYPTION_KEY set"] = False

    db_url_raw = os.getenv("DATABASE_URL") or (app.config.get("SQLALCHEMY_DATABASE_URI") if app else None) or ""
    db_url_safe = _redact_database_url(db_url_raw) if db_url_raw else None
    db_kind = "postgres" if db_url_raw.startswith(("postgres", "postgresql")) else (
        "sqlite" if db_url_raw.startswith("sqlite") else ("unknown" if db_url_raw else "not configured")
    )

    return {
        "log_level": os.getenv("LOG_LEVEL", "INFO"),
        "log_dir": os.getenv("LOG_DIR", "logs"),
        "database_kind": db_kind,
        "database_url": db_url_safe,
        "session_type": (app.config.get("SESSION_TYPE") if app else None) or os.getenv("SESSION_TYPE", "filesystem"),
        "redis_configured": bool(os.getenv("REDIS_URL")),
        "flask_env": os.getenv("FLASK_ENV", "development"),
        "flask_debug": (os.getenv("FLASK_DEBUG") or "False").lower() == "true",
        "cors_origins": os.getenv("CORS_ORIGINS", ""),
        "secrets_present": secrets_present,
        "secret_strength": strength,
    }


def trading_accounts_snapshot():
    """Counts and per-broker breakdown. Never returns API keys, only presence."""
    info = {
        "total": 0,
        "active": 0,
        "primary_set": False,
        "primary_name": None,
        "primary_broker": None,
        "by_broker": {},
        "encrypted_key_present_count": 0,
    }
    try:
        from app.models import TradingAccount

        accounts = TradingAccount.query.all()
        info["total"] = len(accounts)
        info["active"] = sum(1 for a in accounts if a.is_active)
        primaries = [a for a in accounts if a.is_primary]
        if primaries:
            primary = primaries[0]
            info["primary_set"] = True
            info["primary_name"] = primary.account_name
            info["primary_broker"] = primary.broker_name
        by_broker = {}
        enc_present = 0
        for a in accounts:
            broker = a.broker_name or "unknown"
            by_broker[broker] = by_broker.get(broker, 0) + 1
            if getattr(a, "api_key_encrypted", None):
                enc_present += 1
        info["by_broker"] = by_broker
        info["encrypted_key_present_count"] = enc_present
    except Exception:
        # DB down or model import failed — return zeros rather than crash diagnose
        pass
    return info


def database_snapshot(app=None):
    """SQLite: file presence/size/mtime. Postgres: just kind label.
    Live connection probe is done separately in probes.check_db_read()."""
    out = []
    try:
        db_url = (app.config.get("SQLALCHEMY_DATABASE_URI") if app else None) or os.getenv("DATABASE_URL", "")
    except Exception:
        db_url = ""

    if db_url.startswith("sqlite"):
        # sqlite:///instance/algomirror.db  → instance/algomirror.db
        try:
            path_str = db_url.split("sqlite:///", 1)[-1] or db_url.split("sqlite://", 1)[-1]
            p = Path(path_str)
            if p.exists():
                st = p.stat()
                out.append({
                    "name": p.name,
                    "kind": "sqlite",
                    "exists": True,
                    "size_mb": round(st.st_size / (1024 * 1024), 2),
                    "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
            else:
                out.append({"name": p.name, "kind": "sqlite", "exists": False, "size_mb": 0, "modified": None})
        except Exception:
            pass
    elif db_url.startswith(("postgres", "postgresql")):
        out.append({"name": "postgres", "kind": "postgres", "exists": True, "size_mb": None, "modified": None})
    return out


def server_time_info():
    try:
        from zoneinfo import ZoneInfo

        now_local = datetime.now()
        now_ist = datetime.now(tz=ZoneInfo("Asia/Kolkata"))
        return {
            "server_time": now_local.strftime("%Y-%m-%d %H:%M:%S"),
            "server_tz": str(now_local.astimezone().tzinfo),
            "ist_time": now_ist.strftime("%Y-%m-%d %H:%M:%S %Z"),
        }
    except Exception:
        return {
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "server_tz": None,
            "ist_time": None,
        }


def build_system_payload(app=None):
    """Assemble the full snapshot. No secrets, no external calls."""
    distro = detect_linux_distro()
    extras = detect_container_and_device()
    return {
        "host": {
            "system": _platform.system(),
            "release": _platform.release(),
            "version": _platform.version(),
            "machine": _platform.machine(),
            "platform": _platform.platform(),
            "distro": distro,
            "in_docker": extras["in_docker"],
            "is_raspberry_pi": extras["is_raspberry_pi"],
            "rpi_model": extras["rpi_model"],
            "is_termux": extras["is_termux"],
            "is_android": extras["is_android"],
        },
        "runtime": runtime_info(),
        "hardware": hardware_snapshot(),
        "build": build_info(),
        "config": safe_config_snapshot(app),
        "accounts": trading_accounts_snapshot(),
        "databases": database_snapshot(app),
        "time": server_time_info(),
    }
