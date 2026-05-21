"""Render a self-contained system report as Markdown or plaintext.
Output is sanitized (no secrets, ANSI stripped) and hard-capped at 1 MB."""

import re
from datetime import datetime

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
MAX_REPORT_BYTES = 1_000_000


def _md_kv(label, value):
    if value is None or value == "":
        return f"- **{label}:** _not set_"
    return f"- **{label}:** {value}"


def _strip_ansi(text):
    return ANSI_RE.sub("", str(text))


def render_report(payload, errors_summary, errors_recent, fmt):
    """fmt: 'md' or 'txt'. Returns a string body, never None."""
    is_md = fmt == "md"
    bullet = "- " if is_md else "  - "
    h1 = "# " if is_md else ""
    h2 = "## " if is_md else ""

    lines = []
    lines.append(f"{h1}AlgoMirror System Report")
    lines.append("")
    lines.append(_md_kv("Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    lines.append("")

    host = payload.get("host") or {}
    lines.append(f"{h2}Host")
    lines.append(_md_kv("System", host.get("system")))
    lines.append(_md_kv("Release", host.get("release")))
    lines.append(_md_kv("Machine", host.get("machine")))
    lines.append(_md_kv("Platform", host.get("platform")))
    if host.get("distro"):
        d = host["distro"]
        lines.append(_md_kv("Distro", f"{d.get('name')} ({d.get('id')} {d.get('version_id')})"))
    lines.append(_md_kv("In Docker", host.get("in_docker")))
    if host.get("is_raspberry_pi"):
        lines.append(_md_kv("Raspberry Pi", host.get("rpi_model")))
    if host.get("is_termux"):
        lines.append(_md_kv("Termux", True))
    if host.get("is_android"):
        lines.append(_md_kv("Android", True))
    lines.append("")

    runtime = payload.get("runtime") or {}
    lines.append(f"{h2}Runtime")
    lines.append(_md_kv("Python", runtime.get("python_version")))
    lines.append(_md_kv("Implementation", runtime.get("python_implementation")))
    lines.append(_md_kv("WSGI", runtime.get("wsgi_hint")))
    lines.append(_md_kv("PID", runtime.get("pid")))
    lines.append(_md_kv("Process uptime (s)", runtime.get("process_uptime_seconds")))
    lines.append("")

    hw = payload.get("hardware") or {}
    lines.append(f"{h2}Hardware")
    lines.append(_md_kv("CPU count", hw.get("cpu_count")))
    lines.append(_md_kv("CPU model", hw.get("cpu_model")))
    lines.append(_md_kv("Memory total (MB)", hw.get("memory_total_mb")))
    lines.append(_md_kv("Memory available (MB)", hw.get("memory_available_mb")))
    lines.append(_md_kv("Memory used (%)", hw.get("memory_percent")))
    if hw.get("disk_logs"):
        lines.append(_md_kv("Disk (logs)", f"{hw['disk_logs']['free_gb']} GB free of {hw['disk_logs']['total_gb']} GB"))
    if hw.get("disk_instance"):
        lines.append(_md_kv("Disk (instance)", f"{hw['disk_instance']['free_gb']} GB free of {hw['disk_instance']['total_gb']} GB"))
    lines.append("")

    build = payload.get("build") or {}
    lines.append(f"{h2}Build")
    lines.append(_md_kv("AlgoMirror", build.get("algomirror_version")))
    lines.append(_md_kv("OpenAlgo SDK", build.get("openalgo_sdk_version")))
    lines.append(_md_kv("Git branch", build.get("git_branch")))
    lines.append(_md_kv("Git commit", build.get("git_commit")))
    lines.append("")

    cfg = payload.get("config") or {}
    lines.append(f"{h2}Configuration")
    lines.append(_md_kv("Log level", cfg.get("log_level")))
    lines.append(_md_kv("Log dir", cfg.get("log_dir")))
    lines.append(_md_kv("Flask env", cfg.get("flask_env")))
    lines.append(_md_kv("Flask debug", cfg.get("flask_debug")))
    lines.append(_md_kv("Database kind", cfg.get("database_kind")))
    lines.append(_md_kv("Database URL", cfg.get("database_url")))
    lines.append(_md_kv("Session type", cfg.get("session_type")))
    lines.append(_md_kv("Redis configured", cfg.get("redis_configured")))
    secrets = cfg.get("secrets_present") or {}
    if secrets:
        lines.append("")
        lines.append(f"{h2}Secrets (presence only)")
        for k, v in sorted(secrets.items()):
            lines.append(f"{bullet}{k}: {'set' if v else 'not set'}")
    strength = cfg.get("secret_strength") or {}
    if strength:
        lines.append("")
        lines.append(f"{h2}Secret strength")
        for k, v in sorted(strength.items()):
            lines.append(f"{bullet}{k}: {'OK' if v else 'WEAK — looks like a placeholder'}")
    lines.append("")

    acc = payload.get("accounts") or {}
    lines.append(f"{h2}Trading accounts")
    lines.append(_md_kv("Total accounts", acc.get("total")))
    lines.append(_md_kv("Active accounts", acc.get("active")))
    lines.append(_md_kv("Primary set", acc.get("primary_set")))
    if acc.get("primary_set"):
        lines.append(_md_kv("Primary", f"{acc.get('primary_name')} ({acc.get('primary_broker')})"))
    lines.append(_md_kv("Encrypted keys present", acc.get("encrypted_key_present_count")))
    by_broker = acc.get("by_broker") or {}
    if by_broker:
        lines.append(f"{bullet}By broker:")
        for k, v in sorted(by_broker.items()):
            lines.append(f"  {bullet}{k}: {v}")
    lines.append("")

    dbs = payload.get("databases") or []
    lines.append(f"{h2}Databases")
    if not dbs:
        lines.append(f"{bullet}_none reported_")
    for d in dbs:
        if d.get("exists"):
            size = d.get("size_mb")
            size_str = f"{size} MB" if size is not None else "live connection"
            mod = d.get("modified") or "n/a"
            lines.append(f"{bullet}{d['name']} [{d.get('kind', '?')}]: {size_str} (modified {mod})")
        else:
            lines.append(f"{bullet}{d['name']}: _missing_")
    lines.append("")

    t = payload.get("time") or {}
    lines.append(f"{h2}Time")
    lines.append(_md_kv("Server time", t.get("server_time")))
    lines.append(_md_kv("IST time", t.get("ist_time")))
    lines.append(_md_kv("Server timezone", t.get("server_tz")))
    lines.append("")

    if errors_summary:
        lines.append(f"{h2}Errors summary")
        lines.append(_md_kv("Total in window", errors_summary.get("total")))
        lines.append(_md_kv("Last 24h", errors_summary.get("last_24h")))
        lines.append(_md_kv("Last 1h", errors_summary.get("last_1h")))
        by_level = errors_summary.get("by_level") or {}
        for lvl, count in sorted(by_level.items()):
            lines.append(f"{bullet}{lvl}: {count}")
        lines.append("")

    if errors_recent:
        lines.append(f"{h2}Recent errors (latest first, max 50)")
        lines.append("")
        for entry in errors_recent[-50:][::-1]:
            ts = entry.get("ts", "?")
            lvl = entry.get("level", "?")
            mod = entry.get("module", "?")
            msg = _strip_ansi(entry.get("message", ""))[:500]
            if is_md:
                lines.append(f"{bullet}`{ts}` **{lvl}** in `{mod}`: {msg}")
            else:
                lines.append(f"  - [{ts}] {lvl} in {mod}: {msg}")
        lines.append("")

    body = "\n".join(lines)
    if len(body) > MAX_REPORT_BYTES:
        body = body[:MAX_REPORT_BYTES] + "\n\n...[report truncated]\n"
    return body
