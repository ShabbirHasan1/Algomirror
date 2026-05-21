"""Diagnose blueprint — admin-only debugging UI and APIs.

All endpoints are auth-gated, CSRF-protected (POSTs), rate-limited, and
return read-only views over the errors.jsonl log and system state.
No client-supplied probe targets — no SSRF surface.
"""

from flask import Blueprint

diagnose_bp = Blueprint("diagnose", __name__, url_prefix="/diagnose")

# Import routes to register them on the blueprint
from app.diagnose import routes  # noqa: E402, F401
