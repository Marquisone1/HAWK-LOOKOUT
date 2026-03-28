import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps

from flask import jsonify, redirect, request, session, url_for

from .models import User, db

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory sliding-window rate limiter
# ─────────────────────────────────────────────────────────────────────────────
# Keyed by (ip, bucket_name) so API and login limits are tracked separately.

_rate_lock = threading.Lock()
_rate_buckets: dict[tuple, list] = defaultdict(list)

_API_RATE_LIMIT = 30   # requests
_API_RATE_WINDOW = 60  # seconds


def _is_rate_limited(ip: str, limit: int = _API_RATE_LIMIT, window: int = _API_RATE_WINDOW, bucket: str = "default") -> bool:
    """Return True if the IP has exceeded `limit` requests within `window` seconds."""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window)
    key = (ip, bucket)
    with _rate_lock:
        _rate_buckets[key] = [t for t in _rate_buckets[key] if t > cutoff]
        if len(_rate_buckets[key]) >= limit:
            return True
        _rate_buckets[key].append(now)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# API key helpers
# ─────────────────────────────────────────────────────────────────────────────


def _validate_api_key(api_key: str):
    """Return the User row matching api_key, or None."""
    if not api_key:
        return None
    return User.query.filter_by(api_key=api_key).first()


# ─────────────────────────────────────────────────────────────────────────────
# Decorators
# ─────────────────────────────────────────────────────────────────────────────


def require_api_key(f):
    """Require a valid X-API-Key header with per-IP rate limiting."""

    @wraps(f)
    def decorated(*args, **kwargs):
        # After ProxyFix is applied in create_app(), request.remote_addr is the
        # real client IP (extracted from X-Forwarded-For by Werkzeug), so clients
        # cannot spoof it by injecting a custom X-Forwarded-For header.
        client_ip = request.remote_addr

        if _is_rate_limited(client_ip, limit=_API_RATE_LIMIT, window=_API_RATE_WINDOW, bucket="api"):
            return (
                jsonify(
                    {
                        "error": "Too Many Requests",
                        "message": f"Max {_API_RATE_LIMIT} requests per {_API_RATE_WINDOW}s",
                    }
                ),
                429,
            )

        api_key = request.headers.get("X-API-Key", "")
        user = _validate_api_key(api_key)
        if not user:
            return (
                jsonify(
                    {
                        "error": "Unauthorized",
                        "message": "Invalid or missing X-API-Key header",
                    }
                ),
                401,
            )

        user.last_used = datetime.utcnow()
        db.session.commit()
        logger.info(f"API auth: user {user.id} key={user.api_key[:8]}...")

        return f(user, *args, **kwargs)

    return decorated


def web_login_required(f):
    """Require an active web session (username/password login)."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if "site_user_id" not in session:
            return redirect(url_for("whois.login"))
        return f(*args, **kwargs)

    return decorated
