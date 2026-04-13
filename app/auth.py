import logging
import re
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


def require_admin(f):
    """Require admin role via web session."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if "site_user_id" not in session:
            return redirect(url_for("whois.login"))
        if session.get("site_role") != "admin":
            from flask import flash
            flash("Admin access required.", "error")
            return redirect(url_for("whois.index"))
        return f(*args, **kwargs)

    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Password strength validation
# ─────────────────────────────────────────────────────────────────────────────

_MIN_PASSWORD_LEN = 12


def validate_password_strength(password: str) -> list[str]:
    """Return a list of error strings; empty list means the password is acceptable."""
    errors = []
    if len(password) < _MIN_PASSWORD_LEN:
        errors.append(f"Password must be at least {_MIN_PASSWORD_LEN} characters.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]", password):
        errors.append("Password must contain at least one special character.")
    return errors
