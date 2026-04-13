import os
import secrets
from dotenv import load_dotenv

load_dotenv()

_PLACEHOLDER = "replace-with-a-random-64-char-hex-string"


def _load_secret_key() -> str:
    """
    Use SECRET_KEY from env if it looks like a real value.
    Otherwise auto-generate one and persist it to /data/secret_key so
    sessions remain valid across container restarts without needing a
    pre-configured .env file.
    """
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key and env_key != _PLACEHOLDER:
        return env_key

    key_file = "/data/secret_key"
    try:
        with open(key_file) as f:
            stored = f.read().strip()
            if stored:
                return stored
    except (FileNotFoundError, PermissionError):
        pass

    generated = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, "w") as f:
            f.write(generated)
    except Exception:
        pass
    return generated


class Config:
    """Flask configuration settings."""

    # Auto-generated and persisted to /data/secret_key if not set in env
    SECRET_KEY = _load_secret_key()

    # SQLite stored on a Docker volume so data survives container rebuilds
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:////data/database.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    FLASK_ENV = os.getenv("FLASK_ENV", "production")
    FLASK_PORT = int(os.getenv("FLASK_PORT", 8000))

    # Optional env fallback — DB value (set via Settings page) takes precedence
    WHOISFREAK_API_KEY = os.getenv("WHOISFREAK_API_KEY", "")
    WHOISFREAK_IP_ENDPOINT = "https://api.whoisfreaks.com/v1.0/ip-whois"
    WHOISFREAK_DOMAIN_ENDPOINT = "https://api.whoisfreaks.com/v1.0/whois"

    JSON_SORT_KEYS = False

    # Session expires after 8 hours of inactivity
    PERMANENT_SESSION_LIFETIME = 28800

    # Session cookie — must be sent over plain HTTP when not behind TLS
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Flask-WTF CSRF
    WTF_CSRF_TIME_LIMIT = 3600  # 1-hour token lifetime
