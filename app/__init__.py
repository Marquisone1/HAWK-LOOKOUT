import logging
import secrets as _secrets
import string
from datetime import datetime

from sqlalchemy.exc import IntegrityError

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .models import db, User, SiteUser
from .routes import web_bp
from .api import api_bp

logger = logging.getLogger(__name__)

_CSP = {
    "default-src": "'self'",
    # Templates use inline <script> blocks — no external CDN
    "script-src": ["'self'", "'unsafe-inline'"],
    # Templates use inline <style> blocks
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:"],
    "font-src": "'self'",
    # Only allow XHR/fetch back to self — stops XSS key-exfiltration
    "connect-src": "'self'",
    "object-src": "'none'",
    "frame-ancestors": "'none'",
}


def create_app():
    app = Flask(__name__, template_folder="templates")
    app.config.from_object(Config)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    # Trust exactly one upstream proxy hop (Nginx).
    # This populates request.remote_addr with the real client IP from
    # X-Forwarded-For, preventing clients from spoofing that header.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # CSRF protection for all web form POSTs.
    # The API blueprint uses X-API-Key bearer auth and is explicitly exempted.
    csrf = CSRFProtect(app)
    csrf.exempt(api_bp)

    # Security headers.
    # force_https and HSTS are enabled in production; disabled in local dev
    # so that `flask run` works without TLS.
    _in_production = app.config.get("FLASK_ENV", "production") == "production"
    Talisman(
        app,
        content_security_policy=_CSP,
        force_https=_in_production,
        strict_transport_security=_in_production,
        strict_transport_security_max_age=31536000,
        frame_options="DENY",
        x_content_type_options=True,
        referrer_policy="strict-origin-when-cross-origin",
    )

    db.init_app(app)
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    @app.after_request
    def set_cache_headers(response):
        """Prevent browsers from caching sensitive HTML pages."""
        if response.content_type and response.content_type.startswith("text/html"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    with app.app_context():
        db.create_all()
        _bootstrap_db(app)

    return app


def _bootstrap_db(app):
    """Seed required database rows on first boot."""

    # ── Admin site user ──────────────────────────────────────────────────────
    if SiteUser.query.count() == 0:
        alphabet = string.ascii_letters + string.digits
        username = "admin"
        password = "".join(_secrets.choice(alphabet) for _ in range(16))

        admin = SiteUser(username=username)
        admin.set_password(password)
        db.session.add(admin)
        try:
            db.session.commit()
        except IntegrityError:
            # Another worker already created the admin row — not an error.
            db.session.rollback()
        else:
            border = "=" * 58
            creds_path = "/data/first_boot_credentials.txt"
            creds_content = (
                f"{border}\n"
                f"  HAWK LOOKOUT \u2014 FIRST BOOT CREDENTIALS\n"
                f"  Username : {username}\n"
                f"  Password : {password}\n"
                f"  Change these immediately in Settings!\n"
                f"{border}\n"
            )
            try:
                import stat
                with open(creds_path, "w") as cf:
                    cf.write(creds_content)
                import os as _os
                _os.chmod(creds_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logger.warning(f"Could not write credentials file: {e}")
            logger.warning(
                f"Bootstrap: admin created. Credentials written to {creds_path} — "
                "read and delete this file, then change your password in Settings."
            )

    # ── API-key user (dedup + ensure one row) ────────────────────────────────
    all_users = User.query.order_by(User.id).all()
    if len(all_users) > 1:
        keep = sorted(
            all_users,
            key=lambda u: (u.last_used is not None, u.last_used or datetime.min, u.id),
            reverse=True,
        )[0]
        for u in all_users:
            if u.id != keep.id:
                db.session.delete(u)
        db.session.commit()
        logger.info(f"Bootstrap: deduplicated User table, kept id={keep.id}")

    if User.query.count() == 0:
        # Internal X-API-Key for browser\u2192server calls \u2014 random each fresh install
        # WhoisFreak key is seeded from env if provided; update via Settings
        initial_wf_key = app.config.get("WHOISFREAK_API_KEY") or ""
        app_user = User(
            api_key=_secrets.token_hex(16),
            whoisfreak_api_key=initial_wf_key if initial_wf_key else None,
            created_at=datetime.utcnow(),
        )
        db.session.add(app_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
        else:
            logger.info("Bootstrap: internal API key user created.")

    api_key_user = User.query.first()
    logger.info(f"Active internal API key: {api_key_user.api_key[:8]}...")
