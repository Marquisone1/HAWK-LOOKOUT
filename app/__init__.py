import logging
import os
import secrets as _secrets
import shutil
import sqlite3
import string
import threading
import time
from datetime import datetime

from sqlalchemy.exc import IntegrityError

from flask import Flask, jsonify, render_template, request, session
from flask_wtf.csrf import CSRFError, CSRFProtect
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .models import db, User, SiteUser
from .routes import web_bp
from .api import api_bp
from .phase_b_routes import phase_b_bp
from .phase_c_routes import phase_c_bp
from .logging_util import setup_json_logging, inject_request_id

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

    # Set up structured JSON logging
    setup_json_logging(app)

    # Trust exactly one upstream proxy hop (Nginx).
    # This populates request.remote_addr with the real client IP from
    # X-Forwarded-For, preventing clients from spoofing that header.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # CSRF protection for all web form POSTs.
    # Can be temporarily disabled with WTF_CSRF_ENABLED=false.
    # The API blueprint uses X-API-Key bearer auth and is explicitly exempted.
    if app.config.get("WTF_CSRF_ENABLED", True):
        csrf = CSRFProtect(app)
        csrf.exempt(api_bp)
    else:
        logger.warning("CSRF protection is temporarily disabled (WTF_CSRF_ENABLED=false)")

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
    app.register_blueprint(phase_b_bp)
    app.register_blueprint(phase_c_bp)

    @app.after_request
    def set_cache_headers(response):
        """Prevent browsers from caching sensitive HTML pages."""
        if response.content_type and response.content_type.startswith("text/html"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    with app.app_context():
        db.create_all()
        _migrate_db()
        _bootstrap_db(app)

    @app.before_request
    def _inject_request_context():
        """Inject request ID and start timer."""
        inject_request_id()

    @app.before_request
    def _ensure_session_role():
        if 'site_user_id' in session:
            user = SiteUser.query.get(session['site_user_id'])
            if not user:
                session.clear()
                return
            session['site_role'] = user.role

    _start_daily_backup(app)

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(exc):
        logger.warning(
            "CSRF validation failed path=%s ip=%s reason=%s",
            request.path,
            request.remote_addr,
            exc.description,
        )
        if request.path == "/login":
            # Render a fresh login page with a new CSRF token.
            return render_template(
                "login.html",
                error="Your login session expired. Please try again.",
            ), 400
        if request.path.startswith("/api"):
            return jsonify({"error": "CSRF validation failed"}), 400
        return render_template(
            "login.html",
            error="Security check failed. Please sign in again.",
        ), 400

    return app


# ─────────────────────────────────────────────────────────────────────────────
# Backup
# ─────────────────────────────────────────────────────────────────────────────

BACKUP_DIR = "/data/backups"
BACKUP_DB_SOURCE = "/data/database.db"
BACKUP_KEEP_DAYS = 14
_DAILY_BACKUP_INTERVAL = 86400  # seconds

def _migrate_db():
    """Add columns introduced in v2 to existing tables."""
    from sqlalchemy import text
    with db.engine.connect() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(site_users)"))}
        if 'role' not in cols:
            conn.execute(text("ALTER TABLE site_users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'admin'"))
            logger.info("Migration: added 'role' column to site_users (existing users set to admin)")

        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(lookup_history)"))}
        if 'site_user_id' not in cols:
            conn.execute(text("ALTER TABLE lookup_history ADD COLUMN site_user_id INTEGER"))
            logger.info("Migration: added 'site_user_id' column to lookup_history")
        
        if 'source' not in cols:
            conn.execute(text("ALTER TABLE lookup_history ADD COLUMN source VARCHAR(50)"))
            logger.info("Migration: added 'source' column to lookup_history (tracks service used)")

        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(users)"))}
        if 'urlhaus_auth_key' not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN urlhaus_auth_key VARCHAR(255)"))
            logger.info("Migration: added 'urlhaus_auth_key' column to users")
        
        if 'google_safe_browsing_api_key' not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN google_safe_browsing_api_key VARCHAR(255)"))
            logger.info("Migration: added 'google_safe_browsing_api_key' column to users (for Google Safe Browsing integration)")
        
        if 'prefer_fallback' not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN prefer_fallback BOOLEAN NOT NULL DEFAULT 0"))
            logger.info("Migration: added 'prefer_fallback' column to users (default: False)")
        
        # DEPRECATED: prefer_rdap column is no longer used (RDAP service removed)
        # if 'prefer_rdap' not in cols:
        #     conn.execute(text("ALTER TABLE users ADD COLUMN prefer_rdap BOOLEAN NOT NULL DEFAULT 0"))
        #     logger.info("Migration: added 'prefer_rdap' column to users (default: False)")

        conn.commit()

def run_backup() -> str:
    """
    Create a timestamped SQLite backup using the online backup API.
    Returns the path of the created backup file.
    Raises OSError / sqlite3.Error on failure.
    """
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"database-{timestamp}.db")

    src_conn = sqlite3.connect(BACKUP_DB_SOURCE)
    dst_conn = sqlite3.connect(dest)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    # Prune old backups
    cutoff = time.time() - BACKUP_KEEP_DAYS * 86400
    for fname in os.listdir(BACKUP_DIR):
        if fname.startswith("database-") and fname.endswith(".db"):
            fpath = os.path.join(BACKUP_DIR, fname)
            if os.path.getmtime(fpath) < cutoff:
                os.remove(fpath)
                logger.info(f"Backup: pruned old backup {fname}")

    logger.info(f"Backup: created {dest} ({os.path.getsize(dest)} bytes)")
    return dest


def _start_daily_backup(app):
    """Start a background thread that runs a backup once every 24 hours."""

    def _loop():
        # Wait 60 s after startup before first backup so the app is settled
        time.sleep(60)
        while True:
            try:
                with app.app_context():
                    run_backup()
            except Exception as exc:
                logger.warning(f"Daily backup failed: {exc}")
            time.sleep(_DAILY_BACKUP_INTERVAL)

    t = threading.Thread(target=_loop, name="daily-backup", daemon=True)
    t.start()
    logger.info("Backup: daily backup scheduler started (first run in 60s)")


def _bootstrap_db(app):
    """Seed required database rows on first boot."""

    # ── Admin site user ──────────────────────────────────────────────────────
    if SiteUser.query.count() == 0:
        alphabet = string.ascii_letters + string.digits
        username = "admin"
        password = "".join(_secrets.choice(alphabet) for _ in range(16))

        admin = SiteUser(username=username, role="admin")
        admin.set_password(password)
        db.session.add(admin)
        try:
            db.session.commit()
        except IntegrityError:
            # Another worker already created the admin row — not an error.
            db.session.rollback()
        else:
            logger.warning(
                "Bootstrap: admin user created (username=%s). "
                "Credentials written to /data/first_boot_credentials.txt — change it immediately in Settings.",
                username,
            )
            cred_path = "/data/first_boot_credentials.txt"
            creds = (
                f"HAWK LOOKOUT - FIRST BOOT CREDENTIALS\n"
                f"Username: {username}\n"
                f"Password: {password}\n\n"
                f"Change these immediately in Settings and then delete this file.\n"
            )
            try:
                with open(cred_path, "w") as f:
                    f.write(creds)
                os.chmod(cred_path, 0o600)
            except Exception as exc:
                logger.warning(
                    "Bootstrap: failed to write %s (%s). Falling back to stdout.",
                    cred_path,
                    exc,
                )
                print(
                    f"\n{'=' * 58}\n"
                    f"  HAWK LOOKOUT - FIRST BOOT CREDENTIALS\n"
                    f"  Username : {username}\n"
                    f"  Password : {password}\n"
                    f"  Change these immediately in Settings!\n"
                    f"{'=' * 58}\n"
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
    logger.info("Bootstrap: internal API key is configured.")
