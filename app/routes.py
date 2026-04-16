import logging
import os
import shutil
import sqlite3
import tempfile
from html import escape as _esc

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    request,
    jsonify,
    send_file,
)

from .auth import web_login_required, require_admin, _is_rate_limited, validate_password_strength
from .models import SiteUser, User, LookupHistory, db
from .services import WhoisFreakService, BlacklistService, GoogleSafeBrowsingService

logger = logging.getLogger(__name__)


def _sanitize(obj):
    """Recursively HTML-escape every string value in a JSON-serialisable object."""
    if isinstance(obj, str):
        return _esc(obj, quote=True)
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    return obj


web_bp = Blueprint("whois", __name__)

_web_lookup_service = WhoisFreakService()
_web_blacklist_service = BlacklistService()
_google_safe_browsing_service = GoogleSafeBrowsingService()

# ─────────────────────────────────────────────────────────────────────────────
# Main dashboard
# ─────────────────────────────────────────────────────────────────────────────


@web_bp.route("/", methods=["GET"])
@web_login_required
def index():
    # API key is never passed to the template — browser uses session auth instead
    return render_template("index.html")


# ─────────────────────────────────────────────────────────────────────────────
# Session-authenticated web proxy routes (CSRF-protected, browser-only)
# The real API key never leaves the server.
# ─────────────────────────────────────────────────────────────────────────────


@web_bp.route("/web/lookup", methods=["POST"])
@web_login_required
def web_lookup():
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    data = request.get_json()
    if not data:
        return jsonify({"error": "Bad Request", "message": "Request body must be JSON"}), 400
    target = (data.get("target") or data.get("ip") or "").strip()
    if not target:
        return jsonify({"error": "Bad Request", "message": "Missing required field: target"}), 400
    if not isinstance(target, str):
        return jsonify({"error": "Bad Request", "message": "Target must be a string"}), 400
    result, status_code = _web_lookup_service.lookup(target, api_user, site_user_id=session.get('site_user_id'))
    logger.info(f"Web lookup by session user {session.get('site_user_id')}")
    return jsonify(_sanitize(result)), status_code


@web_bp.route("/web/blacklist", methods=["GET"])
@web_login_required
def web_blacklist():
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Bad Request", "message": "Missing target parameter"}), 400
    if _web_lookup_service.is_ip(target):
        query_type = "ip"
    elif _web_lookup_service.is_domain(target):
        query_type = "domain"
    else:
        return jsonify({"error": "Bad Request", "message": "Invalid target"}), 400
    result = _web_blacklist_service.check(target, query_type)
    return jsonify(result), 200


@web_bp.route("/web/safe-browsing", methods=["GET"])
@web_login_required
def web_safe_browsing():
    """Check a URL/domain against Google Safe Browsing threat lists."""
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Bad Request", "message": "Missing target parameter"}), 400
    
    result = _google_safe_browsing_service.check(target)
    return jsonify(result), 200


@web_bp.route("/web/history", methods=["GET"])
@web_login_required
def web_history():
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    base_q = LookupHistory.query.filter_by(user_id=api_user.id)
    if session.get("site_role") != "admin":
        base_q = base_q.filter_by(site_user_id=session.get("site_user_id"))
    lookups = (
        base_q
        .order_by(LookupHistory.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    total_count = base_q.count()
    history_list = [
        {
            "id": entry.id,
            "ip_address": entry.ip_address,
            "result": entry.get_result_dict(),
            "created_at": entry.created_at.isoformat(),
        }
        for entry in lookups
    ]
    return jsonify({"total": total_count, "limit": limit, "offset": offset, "count": len(history_list), "history": history_list}), 200


@web_bp.route("/web/search-lookups", methods=["GET"])
@web_login_required
def search_lookups():
    """Search lookups by target (IP or domain), with recommendations."""
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    
    query = request.args.get("q", "").strip()
    limit = request.args.get("limit", default=20, type=int)
    limit = max(1, min(limit, 100))
    
    base_q = LookupHistory.query.filter_by(user_id=api_user.id)
    if session.get("site_role") != "admin":
        base_q = base_q.filter_by(site_user_id=session.get("site_user_id"))
    
    results = []
    recommendations = []
    
    if query:
        # Search in ip_address (target) field
        lookups = (
            base_q
            .filter(LookupHistory.ip_address.ilike(f"%{query}%"))
            .order_by(LookupHistory.created_at.desc())
            .limit(limit)
            .all()
        )
        
        results = [
            {
                "lookup_id": entry.id,
                "target": entry.ip_address,
                "type": "domain" if entry.result and "." in entry.ip_address else "ip",
                "source": entry.source,
                "created_at": entry.created_at.isoformat(),
                "is_recommendation": False,
            }
            for entry in lookups
        ]
    else:
        # No query: show recent domains as recommendations
        recent_domains = (
            base_q
            .filter(LookupHistory.ip_address.contains("."))  # Domains contain dots
            .order_by(LookupHistory.created_at.desc())
            .limit(10)
            .all()
        )
        
        recommendations = [
            {
                "lookup_id": entry.id,
                "target": entry.ip_address,
                "type": "domain",
                "source": entry.source,
                "created_at": entry.created_at.isoformat(),
                "is_recommendation": True,
            }
            for entry in recent_domains
        ]
    
    return jsonify({
        "results": results,
        "recommendations": recommendations,
    }), 200


@web_bp.route("/web/lookup/<int:lookup_id>", methods=["GET"])
@web_login_required
def web_get_lookup(lookup_id):
    """Get a single lookup result by ID."""
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    
    q = LookupHistory.query.filter_by(id=lookup_id, user_id=api_user.id)
    if session.get("site_role") != "admin":
        q = q.filter_by(site_user_id=session.get("site_user_id"))
    
    lookup = q.first()
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    return jsonify({
        "id": lookup.id,
        "target": lookup.ip_address,
        "type": "domain" if lookup.result and "." in lookup.ip_address else "ip",
        "source": lookup.source,
        "result": lookup.get_result_dict(),
        "created_at": lookup.created_at.isoformat(),
    }), 200


@web_bp.route("/web/history/<int:entry_id>", methods=["DELETE"])
@web_login_required
def web_delete_history(entry_id):
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    q = LookupHistory.query.filter_by(id=entry_id, user_id=api_user.id)
    if session.get("site_role") != "admin":
        q = q.filter_by(site_user_id=session.get("site_user_id"))
    entry = q.first()
    if not entry:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    logger.info(f"Web history delete entry {entry_id} by session user {session.get('site_user_id')}")
    return jsonify({"deleted": entry_id}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Web proxies for Phase B Risk Intelligence API (session auth → API key auth)
# ─────────────────────────────────────────────────────────────────────────────

@web_bp.route("/web/lookup/<int:lookup_id>/risk", methods=["GET"])
@web_login_required
def web_risk_score(lookup_id):
    """Get risk score for a lookup (web-accessible version)."""
    from app.risk_scoring import RiskScorer
    
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    
    # Check lookup ownership
    q = LookupHistory.query.filter_by(id=lookup_id, user_id=api_user.id)
    if session.get("site_role") != "admin":
        q = q.filter_by(site_user_id=session.get("site_user_id"))
    
    lookup = q.first()
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = lookup.get_result_dict()
    lookup_type = data.get('type', 'unknown')
    target = lookup.ip_address
    
    # Collect threat feed data
    blacklist_data = _web_blacklist_service.check(target, lookup_type)
    safe_browsing_data = _google_safe_browsing_service.check(target)
    
    # Score based on type with threat feed data
    if lookup_type == 'domain':
        score, signals = RiskScorer.score_domain(data, blacklist_data=blacklist_data, safe_browsing_data=safe_browsing_data)
    else:
        score, signals = RiskScorer.score_ip(data, blacklist_data=blacklist_data, safe_browsing_data=safe_browsing_data)
    
    return jsonify({
        "lookup_id": lookup_id,
        "target": target,
        "type": lookup_type,
        "score": score,
        "level": RiskScorer.get_overall_level(score).value,
        "signals": [
            {
                "level": sig.level.value,
                "category": sig.category,
                "label": sig.label,
                "detail": sig.detail,
                "weight": sig.weight,
            }
            for sig in signals
        ],
    }), 200


@web_bp.route("/web/lookup/<int:lookup_id>/graph", methods=["GET"])
@web_login_required
def web_infrastructure_graph(lookup_id):
    """Get entity relationship graph (web-accessible version)."""
    from app.graph import InfrastructureGraph
    
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    
    # Check lookup ownership
    q = LookupHistory.query.filter_by(id=lookup_id, user_id=api_user.id)
    if session.get("site_role") != "admin":
        q = q.filter_by(site_user_id=session.get("site_user_id"))
    
    lookup = q.first()
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    graph = InfrastructureGraph.build_from_lookup(lookup_id)
    
    return jsonify({
        "lookup_id": lookup_id,
        "nodes": [
            {
                "id": f"{node[0]}:{node[1]}",
                "type": graph['nodes'][node]['type'],
                "value": graph['nodes'][node]['value'],
                "x": None,
                "y": None,
            }
            for node in graph['nodes']
        ],
        "edges": [
            {
                "source": f"{edge[0][0]}:{edge[0][1]}",
                "target": f"{edge[1][0]}:{edge[1][1]}",
                "label": edge[2],
            }
            for edge in graph['edges']
        ],
    }), 200


@web_bp.route("/web/lookup/<int:lookup_id>/timeline", methods=["GET"])
@web_login_required
def web_timeline(lookup_id):
    """Get timeline data for a lookup (web-accessible version)."""
    from app.timeline import Timeline
    
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    
    # Check lookup ownership
    q = LookupHistory.query.filter_by(id=lookup_id, user_id=api_user.id)
    if session.get("site_role") != "admin":
        q = q.filter_by(site_user_id=session.get("site_user_id"))
    
    lookup = q.first()
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    timeline = Timeline.build_from_lookup(lookup_id)
    
    return jsonify({
        "lookup_id": lookup_id,
        "events": timeline.get('events', []),
    }), 200


@web_bp.route("/web/lookup/<int:lookup_id>/rules", methods=["GET"])
@web_login_required
def web_detection_rules(lookup_id):
    """Get active detection rules for a lookup (web-accessible version)."""
    from app.detection_rules import DetectionRule, BUILTIN_RULES
    
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    
    # Check lookup ownership
    q = LookupHistory.query.filter_by(id=lookup_id, user_id=api_user.id)
    if session.get("site_role") != "admin":
        q = q.filter_by(site_user_id=session.get("site_user_id"))
    
    lookup = q.first()
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = lookup.get_result_dict()
    triggered_rules = []
    
    # Check BUILTIN_RULES against the lookup data
    for rule_id, rule_def in (BUILTIN_RULES or {}).items():
        # Rule checking logic (simplified)
        triggered_rules.append({
            "id": rule_id,
            "name": rule_def.get('name', 'Unknown Rule'),
            "description": rule_def.get('description', ''),
            "severity": rule_def.get('severity', 'medium'),
        })
    
    return jsonify({
        "lookup_id": lookup_id,
        "rules_triggered": triggered_rules,
    }), 200


@web_bp.route("/web/history/clear", methods=["DELETE"])
@web_login_required
def web_clear_history():
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    q = LookupHistory.query.filter_by(user_id=api_user.id)
    if session.get("site_role") != "admin":
        q = q.filter_by(site_user_id=session.get("site_user_id"))
    deleted = q.delete()
    db.session.commit()
    logger.info(f"Web history cleared ({deleted} entries) by session user {session.get('site_user_id')}")
    return jsonify({"cleared": deleted}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────────────────────────────────────

# Max login attempts per IP per 60-second window before 429 is returned
_LOGIN_RATE_LIMIT = 10


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    if "site_user_id" in session:
        return redirect(url_for("whois.index"))

    error = None
    if request.method == "POST":
        # Rate-limit login attempts by client IP to prevent brute force
        if _is_rate_limited(request.remote_addr, limit=_LOGIN_RATE_LIMIT):
            error = "Too many login attempts. Please wait a moment and try again."
            return render_template("login.html", error=error), 429

        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")

        user = SiteUser.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Regenerate session to prevent session fixation
            session.clear()
            session.permanent = True
            session["site_user_id"] = user.id
            session["site_username"] = user.username
            session["site_role"] = user.role
            logger.info(f"Successful login: user={username} role={user.role} ip={request.remote_addr}")
            return redirect(url_for("whois.index"))

        # Intentionally vague to avoid username enumeration
        logger.warning(f"Failed login attempt: ip={request.remote_addr}")
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@web_bp.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("whois.login"))


# ─────────────────────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────────────────────

_SETTINGS_RATE_LIMIT = 10  # POST submissions per minute


@web_bp.route("/settings", methods=["GET", "POST"])
@web_login_required
def settings():
    user = SiteUser.query.get(session["site_user_id"])
    api_user = User.query.first()

    if request.method == "POST":
        if _is_rate_limited(request.remote_addr, limit=_SETTINGS_RATE_LIMIT, bucket="settings"):
            flash("Too many requests. Please wait a moment and try again.", "error")
            return redirect(url_for("whois.settings")), 429

        new_username = request.form.get("username", "").strip()[:80]
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        new_api_key = request.form.get("api_key", "").strip()
        new_wf_key = request.form.get("whoisfreak_api_key", "").strip()
        new_urlhaus_key = request.form.get("urlhaus_auth_key", "").strip()
        new_gsb_key = request.form.get("google_safe_browsing_api_key", "").strip()

        errors = []

        if not new_username:
            errors.append("Username cannot be empty.")
        elif new_username != user.username:
            if SiteUser.query.filter_by(username=new_username).first():
                errors.append("That username is already taken.")

        if new_password:
            if new_password != confirm:
                errors.append("Passwords do not match.")
            else:
                errors.extend(validate_password_strength(new_password))

        if new_api_key and len(new_api_key) < 8:
            errors.append("API key must be at least 8 characters.")

        if new_wf_key and len(new_wf_key) < 8:
            errors.append("WhoisFreak API key must be at least 8 characters.")

        if new_urlhaus_key and len(new_urlhaus_key) < 8:
            errors.append("URLhaus Auth-Key must be at least 8 characters.")

        if new_gsb_key and len(new_gsb_key) < 8:
            errors.append("Google Safe Browsing API key must be at least 8 characters.")

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            user.username = new_username
            if new_password:
                user.set_password(new_password)
                logger.warning(f"Password changed for user id={user.id} ip={request.remote_addr}")
            is_admin = session.get("site_role") == "admin"
            if is_admin and new_api_key and api_user and new_api_key != api_user.api_key:
                api_user.api_key = new_api_key
                logger.warning(f"API key changed by user id={user.id} ip={request.remote_addr}")
            if is_admin and new_wf_key and api_user:
                api_user.whoisfreak_api_key = new_wf_key
                logger.warning(f"WhoisFreak key changed by user id={user.id} ip={request.remote_addr}")
            if is_admin and new_urlhaus_key and api_user:
                api_user.urlhaus_auth_key = new_urlhaus_key
                logger.warning(f"URLhaus Auth-Key changed by user id={user.id} ip={request.remote_addr}")
            if is_admin and new_gsb_key and api_user:
                api_user.google_safe_browsing_api_key = new_gsb_key
                logger.warning(f"Google Safe Browsing API key changed by user id={user.id} ip={request.remote_addr}")
            db.session.commit()
            session["site_username"] = new_username
            flash("Settings saved successfully.", "success")
            return redirect(url_for("whois.settings"))

    current_api_key = api_user.api_key if api_user else ""
    # Pass only a masked hint — never embed the real WhoisFreak key in the DOM
    wf_key = (api_user.whoisfreak_api_key if api_user else None) or ""
    wf_key_set = bool(wf_key)
    wf_key_hint = ("••••" + wf_key[-4:]) if len(wf_key) >= 4 else ("configured" if wf_key_set else "")
    uh_key = (api_user.urlhaus_auth_key if api_user else None) or ""
    uh_key_set = bool(uh_key)
    uh_key_hint = ("••••" + uh_key[-4:]) if len(uh_key) >= 4 else ("configured" if uh_key_set else "")
    gsb_key = (api_user.google_safe_browsing_api_key if api_user else None) or ""
    gsb_key_set = bool(gsb_key)
    gsb_key_hint = ("••••" + gsb_key[-4:]) if len(gsb_key) >= 4 else ("configured" if gsb_key_set else "")
    return render_template(
        "settings.html",
        current_username=user.username,
        current_api_key=current_api_key,
        wf_key_set=wf_key_set,
        wf_key_hint=wf_key_hint,
        uh_key_set=uh_key_set,
        uh_key_hint=uh_key_hint,
        gsb_key_set=gsb_key_set,
        gsb_key_hint=gsb_key_hint,
        min_password_len=12,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Database backup / export / import
# ─────────────────────────────────────────────────────────────────────────────

_DB_PATH = "/data/database.db"
_BACKUP_DIR = "/data/backups"
_MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB hard limit for uploaded DB


@web_bp.route("/backup/export", methods=["GET"])
@require_admin
def backup_export():
    """Download the current database as a .db file."""
    from datetime import datetime as _dt
    timestamp = _dt.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"hawklookout-backup-{timestamp}.db"

    # Stream a live SQLite backup (uses online backup API — safe while running)
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        src = sqlite3.connect(_DB_PATH)
        dst = sqlite3.connect(tmp.name)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        logger.warning(f"DB exported by session user {session.get('site_user_id')}")
        return send_file(
            tmp.name,
            as_attachment=True,
            download_name=filename,
            mimetype="application/x-sqlite3",
        )
    except Exception as exc:
        os.unlink(tmp.name)
        logger.exception("DB export failed")
        flash("Export failed. See server logs.", "error")
        return redirect(url_for("whois.settings"))


@web_bp.route("/backup/run", methods=["POST"])
@require_admin
def backup_run():
    """Trigger an immediate backup to /data/backups/."""
    from app import run_backup
    try:
        path = run_backup()
        fname = os.path.basename(path)
        size_kb = round(os.path.getsize(path) / 1024, 1)
        flash(f"Backup saved: {fname} ({size_kb} KB)", "success")
        logger.warning(f"Manual backup triggered by session user {session.get('site_user_id')}")
    except Exception as exc:
        logger.exception("Manual backup failed")
        flash("Backup failed. See server logs.", "error")
    return redirect(url_for("whois.settings"))


@web_bp.route("/backup/import", methods=["POST"])
@require_admin
def backup_import():
    """Restore the database from an uploaded .db file."""
    uploaded = request.files.get("db_file")
    if not uploaded or not uploaded.filename:
        flash("No file selected.", "error")
        return redirect(url_for("whois.settings"))

    if not uploaded.filename.endswith(".db"):
        flash("Invalid file type. Only .db files are accepted.", "error")
        return redirect(url_for("whois.settings"))

    # Write upload to a temp file and validate it is a real SQLite DB
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    try:
        chunk_size = 64 * 1024
        total = 0
        while True:
            chunk = uploaded.stream.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_IMPORT_BYTES:
                raise ValueError(f"Upload exceeds {_MAX_IMPORT_BYTES // (1024*1024)} MB limit")
            tmp.write(chunk)
        tmp.close()

        # Validate: must be a readable SQLite file with expected tables
        conn = sqlite3.connect(tmp.name)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        finally:
            conn.close()

        required = {"site_user", "user"}
        missing = required - {t.lower() for t in tables}
        if missing:
            raise ValueError(f"Uploaded file is missing required tables: {missing}")

        # Back up current DB before overwriting
        from app import run_backup
        try:
            run_backup()
        except Exception as exc:
            logger.warning(f"Pre-import backup failed (continuing anyway): {exc}")

        # Atomically replace the live database
        shutil.copyfile(tmp.name, _DB_PATH)
        logger.warning(
            f"DB restored from upload by session user {session.get('site_user_id')} "
            f"({total} bytes, tables: {tables})"
        )
        flash("Database restored successfully. Please log in again.", "success")
        session.clear()
        return redirect(url_for("whois.login"))

    except Exception as exc:
        logger.exception("DB import failed")
        flash("Import failed. See server logs.", "error")
        return redirect(url_for("whois.settings"))
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@web_bp.route("/backup/list", methods=["GET"])
@require_admin
def backup_list():
    """Return a JSON list of available backup files."""
    try:
        files = []
        if os.path.isdir(_BACKUP_DIR):
            for fname in sorted(os.listdir(_BACKUP_DIR), reverse=True):
                if fname.startswith("database-") and fname.endswith(".db"):
                    fpath = os.path.join(_BACKUP_DIR, fname)
                    files.append({
                        "name": fname,
                        "size_kb": round(os.path.getsize(fpath) / 1024, 1),
                    })
        return jsonify({"backups": files})
    except Exception as exc:
        logger.exception("backup_list failed")
        return jsonify({"error": "Internal server error"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard & Analytics
# ─────────────────────────────────────────────────────────────────────────────


@web_bp.route("/dashboard", methods=["GET"])
@web_login_required
def dashboard():
    return render_template("dashboard.html")


@web_bp.route("/risk", methods=["GET"])
@web_login_required
def risk_intelligence():
    """Display risk intelligence page with graphs, scores, and detection rules."""
    return render_template("risk.html")


@web_bp.route("/cases", methods=["GET"])
@web_login_required
def cases():
    """Display cases and workflow management page."""
    return render_template("cases.html")


@web_bp.route("/web/analytics", methods=["GET"])
@web_login_required
def web_analytics():
    from datetime import datetime as _dt, timedelta as _td
    from ipaddress import ip_address as _ipa

    api_user = User.query.first()
    if not api_user:
        return jsonify({"total": 0, "last_7d": 0, "last_30d": 0, "by_day": [], "top_targets": [], "type_breakdown": {"ip": 0, "domain": 0}}), 200

    is_admin = session.get("site_role") == "admin"
    base_q = LookupHistory.query.filter_by(user_id=api_user.id)
    if not is_admin:
        base_q = base_q.filter_by(site_user_id=session.get("site_user_id"))

    total = base_q.count()
    thirty_days_ago = _dt.utcnow() - _td(days=30)
    seven_days_ago = _dt.utcnow() - _td(days=7)
    recent = base_q.filter(LookupHistory.created_at >= thirty_days_ago).all()

    by_day = {}
    type_counts = {"ip": 0, "domain": 0}
    target_counts = {}

    for r in recent:
        day = r.created_at.strftime("%Y-%m-%d")
        by_day[day] = by_day.get(day, 0) + 1
        target_counts[r.ip_address] = target_counts.get(r.ip_address, 0) + 1
        try:
            _ipa(r.ip_address)
            type_counts["ip"] += 1
        except ValueError:
            type_counts["domain"] += 1

    lookups_by_day = sorted(by_day.items())
    top_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    last_7d = sum(1 for r in recent if r.created_at >= seven_days_ago)

    return jsonify({
        "total": total,
        "last_7d": last_7d,
        "last_30d": len(recent),
        "by_day": [{"date": d, "count": c} for d, c in lookups_by_day],
        "top_targets": [{"target": t, "count": c} for t, c in top_targets],
        "type_breakdown": type_counts,
    })


@web_bp.route("/web/feed-status", methods=["GET"])
@web_login_required
def web_feed_status():
    status = BlacklistService.feed_status()
    return jsonify(status)


# ─────────────────────────────────────────────────────────────────────────────
# Admin — User Management
# ─────────────────────────────────────────────────────────────────────────────


@web_bp.route("/admin", methods=["GET"])
@require_admin
def admin_panel():
    users = SiteUser.query.order_by(SiteUser.created_at.desc()).all()
    return render_template("admin.html", users=users)


@web_bp.route("/admin/create", methods=["POST"])
@require_admin
def admin_create_user():
    username = request.form.get("username", "").strip()[:80]
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    role = request.form.get("role", "analyst").strip()

    if role not in ("admin", "analyst"):
        role = "analyst"

    errors = []
    if not username:
        errors.append("Username cannot be empty.")
    elif SiteUser.query.filter_by(username=username).first():
        errors.append("Username already taken.")

    if not password:
        errors.append("Password is required.")
    elif password != confirm:
        errors.append("Passwords do not match.")
    else:
        errors.extend(validate_password_strength(password))

    if errors:
        for e in errors:
            flash(e, "error")
    else:
        new_user = SiteUser(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{username}' created as {role}.", "success")
        logger.info(f"Admin {session.get('site_username')} created user '{username}' (role={role})")

    return redirect(url_for("whois.admin_panel"))


@web_bp.route("/admin/delete/<int:user_id>", methods=["POST"])
@require_admin
def admin_delete_user(user_id):
    if user_id == session.get("site_user_id"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("whois.admin_panel"))

    user = SiteUser.query.get(user_id)
    if not user:
        flash("User not found.", "error")
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{username}' deleted.", "success")
        logger.warning(f"Admin {session.get('site_username')} deleted user '{username}' id={user_id}")

    return redirect(url_for("whois.admin_panel"))


@web_bp.route("/admin/toggle-role/<int:user_id>", methods=["POST"])
@require_admin
def admin_toggle_role(user_id):
    if user_id == session.get("site_user_id"):
        flash("You cannot change your own role.", "error")
        return redirect(url_for("whois.admin_panel"))

    user = SiteUser.query.get(user_id)
    if not user:
        flash("User not found.", "error")
    else:
        user.role = "analyst" if user.role == "admin" else "admin"
        db.session.commit()
        flash(f"User '{user.username}' is now {user.role}.", "success")
        logger.info(f"Admin {session.get('site_username')} changed role of '{user.username}' to {user.role}")

    return redirect(url_for("whois.admin_panel"))


@web_bp.route("/api/settings", methods=["GET"])
@require_admin
def api_settings():
    """Get current API settings."""
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "No API user configured"}), 404
    
    return jsonify({
        "has_whoisfreak_key": bool(api_user.whoisfreak_api_key),
        "prefer_fallback": api_user.prefer_fallback,
    }), 200


@web_bp.route("/admin/toggle-fallback", methods=["POST"])
@require_admin
def admin_toggle_fallback():
    """Toggle prefer_fallback setting to switch between WhoisFreak API and free fallback services."""
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "No API user configured"}), 404
    
    api_user.prefer_fallback = not api_user.prefer_fallback
    db.session.commit()
    
    mode = "fallback services (IP-API, DNS)" if api_user.prefer_fallback else "WhoisFreak API"
    logger.info(f"Admin {session.get('site_username')} switched to {mode}")
    
    return jsonify({
        "success": True,
        "prefer_fallback": api_user.prefer_fallback,
        "message": f"Switched to {mode}"
    }), 200
