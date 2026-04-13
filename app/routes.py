import logging

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    request,
    jsonify,
)

from .auth import web_login_required, _is_rate_limited, validate_password_strength
from .models import SiteUser, User, LookupHistory, db
from .services import WhoisFreakService, BlacklistService

logger = logging.getLogger(__name__)

web_bp = Blueprint("whois", __name__)

_web_lookup_service = WhoisFreakService()
_web_blacklist_service = BlacklistService()

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
    result, status_code = _web_lookup_service.lookup(target, api_user)
    logger.info(f"Web lookup by session user {session.get('site_user_id')}: {target}")
    return jsonify(result), status_code


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
    lookups = (
        LookupHistory.query.filter_by(user_id=api_user.id)
        .order_by(LookupHistory.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    total_count = LookupHistory.query.filter_by(user_id=api_user.id).count()
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


@web_bp.route("/web/history/<int:entry_id>", methods=["DELETE"])
@web_login_required
def web_delete_history(entry_id):
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    entry = LookupHistory.query.filter_by(id=entry_id, user_id=api_user.id).first()
    if not entry:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    logger.info(f"Web history delete entry {entry_id} by session user {session.get('site_user_id')}")
    return jsonify({"deleted": entry_id}), 200


@web_bp.route("/web/history/clear", methods=["DELETE"])
@web_login_required
def web_clear_history():
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Unauthorized", "message": "No API user configured"}), 401
    deleted = LookupHistory.query.filter_by(user_id=api_user.id).delete()
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

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = SiteUser.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Regenerate session to prevent session fixation
            session.clear()
            session.permanent = True
            session["site_user_id"] = user.id
            session["site_username"] = user.username
            logger.info(f"Successful login: user={username} ip={request.remote_addr}")
            return redirect(url_for("whois.index"))

        # Intentionally vague to avoid username enumeration
        logger.warning(f"Failed login attempt: ip={request.remote_addr}")
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@web_bp.route("/logout")
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

        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        new_api_key = request.form.get("api_key", "").strip()
        new_wf_key = request.form.get("whoisfreak_api_key", "").strip()

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

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            user.username = new_username
            if new_password:
                user.set_password(new_password)
                logger.warning(f"Password changed for user id={user.id} ip={request.remote_addr}")
            if new_api_key and api_user and new_api_key != api_user.api_key:
                api_user.api_key = new_api_key
                logger.warning(f"API key changed by user id={user.id} ip={request.remote_addr}")
            if new_wf_key and api_user:
                api_user.whoisfreak_api_key = new_wf_key
                logger.warning(f"WhoisFreak key changed by user id={user.id} ip={request.remote_addr}")
            db.session.commit()
            session["site_username"] = new_username
            flash("Settings saved successfully.", "success")
            return redirect(url_for("whois.settings"))

    current_api_key = api_user.api_key if api_user else ""
    # Pass only a masked hint — never embed the real WhoisFreak key in the DOM
    wf_key = (api_user.whoisfreak_api_key if api_user else None) or ""
    wf_key_set = bool(wf_key)
    wf_key_hint = ("••••" + wf_key[-4:]) if len(wf_key) >= 4 else ("configured" if wf_key_set else "")
    return render_template(
        "settings.html",
        current_username=user.username,
        current_api_key=current_api_key,
        wf_key_set=wf_key_set,
        wf_key_hint=wf_key_hint,
        min_password_len=12,
    )
