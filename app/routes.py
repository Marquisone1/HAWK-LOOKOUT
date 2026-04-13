import logging

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    request,
)

from .auth import web_login_required, _is_rate_limited
from .models import SiteUser, User, db

logger = logging.getLogger(__name__)

web_bp = Blueprint("whois", __name__)

# ─────────────────────────────────────────────────────────────────────────────
# Main dashboard
# ─────────────────────────────────────────────────────────────────────────────


@web_bp.route("/", methods=["GET"])
@web_login_required
def index():
    api_user = User.query.first()
    api_key = api_user.api_key if api_user else ""
    return render_template("index.html", api_key=api_key)


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
            return redirect(url_for("whois.index"))

        # Intentionally vague to avoid username enumeration
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@web_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("whois.login"))


# ─────────────────────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────────────────────

_MIN_PASSWORD_LEN = 12


@web_bp.route("/settings", methods=["GET", "POST"])
@web_login_required
def settings():
    user = SiteUser.query.get(session["site_user_id"])
    api_user = User.query.first()

    if request.method == "POST":
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
            elif len(new_password) < _MIN_PASSWORD_LEN:
                errors.append(
                    f"Password must be at least {_MIN_PASSWORD_LEN} characters."
                )

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
            if new_api_key and api_user and new_api_key != api_user.api_key:
                api_user.api_key = new_api_key
            if new_wf_key and api_user:
                api_user.whoisfreak_api_key = new_wf_key
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
        min_password_len=_MIN_PASSWORD_LEN,
    )
