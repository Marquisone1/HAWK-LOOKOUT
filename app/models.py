from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()


class User(db.Model):
    """API-key user — authenticates REST API calls via X-API-Key header."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    # WhoisFreak third-party API key — managed via the Settings page, never exposed to the browser
    whoisfreak_api_key = db.Column(db.String(255), nullable=True)
    # URLhaus (abuse.ch) Auth-Key — managed via Settings, never exposed to the browser
    urlhaus_auth_key = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used = db.Column(db.DateTime, onupdate=datetime.utcnow)

    lookups = db.relationship(
        "LookupHistory", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User {self.id}: {self.api_key[:8]}...>"


class LookupHistory(db.Model):
    """Stores WHOIS query results per user."""

    __tablename__ = "lookup_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    site_user_id = db.Column(
        db.Integer, db.ForeignKey("site_users.id"), nullable=True, index=True
    )
    ip_address = db.Column(db.String(253), nullable=False)  # also holds domain names
    result = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False, index=True
    )

    def __repr__(self):
        return f"<LookupHistory {self.id}: {self.ip_address}>"

    def get_result_dict(self):
        return json.loads(self.result)


class SiteUser(db.Model):
    """Web-UI login user — authenticates via username/password session."""

    __tablename__ = "site_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<SiteUser {self.username} ({self.role})>"
