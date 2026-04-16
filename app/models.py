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
    # Use free fallback services (IP-API, DNS) instead of WhoisFreak API
    prefer_fallback = db.Column(db.Boolean, default=False, nullable=False)
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
    source = db.Column(db.String(50), nullable=True)  # Track which service: "WhoisFreak", "IP-API", "DNS"
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


# ─────────────────────────────────────────────────────────────────────────────
# Phase C: Workflow (Comments, Cases, Evidence Snapshots)
# ─────────────────────────────────────────────────────────────────────────────

class LookupCase(db.Model):
    """Group related lookups into investigation cases."""
    
    __tablename__ = "lookup_cases"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    site_user_id = db.Column(db.Integer, db.ForeignKey("site_users.id"), nullable=True)
    
    case_id = db.Column(db.String(50), unique=True, nullable=False, index=True)  # e.g. 'CASE-2026-001'
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='open')  # open, investigating, resolved, false_positive
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    lookups = db.relationship("LookupHistory", backref="case", lazy=True)
    notes = db.relationship("LookupNote", backref="case", lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<LookupCase {self.case_id}: {self.title}>"


class LookupNote(db.Model):
    """Comments/notes on a lookup or case."""
    
    __tablename__ = "lookup_notes"
    
    id = db.Column(db.Integer, primary_key=True)
    lookup_id = db.Column(db.Integer, db.ForeignKey("lookup_history.id"), nullable=True)
    case_id = db.Column(db.Integer, db.ForeignKey("lookup_cases.id"), nullable=True)
    site_user_id = db.Column(db.Integer, db.ForeignKey("site_users.id"), nullable=False)
    
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(255), nullable=True)  # CSV: phishing,malware,suspicious
    verdict = db.Column(db.String(20), nullable=True)  # clean, suspicious, malicious
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<LookupNote {self.id} on lookup {self.lookup_id}>"


class LookupSnapshot(db.Model):
    """Immutable evidence snapshot of a lookup result."""
    
    __tablename__ = "lookup_snapshots"
    
    id = db.Column(db.Integer, primary_key=True)
    lookup_id = db.Column(db.Integer, db.ForeignKey("lookup_history.id"), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey("lookup_cases.id"), nullable=True)
    
    # Frozen copy of the lookup result at snapshot time
    data_json = db.Column(db.Text, nullable=False)
    
    reason = db.Column(db.String(255), nullable=True)  # 'evidence_for_case', 'pre_remediation', etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def get_data(self):
        return json.loads(self.data_json)
    
    def __repr__(self):
        return f"<LookupSnapshot {self.id} for lookup {self.lookup_id}>"
