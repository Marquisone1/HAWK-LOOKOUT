"""
Phase B & C API endpoints: Risk Intelligence, Entity Graphs, Cases & Workflow.

These endpoints integrate with the session-authenticated web UI.
They return JSON and are accessible to authenticated web users.
"""

import logging
import json
from datetime import datetime
from html import escape as _esc

from flask import Blueprint, jsonify, request, session

from .auth import web_login_required
from .models import (
    LookupCase, LookupHistory, LookupNote, LookupSnapshot, 
    SiteUser, User, db
)

logger = logging.getLogger(__name__)


def _sanitize(obj):
    """Recursively HTML-escape every string value in a JSON-serializable object."""
    if isinstance(obj, str):
        return _esc(obj, quote=True)
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    return obj


api_v2_bp = Blueprint("api_v2", __name__, url_prefix="/api/v2")


# ─────────────────────────────────────────────────────────────────────────────
# Phase C: Cases & Workflow
# ─────────────────────────────────────────────────────────────────────────────

@api_v2_bp.route("/cases", methods=["GET"])
@web_login_required
def get_cases():
    """Retrieve all cases for the current user (session-authenticated)."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    cases = LookupCase.query.filter_by(site_user_id=site_user.id).all()
    result = []
    for case in cases:
        result.append({
            "id": case.id,
            "case_id": case.case_id,
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "severity": case.severity,
            "lookup_count": len(case.lookups) if case.lookups else 0,
            "note_count": len(case.notes) if case.notes else 0,
            "created_at": case.created_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
        })
    
    return jsonify(_sanitize(result)), 200


@api_v2_bp.route("/cases", methods=["POST"])
@web_login_required
def create_case():
    """Create a new investigation case."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    api_user = User.query.first()
    if not api_user:
        return jsonify({"error": "Server configuration error"}), 500
    
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    status = (data.get("status") or "open").strip()
    severity = (data.get("severity") or "medium").strip()
    
    if not title:
        return jsonify({"error": "Bad Request", "message": "Title is required"}), 400
    
    if status not in ["open", "investigating", "resolved", "false_positive"]:
        return jsonify({"error": "Bad Request", "message": "Invalid status"}), 400
    
    if severity not in ["low", "medium", "high", "critical"]:
        return jsonify({"error": "Bad Request", "message": "Invalid severity"}), 400
    
    # Generate case ID (e.g., CASE-2026-001)
    from datetime import datetime as dt
    year = dt.utcnow().year
    count = LookupCase.query.filter_by(user_id=api_user.id).count() + 1
    case_id = f"CASE-{year}-{count:03d}"
    
    try:
        case = LookupCase(
            user_id=api_user.id,
            site_user_id=site_user.id,
            case_id=case_id,
            title=title,
            description=description,
            status=status,
            severity=severity,
        )
        db.session.add(case)
        db.session.commit()
        logger.info(f"Created case {case_id} by {site_user.username}")
        
        return jsonify({
            "id": case.id,
            "case_id": case.case_id,
            "title": case.title,
            "message": "Case created successfully"
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating case: {e}")
        return jsonify({"error": "Server error", "message": str(e)}), 500


@api_v2_bp.route("/cases/<int:case_id>", methods=["GET"])
@web_login_required
def get_case(case_id):
    """Get case details by ID."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    case = LookupCase.query.filter_by(id=case_id, site_user_id=site_user.id).first()
    if not case:
        return jsonify({"error": "Not Found", "message": "Case not found"}), 404
    
    result = {
        "id": case.id,
        "case_id": case.case_id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity": case.severity,
        "lookups": [
            {
                "id": lh.id,
                "target": lh.ip_address,
                "type": "ip" if lh.ip_address.replace(".", "").isdigit() else "domain",
                "source": lh.source,
                "created_at": lh.created_at.isoformat(),
            }
            for lh in (case.lookups or [])
        ],
        "notes": [
            {
                "id": note.id,
                "content": note.content,
                "verdict": note.verdict,
                "tags": note.tags.split(",") if note.tags else [],
                "created_at": note.created_at.isoformat(),
            }
            for note in (case.notes or [])
        ],
        "created_at": case.created_at.isoformat(),
        "updated_at": case.updated_at.isoformat(),
    }
    
    return jsonify(_sanitize(result)), 200


@api_v2_bp.route("/cases/<int:case_id>/add-lookup", methods=["POST"])
@web_login_required
def add_lookup_to_case(case_id):
    """Associate a lookup with a case."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    case = LookupCase.query.filter_by(id=case_id, site_user_id=site_user.id).first()
    if not case:
        return jsonify({"error": "Not Found", "message": "Case not found"}), 404
    
    data = request.get_json() or {}
    lookup_id = data.get("lookup_id")
    
    if not lookup_id:
        return jsonify({"error": "Bad Request", "message": "lookup_id is required"}), 400
    
    lookup = LookupHistory.query.filter_by(id=lookup_id).first()
    if not lookup:
        return jsonify({"error": "Not Found", "message": "Lookup not found"}), 404
    
    try:
        lookup.case_id = case.id
        db.session.commit()
        logger.info(f"Added lookup {lookup_id} to case {case_id}")
        return jsonify({"message": "Lookup added to case"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding lookup to case: {e}")
        return jsonify({"error": "Server error"}), 500


@api_v2_bp.route("/lookup/<int:lookup_id>/notes", methods=["GET", "POST"])
@web_login_required
def lookup_notes(lookup_id):
    """Get or create notes on a lookup."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    lookup = LookupHistory.query.filter_by(id=lookup_id).first()
    if not lookup:
        return jsonify({"error": "Not Found", "message": "Lookup not found"}), 404
    
    if request.method == "GET":
        notes = LookupNote.query.filter_by(lookup_id=lookup_id).all()
        result = [
            {
                "id": note.id,
                "content": note.content,
                "verdict": note.verdict,
                "tags": note.tags.split(",") if note.tags else [],
                "created_at": note.created_at.isoformat(),
            }
            for note in notes
        ]
        return jsonify(_sanitize(result)), 200
    
    elif request.method == "POST":
        data = request.get_json() or {}
        content = (data.get("content") or "").strip()
        verdict = (data.get("verdict") or "").strip()
        tags = (data.get("tags") or "").strip()
        
        if not content:
            return jsonify({"error": "Bad Request", "message": "content is required"}), 400
        
        try:
            note = LookupNote(
                lookup_id=lookup_id,
                site_user_id=site_user.id,
                content=content,
                verdict=verdict if verdict in ["clean", "suspicious", "malicious"] else None,
                tags=tags,
            )
            db.session.add(note)
            db.session.commit()
            logger.info(f"Created note for lookup {lookup_id} by {site_user.username}")
            
            return jsonify({
                "id": note.id,
                "content": note.content,
                "verdict": note.verdict,
                "message": "Note created"
            }), 201
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating note: {e}")
            return jsonify({"error": "Server error"}), 500


@api_v2_bp.route("/lookup/<int:lookup_id>/snapshot", methods=["POST"])
@web_login_required
def create_snapshot(lookup_id):
    """Create an immutable evidence snapshot of a lookup."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    lookup = LookupHistory.query.filter_by(id=lookup_id).first()
    if not lookup:
        return jsonify({"error": "Not Found", "message": "Lookup not found"}), 404
    
    data = request.get_json() or {}
    reason = (data.get("reason") or "manual_snapshot").strip()
    
    try:
        snapshot = LookupSnapshot(
            lookup_id=lookup_id,
            case_id=data.get("case_id"),
            data_json=lookup.result,
            reason=reason,
        )
        db.session.add(snapshot)
        db.session.commit()
        logger.info(f"Created snapshot for lookup {lookup_id}")
        
        return jsonify({
            "id": snapshot.id,
            "message": "Snapshot created"
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating snapshot: {e}")
        return jsonify({"error": "Server error"}), 500


@api_v2_bp.route("/case/<int:case_id>/export/json", methods=["GET"])
@web_login_required
def export_case_json(case_id):
    """Export case data as JSON."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    case = LookupCase.query.filter_by(id=case_id, site_user_id=site_user.id).first()
    if not case:
        return jsonify({"error": "Not Found", "message": "Case not found"}), 404
    
    export_data = {
        "case": {
            "case_id": case.case_id,
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "severity": case.severity,
            "created_at": case.created_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
        },
        "lookups": [
            {
                "id": lh.id,
                "target": lh.ip_address,
                "source": lh.source,
                "result": lh.get_result_dict(),
                "created_at": lh.created_at.isoformat(),
            }
            for lh in (case.lookups or [])
        ],
        "notes": [
            {
                "content": note.content,
                "verdict": note.verdict,
                "tags": note.tags,
                "created_at": note.created_at.isoformat(),
            }
            for note in (case.notes or [])
        ],
        "exported_at": datetime.utcnow().isoformat(),
    }
    
    return jsonify(_sanitize(export_data)), 200


@api_v2_bp.route("/case/<int:case_id>/export/csv", methods=["GET"])
@web_login_required
def export_case_csv(case_id):
    """Export case data as CSV."""
    site_user = SiteUser.query.filter_by(id=session.get('site_user_id')).first()
    if not site_user:
        return jsonify({"error": "Unauthorized"}), 401
    
    case = LookupCase.query.filter_by(id=case_id, site_user_id=site_user.id).first()
    if not case:
        return jsonify({"error": "Not Found", "message": "Case not found"}), 404
    
    import io
    import csv
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Lookup Target", "Type", "Source", "Status", "Created At"])
    
    # Lookups
    for lh in (case.lookups or []):
        query_type = "IP" if lh.ip_address.replace(".", "").replace(":", "").isalnum() else "Domain"
        writer.writerow([
            lh.ip_address,
            query_type,
            lh.source,
            "success",
            lh.created_at.isoformat(),
        ])
    
    csv_data = output.getvalue()
    logger.info(f"Exported case {case_id} as CSV")
    
    return (
        csv_data,
        200,
        {
            "Content-Type": "text/csv",
            "Content-Disposition": f'attachment; filename="case_{case.case_id}.csv"'
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase B: Risk Intelligence, Entity Graphs, Timelines
# ─────────────────────────────────────────────────────────────────────────────

@api_v2_bp.route("/lookup/<int:lookup_id>/risk", methods=["GET"])
@web_login_required
def get_lookup_risk(lookup_id):
    """Get risk scoring for a lookup."""
    lookup = LookupHistory.query.filter_by(id=lookup_id).first()
    if not lookup:
        return jsonify({"error": "Not Found"}), 404
    
    # Placeholder: Risk scoring logic would go here
    # For now, return synthetic risk data
    risk_data = {
        "target": lookup.ip_address,
        "overall_risk_score": 45,
        "risk_level": "medium",
        "signals": {
            "blacklist_score": 30,
            "reputation_score": 60,
            "activity_score": 50,
            "network_score": 40,
        },
        "indicators": [
            {"type": "dns_history", "count": 3, "severity": "low"},
            {"type": "recent_registration", "severity": "medium"},
            {"type": "shared_hosting", "severity": "low"},
        ],
    }
    
    return jsonify(_sanitize(risk_data)), 200


@api_v2_bp.route("/lookup/<int:lookup_id>/graph", methods=["GET"])
@web_login_required
def get_entity_graph(lookup_id):
    """Get entity relationship graph for a lookup."""
    lookup = LookupHistory.query.filter_by(id=lookup_id).first()
    if not lookup:
        return jsonify({"error": "Not Found"}), 404
    
    # Placeholder: Entity graph would analyze relationships
    graph_data = {
        "target": lookup.ip_address,
        "nodes": [
            {"id": lookup.ip_address, "type": "ip", "label": lookup.ip_address},
            {"id": "ns1.example.com", "type": "nameserver", "label": "ns1.example.com"},
            {"id": "192.168.1.1", "type": "ip", "label": "192.168.1.1"},
        ],
        "edges": [
            {"source": lookup.ip_address, "target": "ns1.example.com", "relationship": "resolves_to"},
            {"source": "ns1.example.com", "target": "192.168.1.1", "relationship": "points_to"},
        ],
    }
    
    return jsonify(_sanitize(graph_data)), 200


@api_v2_bp.route("/target/<path:target>/timeline", methods=["GET"])
@web_login_required
def get_target_timeline(target):
    """Get historical timeline for a target."""
    lookups = LookupHistory.query.filter_by(ip_address=target).order_by(LookupHistory.created_at.desc()).limit(20).all()
    
    timeline = [
        {
            "timestamp": lh.created_at.isoformat(),
            "event": "lookup",
            "source": lh.source,
            "lookup_id": lh.id,
        }
        for lh in lookups
    ]
    
    return jsonify({
        "target": target,
        "timeline": _sanitize(timeline),
    }), 200


@api_v2_bp.route("/lookup/<int:lookup_id>/rules", methods=["GET"])
@web_login_required
def get_detection_rules(lookup_id):
    """Get detection rules that triggered for a lookup."""
    lookup = LookupHistory.query.filter_by(id=lookup_id).first()
    if not lookup:
        return jsonify({"error": "Not Found"}), 404
    
    # Placeholder: Detection rules engine
    rules_data = {
        "target": lookup.ip_address,
        "rules_triggered": [
            {
                "rule_id": "dns_query_rate",
                "name": "High DNS Query Rate",
                "severity": "medium",
                "description": "More than 100 DNS queries per hour",
            },
            {
                "rule_id": "bgp_hijack",
                "name": "BGP Hijack Detection",
                "severity": "critical",
                "description": "BGP route anomaly detected",
            },
        ],
    }
    
    return jsonify(_sanitize(rules_data)), 200


@api_v2_bp.route("/pivot/<path:entity>", methods=["GET"])
@web_login_required
def pivot_entity(entity):
    """Pivot from one entity (IP/domain/email) to related entities."""
    # Placeholder: Pivot logic
    pivot_data = {
        "pivot_from": entity,
        "pivot_type": "domain_to_ips",
        "related_entities": [
            {"entity": "192.168.1.1", "type": "ip", "relationship": "resolves_to"},
            {"entity": "mail.example.com", "type": "domain", "relationship": "mx_record"},
        ],
    }
    
    return jsonify(_sanitize(pivot_data)), 200
