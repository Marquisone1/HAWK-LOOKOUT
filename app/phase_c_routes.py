"""Phase C API endpoints: Cases, notes, snapshots, exports."""

from flask import Blueprint, request, jsonify, send_file
from app.auth import web_login_required, require_api_key
from app.models import LookupHistory, LookupCase, LookupNote, LookupSnapshot, db, SiteUser
from datetime import datetime
import json
import csv
from io import BytesIO, StringIO

phase_c_bp = Blueprint("phase_c", __name__, url_prefix="/api/v2")


# ─────────────────────────────────────────────────────────────────────────────
# Cases
# ─────────────────────────────────────────────────────────────────────────────

@phase_c_bp.route("/cases", methods=["GET"])
@web_login_required
def list_cases():
    """List all cases for user."""
    user_id = request.args.get('user_id', type=int)
    cases = LookupCase.query.filter_by(site_user_id=user_id).order_by(LookupCase.created_at.desc()).all()
    
    return jsonify({
        "cases": [
            {
                "id": case.id,
                "case_id": case.case_id,
                "title": case.title,
                "status": case.status,
                "severity": case.severity,
                "lookup_count": len(case.lookups),
                "created_at": case.created_at.isoformat(),
                "updated_at": case.updated_at.isoformat(),
            }
            for case in cases
        ],
    }), 200


@phase_c_bp.route("/cases", methods=["POST"])
@web_login_required
def create_case():
    """Create a new case."""
    data = request.json
    
    user = SiteUser.query.filter_by(username=request.form.get('username')).first()
    
    # Generate case ID
    last_case = LookupCase.query.order_by(LookupCase.id.desc()).first()
    case_num = (last_case.id + 1) if last_case else 1
    case_id = f"CASE-{datetime.utcnow().year}-{case_num:03d}"
    
    case = LookupCase(
        user_id=1,  # API user (stub)
        site_user_id=user.id if user else None,
        case_id=case_id,
        title=data.get('title'),
        description=data.get('description'),
        severity=data.get('severity', 'medium'),
    )
    
    db.session.add(case)
    db.session.commit()
    
    return jsonify({
        "id": case.id,
        "case_id": case.case_id,
        "title": case.title,
    }), 201


@phase_c_bp.route("/cases/<int:case_id>/add-lookup", methods=["POST"])
@web_login_required
def add_lookup_to_case(case_id):
    """Add a lookup to a case."""
    case = LookupCase.query.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    
    lookup_id = request.json.get('lookup_id')
    lookup = LookupHistory.query.get(lookup_id)
    
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    lookup.case_id = case_id
    db.session.commit()
    
    return jsonify({"message": "Lookup added to case"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Notes
# ─────────────────────────────────────────────────────────────────────────────

@phase_c_bp.route("/lookup/<int:lookup_id>/notes", methods=["GET"])
@web_login_required
def get_lookup_notes(lookup_id):
    """Get all notes for a lookup."""
    notes = LookupNote.query.filter_by(lookup_id=lookup_id).order_by(LookupNote.created_at.desc()).all()
    
    return jsonify({
        "lookup_id": lookup_id,
        "notes": [
            {
                "id": note.id,
                "content": note.content,
                "tags": note.tags.split(',') if note.tags else [],
                "verdict": note.verdict,
                "author_id": note.site_user_id,
                "created_at": note.created_at.isoformat(),
            }
            for note in notes
        ],
    }), 200


@phase_c_bp.route("/lookup/<int:lookup_id>/notes", methods=["POST"])
@web_login_required
def create_lookup_note(lookup_id):
    """Create a note on a lookup."""
    lookup = LookupHistory.query.get(lookup_id)
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = request.json
    user = SiteUser.query.filter_by(username=request.form.get('username')).first()
    
    note = LookupNote(
        lookup_id=lookup_id,
        site_user_id=user.id if user else 1,
        content=data.get('content'),
        tags=','.join(data.get('tags', [])),
        verdict=data.get('verdict'),
    )
    
    db.session.add(note)
    db.session.commit()
    
    return jsonify({"id": note.id, "created_at": note.created_at.isoformat()}), 201


# ─────────────────────────────────────────────────────────────────────────────
# Snapshots (Evidence)
# ─────────────────────────────────────────────────────────────────────────────

@phase_c_bp.route("/lookup/<int:lookup_id>/snapshot", methods=["POST"])
@web_login_required
def create_snapshot(lookup_id):
    """Create immutable evidence snapshot."""
    lookup = LookupHistory.query.get(lookup_id)
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = request.json
    
    snapshot = LookupSnapshot(
        lookup_id=lookup_id,
        case_id=data.get('case_id'),
        data_json=lookup.result,
        reason=data.get('reason', 'evidence_preservation'),
    )
    
    db.session.add(snapshot)
    db.session.commit()
    
    return jsonify({
        "id": snapshot.id,
        "lookup_id": lookup_id,
        "created_at": snapshot.created_at.isoformat(),
    }), 201


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

@phase_c_bp.route("/lookup/<int:lookup_id>/export/json", methods=["GET"])
@require_api_key
def export_lookup_json(user, lookup_id):
    """Export lookup as JSON."""
    lookup = LookupHistory.query.get(lookup_id)
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = lookup.get_result_dict()
    
    # Add metadata
    data['export_metadata'] = {
        'lookup_id': lookup_id,
        'exported_at': datetime.utcnow().isoformat(),
        'lookup_created_at': lookup.created_at.isoformat(),
        'source': lookup.source,
    }
    
    return jsonify(data), 200


@phase_c_bp.route("/case/<int:case_id>/export/json", methods=["GET"])
@web_login_required
def export_case_json(case_id):
    """Export entire case as JSON."""
    case = LookupCase.query.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    
    export = {
        "case": {
            "id": case.id,
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "created_at": case.created_at.isoformat(),
        },
        "lookups": [
            {
                "id": lookup.id,
                "target": lookup.ip_address,
                "source": lookup.source,
                "data": lookup.get_result_dict(),
            }
            for lookup in case.lookups
        ],
        "notes": [
            {
                "lookup_id": note.lookup_id,
                "content": note.content,
                "verdict": note.verdict,
                "created_at": note.created_at.isoformat(),
            }
            for note in case.notes
        ],
        "exported_at": datetime.utcnow().isoformat(),
    }
    
    return jsonify(export), 200


@phase_c_bp.route("/case/<int:case_id>/export/csv", methods=["GET"])
@web_login_required
def export_case_csv(case_id):
    """Export case lookups as CSV."""
    case = LookupCase.query.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Lookup ID', 'Target', 'Type', 'Source', 'Created At', 'Verdict'])
    
    for lookup in case.lookups:
        verdict = lookup.notes[0].verdict if lookup.notes else ''
        data = lookup.get_result_dict()
        writer.writerow([
            lookup.id,
            lookup.ip_address,
            data.get('type', 'unknown'),
            lookup.source or 'Unknown',
            lookup.created_at.isoformat(),
            verdict,
        ])
    
    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'case-{case.case_id}.csv'
    )
