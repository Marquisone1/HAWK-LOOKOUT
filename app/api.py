import logging
from html import escape as _esc

from flask import Blueprint, jsonify, request

from .auth import require_api_key
from .models import LookupHistory, db
from .services import BlacklistService, WhoisFreakService

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

api_bp = Blueprint("api", __name__)
lookup_service = WhoisFreakService()
blacklist_service = BlacklistService()


@api_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"}), 200


@api_bp.route("/blacklist", methods=["GET"])
@require_api_key
def blacklist(user):
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Bad Request", "message": "Missing target parameter"}), 400
    if lookup_service.is_ip(target):
        query_type = "ip"
    elif lookup_service.is_domain(target):
        query_type = "domain"
    else:
        return jsonify({"error": "Bad Request", "message": "Invalid target"}), 400
    result = blacklist_service.check(target, query_type)
    return jsonify(result), 200


@api_bp.route("/lookup", methods=["POST"])
@require_api_key
def lookup(user):
    data = request.get_json()
    if not data:
        return (
            jsonify({"error": "Bad Request", "message": "Request body must be JSON"}),
            400,
        )

    target = (data.get("target") or data.get("ip") or "").strip()
    if not target:
        return (
            jsonify(
                {
                    "error": "Bad Request",
                    "message": "Missing required field: target (IP address or domain)",
                }
            ),
            400,
        )

    if not isinstance(target, str):
        return (
            jsonify({"error": "Bad Request", "message": "Target must be a string"}),
            400,
        )
    
    # Enforce length limits to prevent DoS via regex exhaustion
    if len(target) > 255:
        return (
            jsonify({"error": "Bad Request", "message": "Target exceeds maximum length (255 chars)"}),
            400,
        )
    
    # Only allow alphanumerics, dots, hyphens, and colons (IPv6)
    if not all(c.isalnum() or c in '.-:' for c in target):
        return (
            jsonify({"error": "Bad Request", "message": "Target contains invalid characters"}),
            400,
        )

    result, status_code = lookup_service.lookup(target, user)
    return jsonify(_sanitize(result)), status_code


@api_bp.route("/history", methods=["GET"])
@require_api_key
def history(user):
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)

    # Clamp to safe bounds
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    lookups = (
        LookupHistory.query.filter_by(user_id=user.id)
        .order_by(LookupHistory.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    total_count = LookupHistory.query.filter_by(user_id=user.id).count()

    history_list = [
        {
            "id": entry.id,
            "ip_address": entry.ip_address,
            "result": entry.get_result_dict(),
            "created_at": entry.created_at.isoformat(),
        }
        for entry in lookups
    ]

    return (
        jsonify(
            {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "count": len(history_list),
                "history": history_list,
            }
        ),
        200,
    )


@api_bp.route("/history/<int:entry_id>", methods=["DELETE"])
@require_api_key
def delete_history_entry(user, entry_id):
    entry = LookupHistory.query.filter_by(id=entry_id, user_id=user.id).first()
    if not entry:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"deleted": entry_id}), 200


@api_bp.route("/history", methods=["DELETE"])
@require_api_key
def clear_history(user):
    count = LookupHistory.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return jsonify({"deleted": count}), 200
