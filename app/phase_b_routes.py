"""Phase B API endpoints: Risk intelligence, graphs, timelines, rules."""

from flask import Blueprint, request, jsonify, g
from app.auth import web_login_required, require_api_key
from app.models import LookupHistory, db
from app.risk_scoring import RiskScorer
from app.graph import InfrastructureGraph
from app.timeline import Timeline
from app.detection_rules import DetectionRule, BUILTIN_RULES
from app.services import BlacklistService, GoogleSafeBrowsingService
import time

phase_b_bp = Blueprint("phase_b", __name__, url_prefix="/api/v2")


# ─────────────────────────────────────────────────────────────────────────────
# Risk Scoring
# ─────────────────────────────────────────────────────────────────────────────

@phase_b_bp.route("/lookup/<int:lookup_id>/risk", methods=["GET"])
@require_api_key
def get_risk_score(user, lookup_id):
    """Get explainable risk score for a lookup, incorporating threat feeds."""
    lookup = LookupHistory.query.get(lookup_id)
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = lookup.get_result_dict()
    lookup_type = data.get('type', 'unknown')
    target = lookup.ip_address
    
    # Collect threat feed data
    blacklist_service = BlacklistService()
    safe_browsing_service = GoogleSafeBrowsingService()
    
    # Get blacklist data (DNSBL, ClickFix, URLhaus)
    blacklist_data = blacklist_service.check(target, lookup_type)
    
    # Get Safe Browsing data
    safe_browsing_data = safe_browsing_service.check(target)
    
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


# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure Graph
# ─────────────────────────────────────────────────────────────────────────────

@phase_b_bp.route("/lookup/<int:lookup_id>/graph", methods=["GET"])
@require_api_key
def get_infrastructure_graph(user, lookup_id):
    """Get entity relationship graph."""
    lookup = LookupHistory.query.get(lookup_id)
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    graph = InfrastructureGraph.build_from_lookup(lookup_id)
    
    return jsonify({
        "lookup_id": lookup_id,
        "nodes": [
            {
                "id": f"{node[0]}:{node[1]}",
                "type": graph['nodes'][node]['type'],
                "label": graph['nodes'][node]['value'],
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
        "pivot_targets": [f"{t[0]}:{t[1]}" for t in graph['pivot_targets']],
    }), 200


@phase_b_bp.route("/pivot/<entity_type>/<entity_value>", methods=["GET"])
@require_api_key
def pivot_entity(user, entity_type, entity_value):
    """Find all related lookups for an entity."""
    related = InfrastructureGraph.find_related_lookups(entity_type, entity_value)
    
    return jsonify({
        "entity": f"{entity_type}:{entity_value}",
        "related_lookups": len(related),
        "lookups": [
            {
                "id": lookup.id,
                "target": lookup.ip_address,
                "source": lookup.source,
                "timestamp": lookup.created_at.isoformat(),
            }
            for lookup in related[-50:]  # Last 50
        ],
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Timeline
# ─────────────────────────────────────────────────────────────────────────────

@phase_b_bp.route("/target/<target>/timeline", methods=["GET"])
@require_api_key
def get_target_timeline(user, target):
    """Get history of all scans for a target."""
    lookups = LookupHistory.query.filter_by(ip_address=target).order_by(LookupHistory.created_at).all()
    timeline = Timeline.get_timeline(target, lookups)
    
    return jsonify({
        "target": target,
        "scans": len(timeline),
        "timeline": timeline,
    }), 200


@phase_b_bp.route("/target/<target>/changes", methods=["GET"])
@require_api_key
def get_target_changes(user, target):
    """Get what changed between consecutive scans."""
    lookups = LookupHistory.query.filter_by(ip_address=target).order_by(LookupHistory.created_at).all()
    timeline = Timeline.get_timeline(target, lookups)
    deltas = Timeline.compute_deltas(timeline)
    important = Timeline.highlight_critical_changes(deltas)
    
    return jsonify({
        "target": target,
        "total_scans": len(timeline),
        "total_changes": len(deltas),
        "critical_changes": len(important),
        "changes": important,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Detection Rules
# ─────────────────────────────────────────────────────────────────────────────

@phase_b_bp.route("/rules", methods=["GET"])
@web_login_required
def list_rules():
    """List all detection rules."""
    # TODO: Load from DB, for now return built-ins
    return jsonify({
        "rules": [rule.to_dict() for rule in BUILTIN_RULES],
    }), 200


@phase_b_bp.route("/rules/<int:rule_id>/test", methods=["POST"])
@require_api_key
def test_rule(user, rule_id):
    """Test a rule against a lookup."""
    lookup_id = request.json.get('lookup_id')
    lookup = LookupHistory.query.get(lookup_id)
    
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = lookup.get_result_dict()
    
    # Test built-in rules for now
    rule = next((r for r in BUILTIN_RULES if id(r) == rule_id), None)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    
    matched = rule.evaluate(data.get('data', {}))
    
    return jsonify({
        "rule_id": rule_id,
        "lookup_id": lookup_id,
        "matched": matched,
        "rule": rule.to_dict(),
    }), 200


@phase_b_bp.route("/lookup/<int:lookup_id>/rules", methods=["GET"])
@require_api_key
def evaluate_all_rules(user, lookup_id):
    """Test all rules against a lookup."""
    lookup = LookupHistory.query.get(lookup_id)
    if not lookup:
        return jsonify({"error": "Lookup not found"}), 404
    
    data = lookup.get_result_dict()
    
    matches = []
    for rule in BUILTIN_RULES:
        if rule.enabled and rule.evaluate(data.get('data', {})):
            matches.append(rule.to_dict())
    
    return jsonify({
        "lookup_id": lookup_id,
        "total_rules": len(BUILTIN_RULES),
        "matched_rules": len(matches),
        "matches": matches,
    }), 200
