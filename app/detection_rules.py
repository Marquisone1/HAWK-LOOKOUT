"""Detection rules engine for custom pattern matching."""

from enum import Enum
from typing import List, Dict, Callable
from datetime import datetime


class RuleCondition(Enum):
    """Condition operators."""
    EQUALS = "equals"
    CONTAINS = "contains"
    REGEX = "regex"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    IN_LIST = "in_list"


class DetectionRule:
    """Custom rule for flagging targets."""
    
    def __init__(self, name: str, description: str, conditions: List[Dict], severity: str, enabled: bool = True):
        self.id = None  # Set by DB
        self.name = name
        self.description = description
        self.conditions = conditions  # [{'field': 'path.to.field', 'condition': 'contains', 'value': 'pattern'}]
        self.severity = severity  # 'critical', 'high', 'medium', 'low'
        self.enabled = enabled
        self.created_at = datetime.utcnow()
        self.matches = 0
        self.last_match = None
    
    def evaluate(self, result_data: dict) -> bool:
        """Check if data matches all conditions (AND logic)."""
        for condition in self.conditions:
            if not self._evaluate_condition(result_data, condition):
                return False
        return True
    
    @staticmethod
    def _evaluate_condition(data: dict, condition: Dict) -> bool:
        """Evaluate single condition."""
        field = condition.get('field')
        op = condition.get('condition')
        value = condition.get('value')
        
        # Navigate nested field path
        field_value = DetectionRule._get_nested(data, field)
        if field_value is None:
            return False
        
        field_value_str = str(field_value).lower()
        value_str = str(value).lower()
        
        if op == RuleCondition.EQUALS.value:
            return field_value_str == value_str
        elif op == RuleCondition.CONTAINS.value:
            return value_str in field_value_str
        elif op == RuleCondition.GREATER_THAN.value:
            try:
                return float(field_value) > float(value)
            except (ValueError, TypeError):
                return False
        elif op == RuleCondition.LESS_THAN.value:
            try:
                return float(field_value) < float(value)
            except (ValueError, TypeError):
                return False
        elif op == RuleCondition.IN_LIST.value:
            values = value.split(',') if isinstance(value, str) else value
            return any(v.strip().lower() in field_value_str for v in values)
        
        return False
    
    @staticmethod
    def _get_nested(obj: dict, path: str):
        """Navigate nested dict path: 'data.location.country'."""
        parts = path.split('.')
        current = obj
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
    
    def to_dict(self) -> dict:
        """Serialize rule."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'conditions': self.conditions,
            'severity': self.severity,
            'enabled': self.enabled,
            'matches': self.matches,
            'last_match': self.last_match.isoformat() if self.last_match else None,
        }


# Built-in rules
BUILTIN_RULES = [
    DetectionRule(
        name="New Phishing Domain",
        description="Domain < 7 days old with suspicious TLD",
        conditions=[
            {'field': 'data.age_days', 'condition': 'lt', 'value': '7'},
            {'field': 'data.domain_name', 'condition': 'regex', 'value': r'\.(xyz|top|club|tk|ga|ml)$'},
        ],
        severity='critical',
    ),
    
    DetectionRule(
        name="Tor Exit Node",
        description="IP detected as Tor exit node",
        conditions=[
            {'field': 'data.threat_analysis.is_tor', 'condition': 'equals', 'value': 'true'},
        ],
        severity='critical',
    ),
    
    DetectionRule(
        name="Hosting on Major Cloud",
        description="IP from AWS/Azure/GCP/DigitalOcean",
        conditions=[
            {'field': 'data.network.organization', 'condition': 'in_list', 'value': 'amazon,aws,google,gcp,microsoft,azure,digitalocean'},
        ],
        severity='high',
    ),
    
    DetectionRule(
        name="Privacy-Protected Domain",
        description="WHOIS registrant identity hidden",
        conditions=[
            {'field': 'data.registrant_contact.name', 'condition': 'in_list', 'value': 'redacted,whoisguard,privacy,protected'},
        ],
        severity='medium',
    ),
    
    DetectionRule(
        name="Proxy/VPN Detected",
        description="Traffic routing through proxy or VPN",
        conditions=[
            {'field': 'data.threat_analysis.is_proxy', 'condition': 'equals', 'value': 'true'},
        ],
        severity='high',
    ),
]
