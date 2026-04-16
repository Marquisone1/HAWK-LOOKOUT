"""Timeline intelligence for tracking target changes over time."""

from app.models import db, LookupHistory
from datetime import datetime
from typing import Dict, List
import json


class TimelineSnapshot:
    """Immutable snapshot of target state at a point in time."""
    
    def __init__(self, lookup_id: int, target: str, lookup_type: str, data: dict, source: str):
        self.lookup_id = lookup_id
        self.target = target
        self.lookup_type = lookup_type  # 'ip' or 'domain'
        self.data = data
        self.source = source
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> dict:
        return {
            'lookup_id': self.lookup_id,
            'target': self.target,
            'type': self.lookup_type,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
        }


class Timeline:
    """Build timeline of target history."""
    
    @staticmethod
    def get_timeline(target: str, lookups: List[LookupHistory] = None) -> List[Dict]:
        """Get all snapshots for a target, ordered by time."""
        if not lookups:
            lookups = LookupHistory.query.filter_by(ip_address=target).order_by(LookupHistory.created_at).all()
        
        timeline = []
        for lookup in lookups:
            data = lookup.get_result_dict()
            snapshot = {
                'lookup_id': lookup.id,
                'timestamp': lookup.created_at.isoformat(),
                'source': lookup.source or 'Unknown',
                'data': data.get('data', {}),
            }
            timeline.append(snapshot)
        
        return timeline
    
    @staticmethod
    def compute_deltas(timeline: List[Dict]) -> List[Dict]:
        """Compute what changed between consecutive scans."""
        deltas = []
        
        for i in range(1, len(timeline)):
            prev = timeline[i-1]
            curr = timeline[i]
            
            delta = {
                'from_timestamp': prev['timestamp'],
                'to_timestamp': curr['timestamp'],
                'changes': Timeline._diff_dicts(prev['data'], curr['data']),
            }
            deltas.append(delta)
        
        return deltas
    
    @staticmethod
    def _diff_dicts(old: dict, new: dict) -> Dict[str, Dict]:
        """Deep diff two objects (returns added, modified, removed keys)."""
        changes = {
            'added': {},
            'modified': {},
            'removed': {},
        }
        
        all_keys = set(list(old.keys()) + list(new.keys()))
        
        for key in all_keys:
            old_val = old.get(key)
            new_val = new.get(key)
            
            if old_val is None and new_val is not None:
                changes['added'][key] = new_val
            elif old_val is not None and new_val is None:
                changes['removed'][key] = old_val
            elif old_val != new_val:
                changes['modified'][key] = {'from': old_val, 'to': new_val}
        
        return changes
    
    @staticmethod
    def highlight_critical_changes(deltas: List[Dict]) -> List[Dict]:
        """Flag important changes: DNS, ASN, cert issuer, blacklist status."""
        CRITICAL_FIELDS = {
            'ns_records', 'a_records', 'aaaa_records', 'mx_records',
            'organization', 'asn', 'ssl_certificate', 'country',
            'blacklist_status', 'threat_tags',
        }
        
        important = []
        for delta in deltas:
            changes = delta['changes']
            
            # Check if any critical field changed
            all_changed = set(
                list(changes['added'].keys()) +
                list(changes['modified'].keys()) +
                list(changes['removed'].keys())
            )
            
            critical_hits = all_changed & CRITICAL_FIELDS
            if critical_hits:
                delta['critical_changes'] = list(critical_hits)
                important.append(delta)
        
        return important
