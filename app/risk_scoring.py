"""Risk scoring engine with explainable signals."""

from enum import Enum
from datetime import datetime, timedelta
from typing import List, Dict, Tuple


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskSignal:
    """Individual risk indicator with reasoning."""
    
    def __init__(self, level: RiskLevel, category: str, label: str, detail: str, weight: float = 1.0):
        self.level = level
        self.category = category  # 'age', 'infrastructure', 'reputation', 'behavior'
        self.label = label
        self.detail = detail
        self.weight = weight
        self.timestamp = datetime.utcnow()


class RiskScorer:
    """Compute exploitable risk score from lookup data."""
    
    # Signal weights by level
    LEVEL_WEIGHT = {
        RiskLevel.CRITICAL: 4.0,
        RiskLevel.HIGH: 2.0,
        RiskLevel.MEDIUM: 1.0,
        RiskLevel.LOW: 0.2,
        RiskLevel.INFO: 0.05,
    }
    
    SUSPICIOUS_TLDS = {
        'xyz', 'top', 'club', 'work', 'tk', 'ml', 'ga', 'cf', 'gq',
        'buzz', 'icu', 'live', 'online', 'site', 'fun', 'click', 'loan',
        'win', 'racing', 'download', 'stream', 'cyou', 'cfd', 'vip', 'world', 'store'
    }
    
    HOSTING_ASNS = {
        'amazon', 'aws', 'google', 'gcp', 'microsoft', 'azure', 'digitalocean',
        'vultr', 'hetzner', 'ovh', 'linode', 'akamai', 'cloudflare', 'contabo'
    }
    
    @staticmethod
    def score_domain(domain_data: dict, historical_data: dict = None) -> Tuple[float, List[RiskSignal]]:
        """
        Score domain lookup result.
        
        Returns:
            (score 0-100, [RiskSignal list])
        """
        signals = []
        
        d = domain_data.get('data', {})
        created = d.get('create_date') or d.get('createdDate')
        expiry = d.get('expiry_date') or d.get('expiresDate')
        
        # Age signals
        if created:
            age_days = (datetime.utcnow() - datetime.fromisoformat(str(created).split('T')[0])).days
            
            if age_days < 7:
                signals.append(RiskSignal(
                    RiskLevel.CRITICAL, 'age', 'BRAND NEW',
                    f'{age_days} days old — high phishing/typosquatting risk', 2.0
                ))
            elif age_days < 30:
                signals.append(RiskSignal(
                    RiskLevel.HIGH, 'age', 'NEWLY REGISTERED',
                    f'{age_days} days old — exercise caution', 1.5
                ))
            elif age_days > 1825:
                signals.append(RiskSignal(
                    RiskLevel.LOW, 'age', 'ESTABLISHED',
                    f'Registered {age_days // 365} years ago', 0.1
                ))
        
        # TLD signals
        domain_name = d.get('domain_name', domain_data.get('target', '')).lower()
        tld = domain_name.split('.')[-1] if '.' in domain_name else ''
        if tld in RiskScorer.SUSPICIOUS_TLDS:
            signals.append(RiskSignal(
                RiskLevel.HIGH, 'infrastructure', f'SUSPICIOUS TLD (.{tld})',
                'Commonly abused for phishing/malware', 1.2
            ))
        
        # WHOIS privacy
        registrant = d.get('registrant_contact', {})
        registrant_name = (registrant.get('name', '') + ' ' + registrant.get('company', '')).lower()
        privacy_keywords = ['redacted', 'whoisguard', 'privacy', 'protected', 'private', 'identity', 'withheld']
        if any(k in registrant_name for k in privacy_keywords):
            signals.append(RiskSignal(
                RiskLevel.INFO, 'infrastructure', 'PRIVACY-PROTECTED WHOIS',
                'Registrant identity hidden', 0.05
            ))
        
        # Expiry soon
        if expiry:
            days_until = (datetime.fromisoformat(str(expiry).split('T')[0]) - datetime.utcnow()).days
            if 0 < days_until < 30:
                signals.append(RiskSignal(
                    RiskLevel.MEDIUM, 'behavior', 'EXPIRING SOON',
                    f'Expires in {days_until} days', 0.8
                ))
        
        score = RiskScorer._compute_score(signals)
        return score, signals
    
    @staticmethod
    def score_ip(ip_data: dict, historical_data: dict = None) -> Tuple[float, List[RiskSignal]]:
        """
        Score IP lookup result.
        
        Returns:
            (score 0-100, [RiskSignal list])
        """
        signals = []
        
        d = ip_data.get('data', {})
        source = ip_data.get('source', 'Unknown')
        
        # IP-API threat signals
        if source == "IP-API":
            threat = d.get('threat_analysis', {})
            location = d.get('location', {})
            network = d.get('network', {})
            
            if threat.get('is_proxy'):
                signals.append(RiskSignal(RiskLevel.HIGH, 'behavior', 'PROXY', 'Traffic anonymized', 1.5))
            if threat.get('is_vpn'):
                signals.append(RiskSignal(RiskLevel.MEDIUM, 'behavior', 'VPN', 'Likely consumer VPN', 0.8))
            if threat.get('is_tor'):
                signals.append(RiskSignal(RiskLevel.CRITICAL, 'behavior', 'TOR NODE', 'Tor exit node detected', 3.0))
            if threat.get('is_hosting'):
                org_name = network.get('organization', '').lower()
                is_major_cloud = any(k in org_name for k in RiskScorer.HOSTING_ASNS)
                level = RiskLevel.HIGH if is_major_cloud else RiskLevel.MEDIUM
                signals.append(RiskSignal(
                    level, 'infrastructure', 'HOSTING/CLOUD',
                    f'{network.get("organization", "Unknown")} — common for C2/malware',
                    1.5 if is_major_cloud else 0.8
                ))
        
        # WhoisFreak IP signals
        else:
            org = d.get('organization', {})
            org_name = org.get('name', '').lower()
            
            is_major_cloud = any(k in org_name for k in RiskScorer.HOSTING_ASNS)
            if is_major_cloud:
                signals.append(RiskSignal(
                    RiskLevel.HIGH, 'infrastructure', 'MAJOR CLOUD PROVIDER',
                    f'{org.get("name")} — commonly abused for attacks',
                    1.5
                ))
            else:
                signals.append(RiskSignal(
                    RiskLevel.LOW, 'infrastructure', 'NON-CLOUD ISP',
                    f'Registered to {org.get("name", "Unknown")}',
                    0.1
                ))
        
        score = RiskScorer._compute_score(signals)
        return score, signals
    
    @staticmethod
    def _compute_score(signals: List[RiskSignal]) -> float:
        """
        Compute final risk score 0-100.
        
        Uses weighted sum normalized to 0-100 scale.
        """
        if not signals:
            return 0.0
        
        total_weight = sum(
            RiskScorer.LEVEL_WEIGHT[sig.level] * sig.weight
            for sig in signals
        )
        
        # Normalize: highest possible is all critical signals
        max_possible = sum(RiskScorer.LEVEL_WEIGHT.values()) * 10  # Arbitrary high ceiling
        score = min(100.0, (total_weight / max_possible) * 100)
        
        return round(score, 1)
    
    @staticmethod
    def get_overall_level(score: float) -> RiskLevel:
        """Map score to overall risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
