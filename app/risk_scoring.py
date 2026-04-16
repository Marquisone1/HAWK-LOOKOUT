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
    def score_domain(domain_data: dict, blacklist_data: dict = None, safe_browsing_data: dict = None, historical_data: dict = None) -> Tuple[float, List[RiskSignal]]:
        """
        Score domain lookup result, incorporating threat feeds.
        
        Args:
            domain_data: WHOIS lookup result
            blacklist_data: Results from BlacklistService.check()
            safe_browsing_data: Results from GoogleSafeBrowsingService.check()
            historical_data: Historical context
        
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
        
        # ──────────────────────────────────────────────────────────────────
        # THREAT FEED ANALYSIS
        # ──────────────────────────────────────────────────────────────────
        
        # Spamhaus DBL blacklist check (domain-based)
        if blacklist_data:
            dnsbl_data = blacklist_data.get('dnsbl', [])
            for bl_entry in dnsbl_data:
                if bl_entry.get('listed'):
                    signals.append(RiskSignal(
                        RiskLevel.CRITICAL, 'reputation', f'🚫 {bl_entry.get("list", "DNSBL")}',
                        f'Domain listed in {bl_entry.get("list")} — likely spam/malware', 3.0
                    ))
            
            # ClickFix threat feed check
            if blacklist_data.get('clickfix'):
                signals.append(RiskSignal(
                    RiskLevel.CRITICAL, 'reputation', '🔴 ClickFix Threat Feed',
                    'Domain flagged as known threat by ClickFix — Active malicious campaign', 3.5
                ))
            
            # URLhaus malware hosting check
            urlhaus = blacklist_data.get('urlhaus', {})
            if urlhaus.get('status') == 'found':
                url_count = urlhaus.get('url_count', 0)
                tags = urlhaus.get('tags', [])
                tag_str = ', '.join(tags) if tags else 'malware distribution'
                signals.append(RiskSignal(
                    RiskLevel.CRITICAL, 'reputation', f'⚠️ URLhaus (Malware Host)',
                    f'Hosting {url_count} malicious URLs ({tag_str})', 3.5
                ))
        
        # Google Safe Browsing check
        if safe_browsing_data:
            threat_types = safe_browsing_data.get('threats', [])
            if threat_types:
                # Map threat types to risk levels
                threat_map = {
                    'MALWARE': (RiskLevel.CRITICAL, 'Contains malware', 3.0),
                    'SOCIAL_ENGINEERING': (RiskLevel.CRITICAL, 'Phishing/social engineering site', 2.8),
                    'UNWANTED_SOFTWARE': (RiskLevel.HIGH, 'Distributes unwanted software (PUP/adware)', 2.0),
                    'POTENTIALLY_HARMFUL_APPLICATION': (RiskLevel.HIGH, 'Hosts potentially harmful apps', 1.8),
                }
                
                for threat in threat_types:
                    if threat in threat_map:
                        level, detail, weight = threat_map[threat]
                        signals.append(RiskSignal(
                            level, 'reputation', f'🦠 Google Safe Browsing: {threat}',
                            detail, weight
                        ))
        
        score = RiskScorer._compute_score(signals)
        return score, signals
    
    @staticmethod
    def score_ip(ip_data: dict, blacklist_data: dict = None, safe_browsing_data: dict = None, historical_data: dict = None) -> Tuple[float, List[RiskSignal]]:
        """
        Score IP lookup result, incorporating threat feeds.
        
        Args:
            ip_data: IP lookup result
            blacklist_data: Results from BlacklistService.check()
            safe_browsing_data: Results from GoogleSafeBrowsingService.check()
            historical_data: Historical context
        
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
        
        # ──────────────────────────────────────────────────────────────────
        # THREAT FEED ANALYSIS
        # ──────────────────────────────────────────────────────────────────
        
        # Spamhaus ZEN blacklist check (IP-based)
        if blacklist_data:
            dnsbl_data = blacklist_data.get('dnsbl', [])
            for bl_entry in dnsbl_data:
                if bl_entry.get('listed'):
                    signals.append(RiskSignal(
                        RiskLevel.CRITICAL, 'reputation', f'🚫 {bl_entry.get("list", "DNSBL")}',
                        f'IP listed in {bl_entry.get("list")} — spam/botnet indicator', 3.0
                    ))
            
            # ClickFix threat feed check
            if blacklist_data.get('clickfix'):
                signals.append(RiskSignal(
                    RiskLevel.CRITICAL, 'reputation', '🔴 ClickFix Threat Feed',
                    'IP flagged as known threat by ClickFix', 2.5
                ))
            
            # URLhaus malware hosting check
            urlhaus = blacklist_data.get('urlhaus', {})
            if urlhaus.get('status') == 'found':
                url_count = urlhaus.get('url_count', 0)
                tags = urlhaus.get('tags', [])
                tag_str = ', '.join(tags) if tags else 'malware distribution'
                signals.append(RiskSignal(
                    RiskLevel.CRITICAL, 'reputation', f'⚠️ URLhaus (Malware Host)',
                    f'Hosting {url_count} malicious URLs ({tag_str})', 3.5
                ))
        
        # Google Safe Browsing check
        if safe_browsing_data:
            threat_types = safe_browsing_data.get('threats', [])
            if threat_types:
                threat_map = {
                    'MALWARE': (RiskLevel.CRITICAL, 'Serves malware', 3.0),
                    'SOCIAL_ENGINEERING': (RiskLevel.CRITICAL, 'Phishing/social engineering hosting', 2.8),
                    'UNWANTED_SOFTWARE': (RiskLevel.HIGH, 'Distributes unwanted software (PUP/adware)', 2.0),
                    'POTENTIALLY_HARMFUL_APPLICATION': (RiskLevel.HIGH, 'Hosts potentially harmful apps', 1.8),
                }
                
                for threat in threat_types:
                    if threat in threat_map:
                        level, detail, weight = threat_map[threat]
                        signals.append(RiskSignal(
                            level, 'reputation', f'🦠 Google Safe Browsing: {threat}',
                            detail, weight
                        ))
        
        score = RiskScorer._compute_score(signals)
        return score, signals
    
    @staticmethod
    def _compute_score(signals: List[RiskSignal]) -> float:
        """
        Compute final risk score 0-100 using component-based scoring.
        
        Each threat category contributes a specific maximum score:
        - ClickFix Threat Feed: +80 points
        - Google Safe Browsing (Malware/Phishing): +70 points
        - URLhaus Malware Host: +65 points
        - Spamhaus/DNSBL: +60 points
        - Tor Exit Node: +55 points
        - Hosting/Cloud (abused): +40 points
        - New Domain (<7 days): +35 points
        - Suspicious TLD: +20 points
        - VPN/Proxy: +15 points
        
        Multiple threats accumulate, total capped at 100.
        """
        if not signals:
            return 0.0
        
        # Component scoring system - each threat type max contribution
        component_scores = {}
        
        # 1. ClickFix threat feed (highest priority) — 80 max
        if any('ClickFix' in sig.label for sig in signals):
            component_scores['clickfix'] = 80.0
        
        # 2. Google Safe Browsing threats — 70 max
        gsb_score = 0.0
        for sig in signals:
            if 'Google Safe Browsing' in sig.label:
                if 'MALWARE' in sig.label:
                    gsb_score = 70.0  # Malware highest
                elif 'SOCIAL_ENGINEERING' in sig.label or 'Phishing' in sig.label:
                    gsb_score = max(gsb_score, 65.0)
                elif 'UNWANTED_SOFTWARE' in sig.label:
                    gsb_score = max(gsb_score, 50.0)
        if gsb_score > 0:
            component_scores['safe_browsing'] = gsb_score
        
        # 3. URLhaus malware hosting — 65 max
        if any('URLhaus' in sig.label for sig in signals):
            component_scores['urlhaus'] = 65.0
        
        # 4. Spamhaus/DNSBL — 60 max
        if any('DNSBL' in sig.label or 'Spamhaus' in sig.label or 'SpamCop' in sig.label or 'SORBS' in sig.label 
               for sig in signals):
            component_scores['dnsbl'] = 60.0
        
        # 5. Tor exit node — 55 max
        if any('TOR' in sig.label for sig in signals):
            component_scores['tor'] = 55.0
        
        # 6. Hosting/Cloud provider abuse — 40 max (only if explicitly flagged as risky)
        if any(any(token in sig.label for token in ['HOSTING', 'MAJOR CLOUD', 'CLOUD PROVIDER']) for sig in signals):
            component_scores['hosting'] = 40.0
        
        # 7. Brand new domain (<7 days) — 35 max
        if any('BRAND NEW' in sig.label for sig in signals):
            component_scores['new_domain'] = 35.0
        elif any('NEWLY REGISTERED' in sig.label for sig in signals):
            component_scores['newly_registered'] = 20.0
        
        # 8. Suspicious TLD — 20 max
        if any('SUSPICIOUS TLD' in sig.label for sig in signals):
            component_scores['suspicious_tld'] = 20.0
        
        # 9. VPN/Proxy — 15 max
        proxy_score = 0.0
        if any('PROXY' in sig.label for sig in signals):
            proxy_score = max(proxy_score, 15.0)
        if any('VPN' in sig.label for sig in signals):
            proxy_score = max(proxy_score, 10.0)
        if proxy_score > 0:
            component_scores['vpn_proxy'] = proxy_score
        
        # 10. Expiring soon — 10 max
        if any('EXPIRING SOON' in sig.label for sig in signals):
            component_scores['expiring'] = 10.0
        
        # Sum all components and cap at 100
        total_score = sum(component_scores.values())
        final_score = min(100.0, total_score)
        
        return round(final_score, 1)
    
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
