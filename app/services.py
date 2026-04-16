import html
import json
import logging
import re
import socket
import threading
import time
from datetime import datetime
from ipaddress import AddressValueError, IPv4Address, ip_address

import requests

from .config import Config
from .models import LookupHistory, db

logger = logging.getLogger(__name__)

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class WhoisFreakService:
    """Queries the WhoisFreak API for IP and domain WHOIS data."""

    def __init__(self):
        self.ip_endpoint = Config.WHOISFREAK_IP_ENDPOINT
        self.domain_endpoint = Config.WHOISFREAK_DOMAIN_ENDPOINT
        self.timeout = 15

    def _get_api_key(self) -> str:
        """
        Read WhoisFreak API key from the database (set via Settings page).
        Falls back to the env variable if no DB value is set.
        Never logged or returned to the browser.
        """
        from .models import User  # local import avoids circular deps at module level
        user = User.query.first()
        if user and user.whoisfreak_api_key:
            return user.whoisfreak_api_key
        return Config.WHOISFREAK_API_KEY

    def _extract_rate_limit(self, resp):
        """Extract any rate-limit headers from a WhoisFreak API response."""
        rl = {}
        for k, v in resp.headers.items():
            kl = k.lower()
            if any(x in kl for x in ('ratelimit', 'rate-limit', 'quota', 'request-limit')):
                rl[k] = v
        return rl or None

    # ── Input classification ──────────────────────────────────────────────────

    @staticmethod
    def is_ip(target: str) -> bool:
        try:
            ip_address(target)
            return True
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def is_domain(target: str) -> bool:
        return bool(DOMAIN_RE.match(target))

    # ── Public entry point ────────────────────────────────────────────────────

    def lookup(self, target: str, user, site_user_id=None):
        # Check if user prefers fallback services
        if user.prefer_fallback:
            return self._lookup_fallback(target, user, site_user_id=site_user_id)
        
        # Default: use WhoisFreak API
        if self.is_ip(target):
            return self._lookup_ip(target, user, site_user_id=site_user_id)
        elif self.is_domain(target):
            return self._lookup_domain(target, user, site_user_id=site_user_id)
        else:
            return (
                {
                    "error": "Invalid target",
                    "message": "Enter a valid IP address or domain name",
                },
                400,
            )

    # ── IP WHOIS ──────────────────────────────────────────────────────────────

    def _lookup_ip(self, target: str, user, site_user_id=None):
        logger.info(f"WhoisFreak IP lookup: {target}")
        try:
            api_key = self._get_api_key()
            resp = requests.get(
                self.ip_endpoint,
                params={"apiKey": api_key, "ip": target},
                timeout=self.timeout,
            )
            if resp.status_code == 401:
                return {"error": "Unauthorized", "message": "Invalid WhoisFreak API key"}, 401
            if resp.status_code != 200:
                logger.error(f"WhoisFreak IP error {resp.status_code}: {resp.text[:200]}")
                return {"error": f"WhoisFreak API error (HTTP {resp.status_code})"}, 502

            return self._save_and_return(target, "ip", resp.json(), user, self._extract_rate_limit(resp), site_user_id=site_user_id, source="WhoisFreak")

        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}, 504
        except requests.exceptions.ConnectionError:
            return {"error": "Could not connect to WhoisFreak API"}, 502
        except Exception:
            logger.exception(f"Unexpected error for IP {target}")
            return {"error": "Server error"}, 500

    # ── Domain WHOIS ──────────────────────────────────────────────────────────

    def _lookup_domain(self, target: str, user, site_user_id=None):
        domain = re.sub(r"^www\.", "", target.lower())
        logger.info(f"WhoisFreak domain lookup: {domain}")
        try:
            api_key = self._get_api_key()
            resp = requests.get(
                self.domain_endpoint,
                params={"apiKey": api_key, "whois": "live", "domainName": domain},
                timeout=self.timeout,
            )
            if resp.status_code == 401:
                return {"error": "Unauthorized", "message": "Invalid WhoisFreak API key"}, 401
            if resp.status_code != 200:
                logger.error(f"WhoisFreak domain error {resp.status_code}: {resp.text[:200]}")
                return {"error": f"WhoisFreak API error (HTTP {resp.status_code})"}, 502

            return self._save_and_return(domain, "domain", resp.json(), user, self._extract_rate_limit(resp), site_user_id=site_user_id, source="WhoisFreak")

        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}, 504
        except requests.exceptions.ConnectionError:
            return {"error": "Could not connect to WhoisFreak API"}, 502
        except Exception:
            logger.exception(f"Unexpected error for domain {domain}")
            return {"error": "Server error"}, 500

    # ── Persist and return ────────────────────────────────────────────────────

    def _save_and_return(self, target: str, query_type: str, data: dict, user, rate_limit=None, site_user_id=None, source=None):
        lookup_record = None
        try:
            lookup_record = LookupHistory(
                user_id=user.id,
                site_user_id=site_user_id,
                ip_address=target,
                result=json.dumps(data),
                source=source,  # Track which service was used
            )
            db.session.add(lookup_record)
            db.session.commit()
            logger.info(f"Saved {query_type} lookup for '{target}' from {source} (user {user.id})")
        except Exception as db_err:
            logger.error(f"DB error saving lookup: {db_err}")
            db.session.rollback()

        return (
            {
                "target": html.escape(target, quote=True),
                "type": query_type,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
                "lookup_id": lookup_record.id if lookup_record else None,
                "rate_limit": rate_limit,
                "source": source,  # Include source in response
            },
            200,
        )

    # ── Fallback Services (IP-API + DNS) ──────────────────────────────────────

    def _lookup_fallback(self, target: str, user, site_user_id=None):
        """Use free fallback services: IP-API for IPs, DNS for domains."""
        logger.info(f"Fallback services lookup: {target}")
        
        if self.is_ip(target):
            # Use IP-API for IP lookups
            ip_api_service = IPAPIService()
            data = ip_api_service.lookup(target)
            query_type = "ip"
        elif self.is_domain(target):
            # Use DNS service for domain lookups
            dns_service = DNSService()
            data = dns_service.lookup(target)
            query_type = "domain"
        else:
            return (
                {
                    "error": "Invalid target",
                    "message": "Enter a valid IP address or domain name",
                },
                400,
            )
        
        # Save and return with source tracking
        if self.is_ip(target):
            source = "IP-API"
        else:
            source = "DNS"
        return self._save_and_return(target, query_type, data, user, rate_limit=None, site_user_id=site_user_id, source=source)


class IPAPIService:
    """IP-API.com — Free IP geolocation and threat intel (no key required, 45 req/min)."""
    
    API_URL = "http://ip-api.com/json/"
    
    def __init__(self):
        self.timeout = 5
    
    def lookup(self, ip: str) -> dict:
        """Get comprehensive IP geolocation, ISP, and threat intel from IP-API."""
        try:
            # Request all available fields from IP-API
            resp = requests.get(
                f"{self.API_URL}{ip}",
                params={
                    "fields": "status,continent,country,region,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,vpn,tor,reverse,connection_type,connection_speed"
                },
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        # Location info
                        "location": {
                            "continent": data.get("continent"),
                            "country": data.get("country"),
                            "region": data.get("region"),
                            "city": data.get("city"),
                            "district": data.get("district"),
                            "zip_code": data.get("zip"),
                            "coordinates": {
                                "latitude": data.get("lat"),
                                "longitude": data.get("lon")
                            },
                            "timezone": data.get("timezone"),
                            "timezone_offset": data.get("offset"),
                        },
                        # Network info
                        "network": {
                            "isp": data.get("isp"),
                            "organization": data.get("org"),
                            "asn": data.get("as"),
                            "as_name": data.get("asname"),
                            "connection_type": data.get("connection_type"),
                            "connection_speed": data.get("connection_speed"),
                        },
                        # Financial/currency info
                        "financial": {
                            "currency": data.get("currency"),
                        },
                        # Threat detection
                        "threat_analysis": {
                            "is_mobile": data.get("mobile", False),
                            "is_proxy": data.get("proxy", False),
                            "is_vpn": data.get("vpn", False),
                            "is_tor": data.get("tor", False),
                            "is_hosting": data.get("hosting", False),
                        },
                        # Reverse DNS
                        "reverse_dns": data.get("reverse"),
                    }
            return {"error": "IP lookup failed", "status": data.get("status") if resp.status_code == 200 else f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"IP-API lookup failed for {ip}: {e}")
            return {"error": "Failed to retrieve IP information"}


class DNSService:
    """DNS record lookups — MX, NS, SPF, TXT, A, AAAA, CNAME, CAA, SOA, TLSA records (completely free)."""
    
    def __init__(self):
        try:
            import dns.resolver
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 3
            self.enabled = True
        except ImportError:
            logger.warning("dnspython not installed, DNS lookups disabled")
            self.enabled = False
    
    def lookup(self, domain: str) -> dict:
        """Get comprehensive DNS records for a domain."""
        if not self.enabled:
            return {"error": "dnspython not installed"}
        
        result = {}
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            
            # Clean domain name
            domain = domain.lower().replace('www.', '', 1)
            
            # A Records (IPv4)
            try:
                a_records = resolver.resolve(domain, 'A')
                result['a_records'] = [str(record) for record in a_records]
            except Exception:
                pass
            
            # AAAA Records (IPv6)
            try:
                aaaa_records = resolver.resolve(domain, 'AAAA')
                result['aaaa_records'] = [str(record) for record in aaaa_records]
            except Exception:
                pass
            
            # MX Records (Mail)
            try:
                mx_records = resolver.resolve(domain, 'MX')
                result['mx_records'] = [
                    {
                        "priority": int(record.preference),
                        "exchange": str(record.exchange).rstrip('.')
                    }
                    for record in sorted(mx_records, key=lambda x: x.preference)
                ]
            except Exception:
                pass
            
            # NS Records (Nameservers)
            try:
                ns_records = resolver.resolve(domain, 'NS')
                result['ns_records'] = [str(record).rstrip('.') for record in ns_records]
            except Exception:
                pass
            
            # CNAME Records
            try:
                cname_records = resolver.resolve(domain, 'CNAME')
                result['cname_records'] = [str(record).rstrip('.') for record in cname_records]
            except Exception:
                pass
            
            # SOA Record (Start of Authority)
            try:
                soa_records = resolver.resolve(domain, 'SOA')
                soa = soa_records[0]
                result['soa_record'] = {
                    "mname": str(soa.mname).rstrip('.'),
                    "rname": str(soa.rname).rstrip('.'),
                    "serial": int(soa.serial),
                    "refresh": int(soa.refresh),
                    "retry": int(soa.retry),
                    "expire": int(soa.expire),
                    "minimum": int(soa.minimum),
                }
            except Exception:
                pass
            
            # TXT Records (All text records)
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                all_txt = []
                for record in txt_records:
                    txt_strings = [s.decode() if isinstance(s, bytes) else s for s in record.strings]
                    all_txt.append(''.join(txt_strings))
                result['txt_records'] = all_txt
            except Exception:
                pass
            
            # SPF Record
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                spf = [str(record) for record in txt_records if 'v=spf1' in str(record)]
                if spf:
                    result['spf_record'] = spf[0]
            except Exception:
                pass
            
            # DMARC Record
            try:
                dmarc_records = resolver.resolve(f"_dmarc.{domain}", 'TXT')
                dmarc = [str(record) for record in dmarc_records if 'v=DMARC1' in str(record)]
                if dmarc:
                    result['dmarc_record'] = dmarc[0]
            except Exception:
                pass
            
            # CAA Records (Certificate Authority Authorization)
            try:
                caa_records = resolver.resolve(domain, 'CAA')
                result['caa_records'] = [
                    {
                        "flags": int(record.flags),
                        "tag": record.tag.decode() if isinstance(record.tag, bytes) else record.tag,
                        "value": record.value.decode() if isinstance(record.value, bytes) else record.value
                    }
                    for record in caa_records
                ]
            except Exception:
                pass
            
            # TLSA Records (TLS certificate info)
            try:
                tlsa_records = resolver.resolve(f"_443._tcp.{domain}", 'TLSA')
                result['tlsa_records'] = [
                    {
                        "usage": int(record.usage),
                        "selector": int(record.selector),
                        "mtype": int(record.mtype),
                        "cert_data": record.cert.hex()[:32] + "..."  # First 32 chars of hex
                    }
                    for record in tlsa_records
                ]
            except Exception:
                pass
            
            # Try to get SSL/TLS certificate info
            try:
                ssl_info = self._get_ssl_info(domain)
                if ssl_info:
                    result['ssl_certificate'] = ssl_info
            except Exception:
                pass
            
            # Try to get HTTP headers
            try:
                http_info = self._get_http_headers(domain)
                if http_info:
                    result['http_headers'] = http_info
            except Exception:
                pass
            
            return result
        
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            return {"error": "Failed to retrieve DNS records"}
    
    @staticmethod
    def _get_ssl_info(domain: str) -> dict:
        """Get SSL/TLS certificate information."""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            # Enforce TLSv1.2 or higher — disable older insecure protocols
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return {
                            "subject": dict(x[0] for x in cert.get('subject', [])),
                            "issuer": dict(x[0] for x in cert.get('issuer', [])),
                            "version": cert.get('version'),
                            "serial_number": hex(cert.get('serialNumber', 0)),
                            "not_before": cert.get('notBefore'),
                            "not_after": cert.get('notAfter'),
                            "san": cert.get('subjectAltName', []),
                        }
        except Exception as e:
            logger.debug(f"SSL info retrieval failed for {domain}: {e}")
            # Don't expose exception details to client
        return None
    
    @staticmethod
    def _get_http_headers(domain: str) -> dict:
        """Get HTTP headers and server info."""
        try:
            resp = requests.head(f"https://{domain}", timeout=3, allow_redirects=False)
            headers = {}
            
            # Extract security and useful headers
            interesting_headers = [
                'server', 'x-powered-by', 'x-frame-options', 'x-content-type-options',
                'strict-transport-security', 'content-security-policy', 'x-xss-protection',
                'referrer-policy', 'permissions-policy', 'cache-control', 'etag'
            ]
            
            for header in interesting_headers:
                if header in resp.headers:
                    headers[header] = resp.headers[header]
            
            return {
                "status_code": resp.status_code,
                "headers": headers
            }
        except Exception as e:
            logger.debug(f"HTTP headers retrieval failed for {domain}: {e}")
        return None


class BlacklistService:
    """DNSBL lookups + dynamic ClickFix domain/IP check + URLhaus host query."""

    IP_DNSBLS = [
        ('zen.spamhaus.org', 'Spamhaus ZEN'),
        ('bl.spamcop.net', 'SpamCop'),
        ('dnsbl.sorbs.net', 'SORBS'),
    ]
    DOMAIN_DNSBLS = [
        ('dbl.spamhaus.org', 'Spamhaus DBL'),
        ('multi.surbl.org', 'SURBL'),
    ]
    # NOTE: Pin this URL to a specific commit SHA for production reproducibility.
    # Visit the gist revision history, copy a SHA, and replace /raw/ with /raw/<SHA>/.
    CLICKFIX_URL = (
        'https://gist.githubusercontent.com/cdup07/'
        '9f563dfb78a06fad5db794f33ba93a3f/raw/clickfix_domains.txt'
    )
    _CLICKFIX_MAX_BYTES = 5 * 1024 * 1024   # 5 MB sanity cap
    _CLICKFIX_MAX_ENTRIES = 500_000          # reject implausibly large lists
    _clickfix_cache = None
    _clickfix_ts = 0.0
    _clickfix_ttl = 3600.0  # refresh every hour
    _clickfix_lock = threading.Lock()
    _clickfix_last_error = None
    _clickfix_retries = 2  # total attempts per refresh

    # URLhaus API (abuse.ch)
    URLHAUS_HOST_API = 'https://urlhaus-api.abuse.ch/v1/host/'
    _urlhaus_timeout = 10

    def _get_clickfix_domains(self):
        """Return the cached ClickFix set, refreshing if stale. Retries on failure."""
        with self._clickfix_lock:
            if (
                BlacklistService._clickfix_cache is not None
                and (time.time() - BlacklistService._clickfix_ts) < self._clickfix_ttl
            ):
                return BlacklistService._clickfix_cache

            last_exc = None
            for attempt in range(self._clickfix_retries):
                try:
                    resp = requests.get(self.CLICKFIX_URL, timeout=10)
                    resp.raise_for_status()
                    if len(resp.content) > self._CLICKFIX_MAX_BYTES:
                        raise ValueError(f"ClickFix response too large ({len(resp.content)} bytes)")
                    domains = {
                        line.strip().lower()
                        for line in resp.text.splitlines()
                        if line.strip() and not line.startswith("#")
                    }
                    if len(domains) > self._CLICKFIX_MAX_ENTRIES:
                        raise ValueError(f"ClickFix list suspiciously large ({len(domains)} entries)")
                    BlacklistService._clickfix_cache = domains
                    BlacklistService._clickfix_ts = time.time()
                    BlacklistService._clickfix_last_error = None
                    logger.info(f"ClickFix list refreshed: {len(domains)} entries")
                    return domains
                except Exception as exc:
                    last_exc = exc
                    if attempt < self._clickfix_retries - 1:
                        time.sleep(1)

            BlacklistService._clickfix_last_error = str(last_exc)
            logger.warning(f"Failed to fetch ClickFix list after {self._clickfix_retries} attempts: {last_exc}")
            return BlacklistService._clickfix_cache or set()

    @classmethod
    def feed_status(cls):
        """Return metadata about the threat feed cache."""
        with cls._clickfix_lock:
            cache = cls._clickfix_cache
            ts = cls._clickfix_ts
            return {
                'clickfix': {
                    'cached': cache is not None,
                    'entries': len(cache) if cache else 0,
                    'last_refresh': datetime.utcfromtimestamp(ts).isoformat() if ts else None,
                    'age_seconds': round(time.time() - ts, 1) if ts else None,
                    'stale': (time.time() - ts) > cls._clickfix_ttl if ts else True,
                    'last_error': cls._clickfix_last_error,
                },
                'urlhaus': {
                    'configured': cls._is_urlhaus_configured(),
                },
            }

    @classmethod
    def _is_urlhaus_configured(cls):
        """Check if a URLhaus Auth-Key is configured."""
        try:
            from .models import User
            user = User.query.first()
            return bool(user and user.urlhaus_auth_key)
        except Exception:
            return False

    def _get_urlhaus_auth_key(self):
        """Read URLhaus Auth-Key from the database."""
        from .models import User
        user = User.query.first()
        if user and user.urlhaus_auth_key:
            return user.urlhaus_auth_key
        return None

    def _query_urlhaus_host(self, host: str) -> dict | None:
        """Query URLhaus /v1/host/ API. Returns parsed JSON or None on failure."""
        auth_key = self._get_urlhaus_auth_key()
        if not auth_key:
            return None
        try:
            resp = requests.post(
                self.URLHAUS_HOST_API,
                headers={'Auth-Key': auth_key},
                data={'host': host},
                timeout=self._urlhaus_timeout,
            )
            if resp.status_code != 200:
                logger.warning(f"URLhaus host query failed HTTP {resp.status_code}")
                return None
            data = resp.json()
            if data.get('query_status') not in ('ok', 'no_results'):
                logger.warning(f"URLhaus query_status: {data.get('query_status')}")
                return None
            return data
        except Exception as exc:
            logger.warning(f"URLhaus host query error: {exc}")
            return None

    def _check_dnsbl_ip(self, ip: str, bl_host: str) -> bool:
        try:
            addr = ip_address(ip)
            if isinstance(addr, IPv4Address):
                reversed_ip = '.'.join(reversed(ip.split('.')))
            else:
                expanded = addr.exploded.replace(':', '')
                reversed_ip = '.'.join(reversed(list(expanded)))
            socket.getaddrinfo(f'{reversed_ip}.{bl_host}', None)
            return True
        except (socket.gaierror, OSError, ValueError):
            return False

    def _check_dnsbl_domain(self, domain: str, bl_host: str) -> bool:
        try:
            socket.getaddrinfo(f'{domain}.{bl_host}', None)
            return True
        except (socket.gaierror, OSError):
            return False

    def check(self, target: str, query_type: str) -> dict:
        dnsbl_results = []
        target_lower = target.lower()

        if query_type == 'ip':
            for bl_host, bl_name in self.IP_DNSBLS:
                listed = self._check_dnsbl_ip(target, bl_host)
                dnsbl_results.append({'list': bl_name, 'listed': listed})
        else:
            clean = re.sub(r'^www\.', '', target_lower)
            for bl_host, bl_name in self.DOMAIN_DNSBLS:
                listed = self._check_dnsbl_domain(clean, bl_host)
                dnsbl_results.append({'list': bl_name, 'listed': listed})

        # ClickFix check — covers both domain and IP entries in the list
        cf_domains = self._get_clickfix_domains()
        clean_target = re.sub(r'^www\.', '', target_lower)
        clickfix_hit = (
            target_lower in cf_domains
            or clean_target in cf_domains
            or f'www.{clean_target}' in cf_domains
        )

        # URLhaus host query
        urlhaus_data = self._query_urlhaus_host(clean_target)
        urlhaus_result = {'status': 'not_configured'}
        auth_key = self._get_urlhaus_auth_key()
        if not auth_key:
            urlhaus_result = {'status': 'not_configured'}
        elif urlhaus_data is None:
            urlhaus_result = {'status': 'error'}
        elif urlhaus_data.get('query_status') == 'no_results':
            urlhaus_result = {'status': 'clean'}
        elif urlhaus_data.get('query_status') == 'ok':
            urls_list = urlhaus_data.get('urls') or []
            urlhaus_result = {
                'status': 'found',
                'host': urlhaus_data.get('host'),
                'url_count': int(urlhaus_data.get('url_count', 0)),
                'firstseen': urlhaus_data.get('firstseen'),
                'blacklists': urlhaus_data.get('blacklists'),
                'urlhaus_reference': urlhaus_data.get('urlhaus_reference'),
                'urls_online': sum(1 for u in urls_list if u.get('url_status') == 'online'),
                'urls_offline': sum(1 for u in urls_list if u.get('url_status') == 'offline'),
                'tags': list({tag for u in urls_list for tag in (u.get('tags') or [])}),
                'recent_urls': [
                    {
                        'url': u.get('url'),
                        'status': u.get('url_status'),
                        'date_added': u.get('date_added'),
                        'threat': u.get('threat'),
                        'tags': u.get('tags'),
                    }
                    for u in urls_list[:5]
                ],
            }
        else:
            urlhaus_result = {'status': 'error'}

        return {
            'target': target,
            'type': query_type,
            'dnsbl': dnsbl_results,
            'clickfix': clickfix_hit,
            'urlhaus': urlhaus_result,
        }
