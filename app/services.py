import json
import logging
import re
from datetime import datetime
from ipaddress import AddressValueError, ip_address

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

    def lookup(self, target: str, user):
        if self.is_ip(target):
            return self._lookup_ip(target, user)
        elif self.is_domain(target):
            return self._lookup_domain(target, user)
        else:
            return (
                {
                    "error": "Invalid target",
                    "message": "Enter a valid IP address or domain name",
                },
                400,
            )

    # ── IP WHOIS ──────────────────────────────────────────────────────────────

    def _lookup_ip(self, target: str, user):
        logger.info(f"WhoisFreak IP lookup: {target}")
        try:
            resp = requests.get(
                self.ip_endpoint,
                params={"apiKey": self._get_api_key(), "ip": target},
                timeout=self.timeout,
            )
            if resp.status_code == 401:
                return {"error": "Unauthorized", "message": "Invalid WhoisFreak API key"}, 401
            if resp.status_code != 200:
                logger.error(f"WhoisFreak IP error {resp.status_code}: {resp.text[:200]}")
                return {"error": f"WhoisFreak API error (HTTP {resp.status_code})"}, 502

            return self._save_and_return(target, "ip", resp.json(), user)

        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}, 504
        except requests.exceptions.ConnectionError:
            return {"error": "Could not connect to WhoisFreak API"}, 502
        except Exception:
            logger.exception(f"Unexpected error for IP {target}")
            return {"error": "Server error"}, 500

    # ── Domain WHOIS ──────────────────────────────────────────────────────────

    def _lookup_domain(self, target: str, user):
        domain = re.sub(r"^www\.", "", target.lower())
        logger.info(f"WhoisFreak domain lookup: {domain}")
        try:
            resp = requests.get(
                self.domain_endpoint,
                params={"apiKey": self._get_api_key(), "whois": "live", "domainName": domain},
                timeout=self.timeout,
            )
            if resp.status_code == 401:
                return {"error": "Unauthorized", "message": "Invalid WhoisFreak API key"}, 401
            if resp.status_code != 200:
                logger.error(f"WhoisFreak domain error {resp.status_code}: {resp.text[:200]}")
                return {"error": f"WhoisFreak API error (HTTP {resp.status_code})"}, 502

            return self._save_and_return(domain, "domain", resp.json(), user)

        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}, 504
        except requests.exceptions.ConnectionError:
            return {"error": "Could not connect to WhoisFreak API"}, 502
        except Exception:
            logger.exception(f"Unexpected error for domain {domain}")
            return {"error": "Server error"}, 500

    # ── Persist and return ────────────────────────────────────────────────────

    def _save_and_return(self, target: str, query_type: str, data: dict, user):
        lookup_record = None
        try:
            lookup_record = LookupHistory(
                user_id=user.id,
                ip_address=target,
                result=json.dumps(data),
            )
            db.session.add(lookup_record)
            db.session.commit()
            logger.info(f"Saved {query_type} lookup for '{target}' (user {user.id})")
        except Exception as db_err:
            logger.error(f"DB error saving lookup: {db_err}")
            db.session.rollback()

        return (
            {
                "target": target,
                "type": query_type,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
                "lookup_id": lookup_record.id if lookup_record else None,
            },
            200,
        )
