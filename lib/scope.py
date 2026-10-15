"""
ScopeEnforcer — ported from srt-recon, pure stdlib (ipaddress + re).
Validates targets against in-scope/out-of-scope rules.
"""

import ipaddress
import re
import logging

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """
    Accepts a list of scope entry dicts:
        {"value": "10.0.0.0/24", "type": "ip_range", "direction": "in"}
        {"value": "192.168.1.5", "type": "ip", "direction": "in"}
        {"value": "*.example.com", "type": "wildcard_domain", "direction": "in"}
        {"value": "10.0.0.99", "type": "ip", "direction": "out"}
    """

    def __init__(self, scope_entries: list[dict]):
        self.in_scope_matchers: list[callable] = []
        self.out_of_scope_matchers: list[callable] = []

        for entry in scope_entries:
            matcher = self._build_matcher(entry)
            if entry.get("direction", "in") == "out":
                self.out_of_scope_matchers.append(matcher)
            else:
                self.in_scope_matchers.append(matcher)

    def _build_matcher(self, entry: dict) -> callable:
        etype = entry.get("type", "ip_range")
        value = entry["value"]

        if etype == "ip":
            addr = ipaddress.ip_address(value)
            return lambda v, a=addr: self._match_ip(v, a)

        if etype == "ip_range":
            network = ipaddress.ip_network(value, strict=False)
            return lambda v, n=network: self._match_ip_range(v, n)

        if etype == "wildcard_domain":
            pattern = self._wildcard_to_regex(value)
            return lambda v, p=pattern: self._match_domain(v, p)

        if etype == "url":
            prefix = value.rstrip("/")
            return lambda v, pf=prefix: self._match_url(v, pf)

        return lambda v: False

    @staticmethod
    def _wildcard_to_regex(wildcard: str) -> re.Pattern:
        wildcard = wildcard.lstrip("*.")
        escaped = re.escape(wildcard)
        return re.compile(rf"^(.*\.)?{escaped}$", re.IGNORECASE)

    @staticmethod
    def _match_ip(value: str, addr) -> bool:
        try:
            return ipaddress.ip_address(value) == addr
        except ValueError:
            return False

    @staticmethod
    def _match_ip_range(value: str, network) -> bool:
        try:
            return ipaddress.ip_address(value) in network
        except ValueError:
            return False

    @staticmethod
    def _match_domain(value: str, pattern: re.Pattern) -> bool:
        host = value.split("://")[-1].split("/")[0].split(":")[0]
        return bool(pattern.match(host))

    @staticmethod
    def _match_url(value: str, prefix: str) -> bool:
        return value.rstrip("/").startswith(prefix)

    def is_in_scope(self, value: str) -> bool:
        for matcher in self.out_of_scope_matchers:
            if matcher(value):
                logger.info("OUT OF SCOPE (exclusion): %s", value)
                return False

        for matcher in self.in_scope_matchers:
            if matcher(value):
                return True

        logger.info("OUT OF SCOPE (no match): %s", value)
        return False

    def filter_targets(self, values: list[str]) -> list[str]:
        return [v for v in values if self.is_in_scope(v)]

    @staticmethod
    def expand_cidrs(scope_entries: list[dict]) -> list[str]:
        """Expand all in-scope CIDR ranges to individual IP addresses."""
        ips = []
        for entry in scope_entries:
            if entry.get("direction", "in") != "in":
                continue
            etype = entry.get("type", "ip_range")
            value = entry["value"]
            if etype == "ip":
                ips.append(value)
            elif etype == "ip_range":
                network = ipaddress.ip_network(value, strict=False)
                for addr in network.hosts():
                    ips.append(str(addr))
        return ips

    @staticmethod
    def parse_targets(targets: list[str]) -> list[dict]:
        """Convert CLI target strings (IPs, CIDRs) into scope entry dicts."""
        entries = []
        for t in targets:
            t = t.strip()
            if not t:
                continue
            if "/" in t:
                entries.append({"value": t, "type": "ip_range", "direction": "in"})
            else:
                try:
                    ipaddress.ip_address(t)
                    entries.append({"value": t, "type": "ip", "direction": "in"})
                except ValueError:
                    entries.append({"value": t, "type": "wildcard_domain", "direction": "in"})
        return entries
