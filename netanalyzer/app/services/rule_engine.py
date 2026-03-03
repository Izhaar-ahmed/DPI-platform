"""
Rule Engine — Manages blocking rules with JSON file persistence.

This is the Python equivalent of rule_manager.cpp in the C++ engine.
It uses the same JSON format so rules files are interchangeable
between the C++ and Python engines.

Thread safety: Not required here since FastAPI runs in a single
asyncio event loop. The C++ engine needs shared_mutex because
it has multiple FP threads reading rules concurrently.

Persistence: Rules are saved atomically using os.replace() to
prevent corruption if the process is killed mid-write.
"""

import json
import os
import ipaddress
from pathlib import Path
from typing import Optional, Tuple

from ..models.rules import Rules
from ..models.flow import VALID_APP_TYPES
from ..core.exceptions import RuleError


class RuleEngine:
    """
    Manages blocking rules for IP addresses, apps, domains, and ports.
    Rules are loaded from and persisted to a JSON file.
    """

    def __init__(self, rules_path: str):
        """
        Initialize the rule engine.

        Args:
            rules_path: Path to the rules.json file. Created automatically
                        if it doesn't exist.
        """
        self._rules_path = Path(rules_path)
        self._rules = Rules()

        # Load existing rules or create default file
        self._load_or_create()

    def _load_or_create(self) -> None:
        """Load rules from disk, or create a default empty rules file."""
        if self._rules_path.exists():
            try:
                with open(self._rules_path, "r") as f:
                    data = json.load(f)
                self._rules = Rules(**data)
            except (json.JSONDecodeError, Exception) as e:
                print(f"[RuleEngine] Warning: Could not load {self._rules_path}: {e}")
                self._rules = Rules()
        else:
            # Create the data directory and default rules file
            self._rules_path.parent.mkdir(parents=True, exist_ok=True)
            self._save()

    def _save(self) -> None:
        """
        Save rules to disk atomically.
        
        Uses temp file + os.replace() so that a crash mid-write
        won't corrupt the rules file. os.replace() is atomic on
        all major operating systems.
        """
        self._rules_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = str(self._rules_path) + ".tmp"

        with open(temp_path, "w") as f:
            json.dump(self._rules.model_dump(), f, indent=2)

        # Atomic rename — old file is replaced in one OS call
        os.replace(temp_path, str(self._rules_path))

    # ========== Read operations ==========

    def get_rules(self) -> Rules:
        """Return the current rules."""
        return self._rules

    # ========== IP blocking ==========

    def block_ip(self, ip: str) -> None:
        """Block a source IP address."""
        # Validate the IP address format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise RuleError(f"Invalid IP address: {ip}")

        if ip not in self._rules.blocked_ips:
            self._rules.blocked_ips.append(ip)
            self._save()

    def unblock_ip(self, ip: str) -> None:
        """Unblock a source IP address."""
        if ip in self._rules.blocked_ips:
            self._rules.blocked_ips.remove(ip)
            self._save()

    # ========== Application blocking ==========

    def block_app(self, app: str) -> None:
        """Block an application type (e.g., 'YouTube')."""
        if app not in VALID_APP_TYPES:
            raise RuleError(
                f"Unknown app: {app}. Valid apps: {', '.join(VALID_APP_TYPES)}"
            )
        if app not in self._rules.blocked_apps:
            self._rules.blocked_apps.append(app)
            self._save()

    def unblock_app(self, app: str) -> None:
        """Unblock an application type."""
        if app in self._rules.blocked_apps:
            self._rules.blocked_apps.remove(app)
            self._save()

    # ========== Domain blocking ==========

    def block_domain(self, domain: str) -> None:
        """Block a domain (supports *.domain.com wildcards)."""
        if not domain:
            raise RuleError("Domain cannot be empty")
        if domain not in self._rules.blocked_domains:
            self._rules.blocked_domains.append(domain)
            self._save()

    def unblock_domain(self, domain: str) -> None:
        """Unblock a domain."""
        if domain in self._rules.blocked_domains:
            self._rules.blocked_domains.remove(domain)
            self._save()

    # ========== Port blocking ==========

    def block_port(self, port: int) -> None:
        """Block a destination port."""
        if not (0 <= port <= 65535):
            raise RuleError(f"Invalid port: {port}")
        if port not in self._rules.blocked_ports:
            self._rules.blocked_ports.append(port)
            self._save()

    def unblock_port(self, port: int) -> None:
        """Unblock a port."""
        if port in self._rules.blocked_ports:
            self._rules.blocked_ports.remove(port)
            self._save()

    # ========== Combined check ==========

    def should_block(
        self,
        src_ip: str,
        dst_port: int,
        app_type: str,
        domain: str
    ) -> Optional[Tuple[str, str]]:
        """
        Check if a flow should be blocked based on all active rules.

        Returns:
            None if the flow is allowed, or a tuple of (reason_type, detail)
            if blocked. Example: ("IP", "192.168.1.50") or ("APP", "YouTube")
        """
        # Check IP rule
        if src_ip in self._rules.blocked_ips:
            return ("IP", src_ip)

        # Check port rule
        if dst_port in self._rules.blocked_ports:
            return ("PORT", str(dst_port))

        # Check app rule
        if app_type in self._rules.blocked_apps:
            return ("APP", app_type)

        # Check domain rules (exact and wildcard)
        if domain:
            domain_lower = domain.lower()
            for blocked in self._rules.blocked_domains:
                blocked_lower = blocked.lower()

                # Exact match
                if domain_lower == blocked_lower:
                    return ("DOMAIN", domain)

                # Wildcard match: *.example.com
                if blocked_lower.startswith("*."):
                    suffix = blocked_lower[1:]  # .example.com
                    if domain_lower.endswith(suffix) or domain_lower == blocked_lower[2:]:
                        return ("DOMAIN", domain)

        return None

    def clear_all(self) -> None:
        """Remove all blocking rules."""
        self._rules = Rules()
        self._save()
