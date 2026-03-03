"""
Rules Models — Data structures for blocking/filtering rules.

Rules determine which traffic is blocked. They can target:
- Specific IP addresses
- Application types (e.g., YouTube, TikTok)
- Domain names (supports wildcards like *.ads.example.com)
- Port numbers (e.g., block torrent port 6881)

This mirrors the RuleManager in the C++ engine, using the same
JSON format for interoperability.
"""

from pydantic import BaseModel, Field
from typing import List


class Rules(BaseModel):
    """
    Complete set of blocking rules.
    
    JSON format (compatible with C++ engine):
    {
        "blocked_ips": ["192.168.1.50"],
        "blocked_apps": ["YouTube", "TikTok"],
        "blocked_domains": ["tiktok.com", "*.ads.google.com"],
        "blocked_ports": [6881]
    }
    """
    blocked_ips: List[str] = Field(
        default_factory=list,
        description="List of blocked source IP addresses"
    )
    blocked_apps: List[str] = Field(
        default_factory=list,
        description="List of blocked application names"
    )
    blocked_domains: List[str] = Field(
        default_factory=list,
        description="List of blocked domains (supports *.domain.com wildcards)"
    )
    blocked_ports: List[int] = Field(
        default_factory=list,
        description="List of blocked destination port numbers"
    )
