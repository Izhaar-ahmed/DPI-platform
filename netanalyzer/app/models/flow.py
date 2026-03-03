"""
Flow Models — Data structures for network traffic flows.

A 'flow' represents a single network conversation between two endpoints,
identified by a five-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
This is the same concept as a 'Connection' in the C++ engine, but
implemented as Pydantic models for API serialization.
"""

from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


# Known application types — mirrors the C++ AppType enum
# so the Python and C++ engines produce comparable output
VALID_APP_TYPES = [
    "Unknown", "HTTP", "HTTPS", "DNS", "TLS", "QUIC",
    "Google", "Facebook", "YouTube", "Twitter/X", "Instagram",
    "Netflix", "Amazon", "Microsoft", "Apple", "WhatsApp",
    "Telegram", "TikTok", "Spotify", "Zoom", "Discord",
    "GitHub", "Cloudflare"
]


class FiveTuple(BaseModel):
    """
    Network five-tuple — the unique identifier for a flow.
    Every packet belongs to exactly one flow, determined by these 5 fields.
    """
    src_ip: str = Field(..., description="Source IP address (e.g., '192.168.1.10')")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., ge=0, le=65535, description="Source port number")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination port number")
    protocol: str = Field(..., description="Transport protocol: 'TCP' or 'UDP'")


class Flow(BaseModel):
    """
    A single network flow — represents one conversation between two endpoints.
    Flows are created when the first packet of a conversation is seen,
    and updated as more packets arrive.
    """
    flow_id: str = Field(..., description="Unique flow identifier (hash of five-tuple)")
    five_tuple: FiveTuple
    app_type: str = Field(default="Unknown", description="Classified application type")
    sni: Optional[str] = Field(default=None, description="Server Name Indication from TLS handshake")
    packets_sent: int = Field(default=0, ge=0, description="Packets from source to destination")
    packets_recv: int = Field(default=0, ge=0, description="Packets from destination to source")
    bytes_sent: int = Field(default=0, ge=0, description="Bytes from source to destination")
    bytes_recv: int = Field(default=0, ge=0, description="Bytes from destination to source")
    blocked: bool = Field(default=False, description="Whether this flow was blocked by a rule")
    block_reason: Optional[str] = Field(default=None, description="Why the flow was blocked")
    timestamp_start: Optional[float] = Field(default=None, description="Unix timestamp of first packet")
    timestamp_end: Optional[float] = Field(default=None, description="Unix timestamp of last packet")

    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        return self.packets_sent + self.packets_recv

    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions."""
        return self.bytes_sent + self.bytes_recv
