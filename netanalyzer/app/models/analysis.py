"""
Analysis Models — Data structures for PCAP analysis results.

These models structure the output of the PCAP analyzer service,
including per-app breakdowns, overall statistics, and the combined result.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from .flow import Flow


class AppBreakdown(BaseModel):
    """
    Traffic breakdown for a single application type.
    Shows how much traffic a specific app (e.g., YouTube) generated.
    """
    app_type: str = Field(..., description="Application name")
    flow_count: int = Field(default=0, ge=0, description="Number of flows for this app")
    packet_count: int = Field(default=0, ge=0, description="Total packets for this app")
    byte_count: int = Field(default=0, ge=0, description="Total bytes for this app")
    percentage: float = Field(default=0.0, description="Percentage of total flows")


class AnalysisStats(BaseModel):
    """
    Overall statistics from a PCAP analysis run.
    Mirrors the stats.json output from the C++ engine.
    """
    total_packets: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)
    tcp_packets: int = Field(default=0, ge=0)
    udp_packets: int = Field(default=0, ge=0)
    total_flows: int = Field(default=0, ge=0)
    blocked_flows: int = Field(default=0, ge=0)
    classified_flows: int = Field(default=0, ge=0, description="Flows with known app type")
    app_breakdown: List[AppBreakdown] = Field(default_factory=list)
    detected_snis: List[str] = Field(default_factory=list, description="All unique SNIs found")


class AnalysisResult(BaseModel):
    """
    Complete result of a PCAP file analysis.
    Contains the stats summary, all detected flows, and the source filename.
    """
    filename: str = Field(..., description="Name of the analyzed PCAP file")
    stats: AnalysisStats
    flows: List[Flow] = Field(default_factory=list)
    analysis_time_ms: float = Field(default=0.0, description="Processing time in milliseconds")
