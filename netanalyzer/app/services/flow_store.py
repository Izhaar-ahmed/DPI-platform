"""
Flow Store — In-memory cache for analysis results.

This is the Python equivalent of GlobalConnectionTable in the C++ engine.
Stores flows from completed PCAP analyses, keyed by flow_id.
No database — everything is a dict + JSON file.

Thread safety: Not needed since FastAPI uses a single event loop.
"""

from typing import Dict, List, Optional

from ..models.flow import Flow
from ..models.analysis import AnalysisStats
from ..core.exceptions import FlowNotFoundError


class FlowStore:
    """
    In-memory store for network flows.
    Flows are indexed by flow_id for O(1) lookup.
    """

    def __init__(self):
        self._flows: Dict[str, Flow] = {}
        self._latest_stats: Optional[AnalysisStats] = None

    def add_flow(self, flow: Flow) -> None:
        """Add or update a flow in the store."""
        self._flows[flow.flow_id] = flow

    def get_flow(self, flow_id: str) -> Flow:
        """
        Get a flow by its ID.

        Raises:
            FlowNotFoundError: If the flow_id doesn't exist.
        """
        if flow_id not in self._flows:
            raise FlowNotFoundError(f"Flow not found: {flow_id}")
        return self._flows[flow_id]

    def get_all_flows(
        self,
        app_type: Optional[str] = None,
        blocked: Optional[bool] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
    ) -> List[Flow]:
        """
        Get all flows, optionally filtered by criteria.

        Args:
            app_type: Filter by application type (e.g., 'YouTube')
            blocked: Filter by blocked status (True/False)
            src_ip: Filter by source IP
            dst_ip: Filter by destination IP

        Returns:
            List of flows matching all specified filters.
        """
        flows = list(self._flows.values())

        if app_type is not None:
            flows = [f for f in flows if f.app_type == app_type]

        if blocked is not None:
            flows = [f for f in flows if f.blocked == blocked]

        if src_ip is not None:
            flows = [f for f in flows if f.five_tuple.src_ip == src_ip]

        if dst_ip is not None:
            flows = [f for f in flows if f.five_tuple.dst_ip == dst_ip]

        return flows

    def set_stats(self, stats: AnalysisStats) -> None:
        """Store the latest analysis statistics."""
        self._latest_stats = stats

    def get_stats(self) -> Optional[AnalysisStats]:
        """Get the latest analysis statistics, or None if no analysis has run."""
        return self._latest_stats

    def clear(self) -> None:
        """Clear all stored flows and stats."""
        self._flows.clear()
        self._latest_stats = None

    @property
    def flow_count(self) -> int:
        """Number of flows currently stored."""
        return len(self._flows)
