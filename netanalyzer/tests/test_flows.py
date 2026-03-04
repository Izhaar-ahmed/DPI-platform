"""
Tests for the Flows endpoint filtering.
"""

import pytest
from app.services.flow_store import FlowStore
from app.models.flow import Flow, FiveTuple


class TestFlowStore:
    """Tests for the in-memory flow store."""

    def test_add_and_get_flow(self):
        """Adding a flow and retrieving it by ID should work."""
        store = FlowStore()
        flow = Flow(
            flow_id="abc123",
            five_tuple=FiveTuple(
                src_ip="10.0.0.1",
                dst_ip="172.217.0.46",
                src_port=12345,
                dst_port=443,
                protocol="TCP",
            ),
            app_type="Google",
            sni="www.google.com",
        )
        store.add_flow(flow)
        result = store.get_flow("abc123")
        assert result.flow_id == "abc123"
        assert result.app_type == "Google"

    def test_flow_not_found(self):
        """Getting a non-existent flow should raise FlowNotFoundError."""
        from app.core.exceptions import FlowNotFoundError
        store = FlowStore()
        with pytest.raises(FlowNotFoundError):
            store.get_flow("nonexistent")

    def test_filter_by_app_type(self):
        """Filtering flows by app_type should return only matching flows."""
        store = FlowStore()
        store.add_flow(Flow(
            flow_id="f1",
            five_tuple=FiveTuple(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=443, protocol="TCP"),
            app_type="YouTube",
        ))
        store.add_flow(Flow(
            flow_id="f2",
            five_tuple=FiveTuple(src_ip="1.1.1.1", dst_ip="3.3.3.3", src_port=2, dst_port=443, protocol="TCP"),
            app_type="Netflix",
        ))

        yt_flows = store.get_all_flows(app_type="YouTube")
        assert len(yt_flows) == 1
        assert yt_flows[0].flow_id == "f1"

    def test_filter_by_blocked(self):
        """Filtering flows by blocked status should work."""
        store = FlowStore()
        store.add_flow(Flow(
            flow_id="f1",
            five_tuple=FiveTuple(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=443, protocol="TCP"),
            blocked=True,
            block_reason="APP: YouTube",
        ))
        store.add_flow(Flow(
            flow_id="f2",
            five_tuple=FiveTuple(src_ip="1.1.1.1", dst_ip="3.3.3.3", src_port=2, dst_port=443, protocol="TCP"),
            blocked=False,
        ))

        blocked = store.get_all_flows(blocked=True)
        assert len(blocked) == 1

    def test_clear(self):
        """Clearing the store should remove all flows."""
        store = FlowStore()
        store.add_flow(Flow(
            flow_id="f1",
            five_tuple=FiveTuple(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=443, protocol="TCP"),
        ))
        assert store.flow_count == 1
        store.clear()
        assert store.flow_count == 0
