"""
Tests for the Analysis and Flow endpoints.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.anyio
async def test_no_stats_before_analysis(client):
    """Stats endpoint should return 404 before any analysis."""
    resp = await client.get("/api/v1/analysis/stats")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_empty_flows(client):
    """Flows endpoint should return empty list before any analysis."""
    resp = await client.get("/api/v1/flows")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.anyio
async def test_flow_not_found(client):
    """Requesting a non-existent flow should return 404."""
    resp = await client.get("/api/v1/flows/nonexistent123")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_analyze_invalid_extension(client):
    """Uploading a non-PCAP file should return 400."""
    resp = await client.post(
        "/api/v1/analyze",
        files={"file": ("test.txt", b"not a pcap file", "text/plain")},
    )
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_health_endpoint(client):
    """Health check sanity test."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data
