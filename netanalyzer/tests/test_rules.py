"""
Tests for the Rules API endpoints.
Tests CRUD operations for blocking IPs, apps, domains, and ports.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.anyio
async def test_get_rules_empty(client):
    """Initially, all rule lists should be empty."""
    resp = await client.get("/api/v1/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert data["blocked_ips"] == []
    assert data["blocked_apps"] == []
    assert data["blocked_domains"] == []
    assert data["blocked_ports"] == []


@pytest.mark.anyio
async def test_block_unblock_ip(client):
    """Test blocking and unblocking an IP address."""
    resp = await client.post("/api/v1/rules/ips", json={"ip": "192.168.1.50"})
    assert resp.status_code == 200

    resp = await client.get("/api/v1/rules")
    assert "192.168.1.50" in resp.json()["blocked_ips"]

    resp = await client.delete("/api/v1/rules/ips/192.168.1.50")
    assert resp.status_code == 200

    resp = await client.get("/api/v1/rules")
    assert "192.168.1.50" not in resp.json()["blocked_ips"]


@pytest.mark.anyio
async def test_block_invalid_ip(client):
    """Blocking an invalid IP should return 400."""
    resp = await client.post("/api/v1/rules/ips", json={"ip": "not-an-ip"})
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_block_unblock_app(client):
    """Test blocking and unblocking an application."""
    resp = await client.post("/api/v1/rules/apps", json={"app": "YouTube"})
    assert resp.status_code == 200

    resp = await client.get("/api/v1/rules")
    assert "YouTube" in resp.json()["blocked_apps"]

    resp = await client.delete("/api/v1/rules/apps/YouTube")
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_block_invalid_app(client):
    """Blocking an unknown app should return 400."""
    resp = await client.post("/api/v1/rules/apps", json={"app": "FakeApp"})
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_block_unblock_domain(client):
    """Test blocking and unblocking a domain."""
    resp = await client.post("/api/v1/rules/domains", json={"domain": "tiktok.com"})
    assert resp.status_code == 200

    resp = await client.get("/api/v1/rules")
    assert "tiktok.com" in resp.json()["blocked_domains"]

    resp = await client.delete("/api/v1/rules/domains/tiktok.com")
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_block_unblock_port(client):
    """Test blocking and unblocking a port."""
    resp = await client.post("/api/v1/rules/ports", json={"port": 6881})
    assert resp.status_code == 200

    resp = await client.get("/api/v1/rules")
    assert 6881 in resp.json()["blocked_ports"]

    resp = await client.delete("/api/v1/rules/ports/6881")
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_clear_all_rules(client):
    """Test clearing all rules at once."""
    await client.post("/api/v1/rules/ips", json={"ip": "10.0.0.1"})
    await client.post("/api/v1/rules/apps", json={"app": "Netflix"})

    resp = await client.delete("/api/v1/rules")
    assert resp.status_code == 200

    resp = await client.get("/api/v1/rules")
    data = resp.json()
    assert data["blocked_ips"] == []
    assert data["blocked_apps"] == []


@pytest.mark.anyio
async def test_health_check(client):
    """Health endpoint should always return 200."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
