"""
Rules Router — Full CRUD for blocking rules.

GET    /api/v1/rules              — Get all current rules
POST   /api/v1/rules/ips          — Block an IP
DELETE /api/v1/rules/ips/{ip}     — Unblock an IP
POST   /api/v1/rules/apps         — Block an app
DELETE /api/v1/rules/apps/{app}   — Unblock an app
POST   /api/v1/rules/domains      — Block a domain
DELETE /api/v1/rules/domains/{dom} — Unblock a domain
POST   /api/v1/rules/ports        — Block a port
DELETE /api/v1/rules/ports/{port} — Unblock a port
DELETE /api/v1/rules              — Clear all rules
"""

import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..models.rules import Rules
from ..core.exceptions import RuleError

logger = logging.getLogger("netanalyzer.rules")

router = APIRouter()


# ========== Request bodies ==========

class IPRequest(BaseModel):
    ip: str = Field(..., description="IP address to block (e.g., '192.168.1.50')")

class AppRequest(BaseModel):
    app: str = Field(..., description="Application name (e.g., 'YouTube')")

class DomainRequest(BaseModel):
    domain: str = Field(..., description="Domain to block (e.g., 'tiktok.com')")

class PortRequest(BaseModel):
    port: int = Field(..., ge=0, le=65535, description="Port number to block")


# ========== Endpoints ==========

@router.get("/rules", response_model=Rules)
async def get_rules():
    """Get all current blocking rules."""
    from ..main import rule_engine
    return rule_engine.get_rules()


@router.delete("/rules")
async def clear_all_rules():
    """Clear all blocking rules."""
    from ..main import rule_engine
    rule_engine.clear_all()
    return {"message": "All rules cleared"}


# ----- IPs -----

@router.post("/rules/ips")
async def block_ip(request: IPRequest):
    """Block a source IP address."""
    from ..main import rule_engine
    try:
        rule_engine.block_ip(request.ip)
        return {"message": f"Blocked IP: {request.ip}"}
    except RuleError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/rules/ips/{ip}")
async def unblock_ip(ip: str):
    """Unblock a source IP address."""
    from ..main import rule_engine
    rule_engine.unblock_ip(ip)
    return {"message": f"Unblocked IP: {ip}"}


# ----- Apps -----

@router.post("/rules/apps")
async def block_app(request: AppRequest):
    """Block an application type."""
    from ..main import rule_engine
    try:
        rule_engine.block_app(request.app)
        return {"message": f"Blocked app: {request.app}"}
    except RuleError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/rules/apps/{app}")
async def unblock_app(app: str):
    """Unblock an application type."""
    from ..main import rule_engine
    rule_engine.unblock_app(app)
    return {"message": f"Unblocked app: {app}"}


# ----- Domains -----

@router.post("/rules/domains")
async def block_domain(request: DomainRequest):
    """Block a domain (supports wildcards like *.example.com)."""
    from ..main import rule_engine
    try:
        rule_engine.block_domain(request.domain)
        return {"message": f"Blocked domain: {request.domain}"}
    except RuleError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/rules/domains/{domain}")
async def unblock_domain(domain: str):
    """Unblock a domain."""
    from ..main import rule_engine
    rule_engine.unblock_domain(domain)
    return {"message": f"Unblocked domain: {domain}"}


# ----- Ports -----

@router.post("/rules/ports")
async def block_port(request: PortRequest):
    """Block a destination port."""
    from ..main import rule_engine
    try:
        rule_engine.block_port(request.port)
        return {"message": f"Blocked port: {request.port}"}
    except RuleError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/rules/ports/{port}")
async def unblock_port(port: int):
    """Unblock a port."""
    from ..main import rule_engine
    rule_engine.unblock_port(port)
    return {"message": f"Unblocked port: {port}"}
