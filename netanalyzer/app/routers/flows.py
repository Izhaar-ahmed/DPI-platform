"""
Flows Router — Endpoints for querying detected network flows.

GET /api/v1/flows          — List all flows (with optional filters)
GET /api/v1/flows/{flow_id} — Get details for a specific flow
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..models.flow import Flow
from ..core.exceptions import FlowNotFoundError

logger = logging.getLogger("netanalyzer.flows")

router = APIRouter()


@router.get("/flows", response_model=List[Flow])
async def list_flows(
    app_type: Optional[str] = Query(None, description="Filter by app type"),
    blocked: Optional[bool] = Query(None, description="Filter by blocked status"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
):
    """
    List all detected flows with optional filtering.

    Flows are populated by the POST /analyze endpoint.
    If no analysis has been run, returns an empty list.
    """
    from ..main import flow_store

    flows = flow_store.get_all_flows(
        app_type=app_type,
        blocked=blocked,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )
    return flows


@router.get("/flows/{flow_id}", response_model=Flow)
async def get_flow(flow_id: str):
    """
    Get details for a specific flow by its ID.

    The flow_id is a 12-character hex string derived from the
    five-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
    """
    from ..main import flow_store

    try:
        return flow_store.get_flow(flow_id)
    except FlowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Flow not found: {flow_id}")
