"""
Analysis Router — Endpoints for PCAP file analysis.

POST /api/v1/analyze     — Upload and analyze a PCAP file
GET  /api/v1/analysis/stats — Get the latest analysis statistics
"""

import os
import tempfile
import logging

from fastapi import APIRouter, UploadFile, File, HTTPException

from ..models.analysis import AnalysisResult, AnalysisStats
from ..services.pcap_analyzer import analyze_pcap
from ..core.config import settings

logger = logging.getLogger("netanalyzer.analysis")

router = APIRouter()


@router.post("/analyze", response_model=AnalysisResult)
async def analyze_pcap_file(file: UploadFile = File(...)):
    """
    Upload and analyze a PCAP file.

    The file is saved to a temp directory, analyzed using Scapy,
    then deleted. Results include all flows, app classification,
    SNI extraction, and blocking status.
    """
    # Validate file extension
    if file.filename and not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .pcap, .pcapng, and .cap files are accepted."
        )

    # Read the uploaded file
    contents = await file.read()

    # Check file size
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if len(contents) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.max_upload_mb}MB."
        )

    # Write to temp file for Scapy to read
    # (Scapy's rdpcap needs a file path, not bytes)
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        # Import the global services from main
        from ..main import rule_engine, flow_store

        # Analyze the PCAP file
        result = analyze_pcap(tmp_path, rule_engine)

        # Store results in the flow store for later retrieval
        for flow in result.flows:
            flow_store.add_flow(flow)
        flow_store.set_stats(result.stats)

        logger.info(
            f"Analyzed {file.filename}: {result.stats.total_packets} packets, "
            f"{result.stats.total_flows} flows, {result.analysis_time_ms:.1f}ms"
        )

        return result

    except Exception as e:
        logger.error(f"Analysis failed for {file.filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.get("/analysis/stats", response_model=AnalysisStats)
async def get_analysis_stats():
    """
    Get the latest analysis statistics.
    Returns 404 if no analysis has been performed yet.
    """
    from ..main import flow_store

    stats = flow_store.get_stats()
    if stats is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis results available. Upload a PCAP file first."
        )
    return stats
