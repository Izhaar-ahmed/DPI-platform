"""
FastAPI Application — Main entry point for the NetAnalyzer service.

Sets up:
  - CORS middleware (allows browser-based API clients)
  - Logging middleware (request/response logging for debugging)
  - Health check endpoint
  - Startup initialization (rule engine, flow store)
  - API router mounting
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .services.rule_engine import RuleEngine
from .services.flow_store import FlowStore
from .routers import analysis, flows, rules


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netanalyzer")


# Global service instances — initialized at startup
rule_engine: RuleEngine = None  # type: ignore
flow_store: FlowStore = None  # type: ignore


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler — runs on startup and shutdown.
    Initializes the rule engine (loads rules.json) and flow store.
    """
    global rule_engine, flow_store

    # Initialize services
    rules_path = f"{settings.data_dir}/rules.json"
    rule_engine = RuleEngine(rules_path)
    flow_store = FlowStore()

    logger.info(f"NetAnalyzer v{settings.version} starting up")
    logger.info(f"Rules loaded from: {rules_path}")
    logger.info(f"Data directory: {settings.data_dir}")

    yield  # App is running

    logger.info("NetAnalyzer shutting down")


# Create the FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "Network Traffic Analysis API — "
        "Upload PCAP files, analyze traffic flows, "
        "classify applications via SNI, and manage blocking rules."
    ),
    lifespan=lifespan,
)

# CORS middleware — allows the API to be called from browser apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Logging middleware — logs every request with timing.
    Useful for debugging and monitoring API performance.
    """
    start = time.time()
    response = await call_next(request)
    elapsed_ms = (time.time() - start) * 1000
    logger.info(
        f"{request.method} {request.url.path} → {response.status_code} ({elapsed_ms:.1f}ms)"
    )
    return response


# ========== Health Check ==========

@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for Docker/Kubernetes liveness probes.
    Returns service status and basic configuration info.
    """
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.version,
    }


# ========== Mount API Routers ==========

app.include_router(analysis.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(flows.router, prefix="/api/v1", tags=["Flows"])
app.include_router(rules.router, prefix="/api/v1", tags=["Rules"])
