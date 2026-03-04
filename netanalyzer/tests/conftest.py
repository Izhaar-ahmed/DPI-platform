"""
Shared test configuration.

The FastAPI lifespan handler doesn't run automatically during tests,
so we need to initialize the global services (rule_engine, flow_store)
manually before any test that hits the API.
"""

import os
import tempfile
import pytest
from httpx import AsyncClient, ASGITransport

# Set up a temp data directory for tests so we don't pollute the real one
_test_data_dir = tempfile.mkdtemp()
os.environ["DATA_DIR"] = _test_data_dir

import app.main as main_module
from app.main import app
from app.services.rule_engine import RuleEngine
from app.services.flow_store import FlowStore


@pytest.fixture(autouse=True)
def setup_services():
    """
    Initialize the global services before every test.
    Uses a temp directory so tests don't affect real data.
    Cleans up after each test to prevent state leakage.
    """
    rules_path = os.path.join(_test_data_dir, "rules.json")

    # Initialize global services
    main_module.rule_engine = RuleEngine(rules_path)
    main_module.flow_store = FlowStore()

    yield

    # Clean up: clear rules and flows
    main_module.rule_engine.clear_all()
    main_module.flow_store.clear()


@pytest.fixture
async def client():
    """Create an async test client for FastAPI."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
