"""
Configuration — Application settings via Pydantic Settings.

Uses environment variables for configuration, with sensible defaults.
This allows the service to be configured differently in Docker vs local dev
without changing code.

Environment variables:
  DATA_DIR     — Where rules.json is stored (default: ./data)
  PORT         — Port to listen on (default: 8000)
  LOG_LEVEL    — Logging level (default: INFO)
  MAX_UPLOAD_MB — Maximum PCAP upload size (default: 50)
"""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Service identification
    app_name: str = "NetAnalyzer"
    version: str = "1.0.0"

    # Data directory for persistent storage (rules.json lives here)
    data_dir: str = str(Path(__file__).parent.parent.parent / "data")

    # Server configuration
    host: str = "0.0.0.0"
    port: int = 8000

    # Logging
    log_level: str = "INFO"

    # Upload limits
    max_upload_mb: int = 50

    # CORS origins (comma-separated in env, or list)
    cors_origins: str = "*"

    class Config:
        env_prefix = ""  # No prefix — use DATA_DIR, PORT, etc. directly
        env_file = ".env"
        case_sensitive = False


# Singleton settings instance — import this everywhere
settings = Settings()
