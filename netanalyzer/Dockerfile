# ============================================================================
# Dockerfile for the Python NetAnalyzer Service
# python:3.11-slim, non-root user, healthcheck, layer-cached pip install
# ============================================================================

FROM python:3.11-slim

# Create non-root user
RUN groupadd -g 1001 netanalyzer && \
    useradd -u 1001 -g netanalyzer -m -s /bin/bash netanalyzer

WORKDIR /app

# Copy requirements first for Docker layer caching
# (dependencies change less often than source code)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ app/
COPY data/ data/

# Set ownership
RUN chown -R netanalyzer:netanalyzer /app

# Switch to non-root user
USER netanalyzer

# Expose the API port
EXPOSE 8000

# Health check — Docker will ping this endpoint every 30s
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start the FastAPI service
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
