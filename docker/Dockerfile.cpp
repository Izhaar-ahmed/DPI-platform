# ============================================================================
# Dockerfile for the C++ DPI Engine
# Multi-stage build: ubuntu:22.04 builder → minimal runtime
# ============================================================================

# Stage 1: Build
FROM ubuntu:22.04 AS builder

# Install build tools — cmake, g++, make
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source code
COPY CMakeLists.txt .
COPY src/ src/
COPY include/ include/

# Build all targets
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --parallel

# Stage 2: Runtime (minimal image)
FROM ubuntu:22.04

# Create non-root user for security (uid 1001 as specified)
RUN groupadd -g 1001 dpi && \
    useradd -u 1001 -g dpi -m -s /bin/bash dpi

# Copy only the compiled binaries from builder
COPY --from=builder /build/build/dpi_engine /usr/local/bin/dpi_engine
COPY --from=builder /build/build/packet_analyzer /usr/local/bin/packet_analyzer
COPY --from=builder /build/build/dpi_simple /usr/local/bin/dpi_simple

# Create directories for data and output
RUN mkdir -p /data /output && chown -R dpi:dpi /data /output

# Switch to non-root user
USER dpi

WORKDIR /data

# Default command — show help
ENTRYPOINT ["dpi_engine"]
CMD ["--help"]
