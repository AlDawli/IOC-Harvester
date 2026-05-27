# ─────────────────────────────────────────────────────────────
# IOC Harvester — Multi-stage Docker Build
# ─────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build deps
RUN pip install --no-cache-dir hatchling pip --upgrade

# Copy only dependency files first (better layer caching)
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy source and install the package itself
COPY ioc_harvester/ ./ioc_harvester/
RUN pip install --no-cache-dir --prefix=/install --no-deps .


# ── Stage 2: runtime ──────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN useradd --create-home --shell /bin/bash harvester

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Output directory (will be mounted as volume in docker-compose)
RUN mkdir -p /app/output && chown harvester:harvester /app/output

USER harvester

# Health check: verify CLI is available
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ioc-harvester --version || exit 1

VOLUME ["/app/output"]

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["run"]
