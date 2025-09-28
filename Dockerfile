# Multi-stage build for JanuSec (formerly Threat Sifter)
# Stage 1: base with build deps
FROM python:3.11-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Leverage build cache: copy only requirements first
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip check || true

# Optional: install transformers/torch if present in requirements

# Stage 2: runtime image
FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# Minimal OS tools for troubleshooting
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=base /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=base /usr/local/bin /usr/local/bin

# Copy application source
COPY . /app

# Set default environment (override in compose / prod)
ENV EVENT_QUEUE_MAX=2000 \
    ACCESS_LOG_SAMPLE_RATE=0.5

# Create non-root user
RUN useradd -m appuser

# Port alignment with FastAPI default (we run uvicorn at 8000)
EXPOSE 8000

# Runtime env defaults (override as needed)
ENV PERSIST_BACKEND=jsonl \
    ALERT_THRESHOLD=0.75 \
    OBSERVE_LOW=0.45 \
    OBSERVE_HIGH=0.60 \
    FAST_LIVE_MODE=1

USER appuser

# Optional: healthcheck hitting /health
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD curl -fsS http://localhost:8000/health || exit 1

# Use uvicorn explicitly (enables reload off by default)
ENTRYPOINT ["uvicorn","api.server:app","--host","0.0.0.0","--port","8000"]
