# Multi-stage build for Threat Sifter
# Stage 1: base with build deps
FROM python:3.11-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt || true

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

EXPOSE 8080

CMD ["python","-m","src.api.server"]
