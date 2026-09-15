FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && pip check
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --upgrade pip setuptools wheel "jaraco.context>=6.1.0" \
    && pip check
# Package installation belongs to image builds. Remove the installer and its
# vendored dependencies, including ensurepip's offline installer, at runtime.
RUN python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.11/ensurepip
COPY src ./src
COPY database_adapter.py ./
COPY core ./core
COPY security ./security
COPY api ./api
COPY db ./db
COPY integrations ./integrations
COPY modules ./modules
COPY schemas ./schemas
COPY mappings ./mappings
COPY factor_specs ./factor_specs
COPY taxonomy ./taxonomy
COPY prompts ./prompts
COPY frontend ./frontend
COPY config ./config
COPY scripts ./scripts
COPY tests/fixtures/telemetry_corpora ./tests/fixtures/telemetry_corpora
COPY tests/fixtures/ground_truth ./tests/fixtures/ground_truth
RUN useradd --uid 10001 --create-home pilot \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
USER 10001:10001
ENTRYPOINT ["python", "scripts/pilot_state.py"]
CMD ["serve", "--state", "/state/runtime", "--container-listen"]
