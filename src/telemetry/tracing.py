"""OpenTelemetry tracing scaffold (optional).

Enabled when OTEL_TRACING_ENABLED=1. Exports OTLP using HTTP/protobuf by
default, or gRPC when OTEL_EXPORTER_OTLP_PROTOCOL=grpc. Configurable via env:

- OTEL_TRACING_ENABLED: 1/true to enable
- OTEL_SERVICE_NAME: logical service name (default: janusec-platform)
- OTEL_EXPORTER_OTLP_ENDPOINT: exporter endpoint (default: http://localhost:4318)
- OTEL_EXPORTER_OTLP_PROTOCOL: http/protobuf | grpc (default: http/protobuf)
- OTEL_EXPORTER_OTLP_HEADERS: optional comma-separated headers (key=value,...)
- OTEL_TRACES_SAMPLER: always_on | always_off (default: always_on)

Minimal helpers: "pipeline_span" for custom spans. FastAPI ASGI
instrumentation can be added by the API app on startup.
"""
from __future__ import annotations

import os, logging

logger = logging.getLogger(__name__)

_TRACING_ENABLED = os.getenv('OTEL_TRACING_ENABLED','0').lower() in {'1','true','yes'}

TRACER = None

def init_tracing():  # pragma: no cover
    global TRACER
    if not _TRACING_ENABLED:
        return
    try:  # optional imports
        from opentelemetry import trace  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore

        service_name = os.getenv('OTEL_SERVICE_NAME','janusec-platform')
        endpoint = (os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT')
                    or 'http://localhost:4318')
        protocol = (os.getenv('OTEL_EXPORTER_OTLP_PROTOCOL','http/protobuf')
                    .lower())
        headers_env = os.getenv('OTEL_EXPORTER_OTLP_HEADERS','')
        headers = None
        if headers_env:
            try:
                # Convert "k=v,k2=v2" to dict
                headers = dict(
                    kv.split('=',1) for kv in headers_env.split(',') if '=' in kv
                )
            except Exception:
                headers = None

        # Build resource from service.name plus optional OTEL_RESOURCE_ATTRIBUTES
        res_attrs_env = os.getenv('OTEL_RESOURCE_ATTRIBUTES','')
        res_attrs: dict[str,str] = {'service.name': service_name}
        if res_attrs_env:
            try:
                for kv in filter(None, [p.strip() for p in res_attrs_env.split(',')]):
                    if '=' in kv:
                        k, v = kv.split('=', 1)
                        res_attrs[k.strip()] = v.strip()
            except Exception:
                pass

        # Provider + sampler
        sampler_name = os.getenv('OTEL_TRACES_SAMPLER','always_on').lower()
        sampler = None
        if sampler_name == 'always_off':
            from opentelemetry.sdk.trace.sampling import (  # type: ignore
                ALWAYS_OFF,
            )
            sampler = ALWAYS_OFF
        elif sampler_name in {'parentbased_traceidratio','traceidratio','ratio'}:
            from opentelemetry.sdk.trace.sampling import (  # type: ignore
                ParentBased,
                TraceIdRatioBased,
            )
            ratio_str = os.getenv('OTEL_TRACES_SAMPLER_ARG') or os.getenv('OTEL_SAMPLER_RATIO') or '1.0'
            try:
                ratio = max(0.0, min(1.0, float(ratio_str)))
            except Exception:
                ratio = 1.0
            base = TraceIdRatioBased(ratio)
            sampler = ParentBased(base)
        # else defaults to always_on

        provider = TracerProvider(
            resource=Resource.create(res_attrs),
            sampler=sampler,
        )

        # Exporter selection
        if protocol.startswith('grpc'):
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore
                OTLPSpanExporter as _GrpcExporter,
            )
            exporter = _GrpcExporter(endpoint=endpoint, headers=headers)
        else:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore
                OTLPSpanExporter as _HttpExporter,
            )
            # Ensure we target the traces path when using base endpoint
            ep = endpoint.rstrip('/')
            if not ep.endswith('/v1/traces'):
                ep = f"{ep}/v1/traces"
            exporter = _HttpExporter(endpoint=ep, headers=headers)

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        TRACER = trace.get_tracer(service_name)
        logger.info('Tracing initialized (OTLP %s to %s, sampler=%s)', protocol, endpoint, sampler_name)

        # Optional breadth instrumentation
        try:
            if os.getenv('OTEL_INSTRUMENT_HTTPX', '0').lower() in {'1','true','yes'}:
                from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
                HTTPXClientInstrumentor().instrument()
                logger.info('HTTPX instrumentation enabled')
        except Exception:
            logger.debug('HTTPX instrumentation unavailable')
        try:
            if os.getenv('OTEL_INSTRUMENT_ASYNCPG', '0').lower() in {'1','true','yes'}:
                from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor  # type: ignore
                AsyncPGInstrumentor().instrument()
                logger.info('asyncpg instrumentation enabled')
        except Exception:
            logger.debug('asyncpg instrumentation unavailable')
    except Exception as e:
        logger.warning(f'Tracing initialization failed: {e}')

def pipeline_span(name: str):
    """Context manager wrapper for custom pipeline spans."""
    from contextlib import nullcontext
    if not _TRACING_ENABLED or TRACER is None:
        return nullcontext()
    return TRACER.start_as_current_span(name)

__all__ = ['init_tracing','pipeline_span']
