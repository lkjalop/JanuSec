"""
Kafka Settings (P2)
Pydantic-based settings model for Kafka configuration.
Loaded once at import time from environment variables.

Env vars:
    KAFKA_BOOTSTRAP_SERVERS     — comma-separated brokers (default localhost:9092)
    KAFKA_ENABLED               — '1' to activate Kafka (default '0' — Redis-only)
    KAFKA_SECURITY_PROTOCOL     — PLAINTEXT | SSL | SASL_PLAINTEXT | SASL_SSL (default PLAINTEXT)
    KAFKA_SASL_MECHANISM        — PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512 (if SASL)
    KAFKA_SASL_USERNAME         — SASL username
    KAFKA_SASL_PASSWORD         — SASL password
    KAFKA_SSL_CA_LOCATION       — path to CA cert (if SSL/SASL_SSL)
    KAFKA_CONSUMER_GROUP        — consumer group id (default janusec.pipeline-workers)
    KAFKA_INPUT_TOPIC           — topic to consume from (default janusec.normalized)
    KAFKA_OUTPUT_TOPIC          — topic to produce to (default janusec.decisions)
    KAFKA_INGEST_TOPICS         — comma-separated input topics for fan-in (overrrides INPUT_TOPIC)
    KAFKA_POLL_TIMEOUT_MS       — consumer poll timeout ms (default 1000)
    KAFKA_BATCH_SIZE            — max records per poll (default 100)
    KAFKA_LINGER_MS             — producer linger ms for batching (default 20)
    KAFKA_COMPRESSION_TYPE      — producer compression (gzip|snappy|lz4|zstd, default gzip)
    KAFKA_SCHEMA_REGISTRY_URL   — Schema Registry URL (optional)
    KAFKA_TOPIC_PREFIX          — topic name prefix (default 'janusec.')
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class KafkaSettings:
    # Connection
    bootstrap_servers: str = field(
        default_factory=lambda: os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
    )
    enabled: bool = field(
        default_factory=lambda: os.getenv('KAFKA_ENABLED', '0') in ('1', 'true', 'yes')
    )
    security_protocol: str = field(
        default_factory=lambda: os.getenv('KAFKA_SECURITY_PROTOCOL', 'PLAINTEXT')
    )
    sasl_mechanism: str = field(
        default_factory=lambda: os.getenv('KAFKA_SASL_MECHANISM', 'PLAIN')
    )
    sasl_username: str = field(
        default_factory=lambda: os.getenv('KAFKA_SASL_USERNAME', '')
    )
    sasl_password: str = field(
        default_factory=lambda: os.getenv('KAFKA_SASL_PASSWORD', '')
    )
    ssl_ca_location: str = field(
        default_factory=lambda: os.getenv('KAFKA_SSL_CA_LOCATION', '')
    )

    # Consumer
    consumer_group: str = field(
        default_factory=lambda: os.getenv('KAFKA_CONSUMER_GROUP', 'janusec.pipeline-workers')
    )
    input_topic: str = field(
        default_factory=lambda: os.getenv('KAFKA_INPUT_TOPIC', 'janusec.normalized')
    )
    output_topic: str = field(
        default_factory=lambda: os.getenv('KAFKA_OUTPUT_TOPIC', 'janusec.decisions')
    )
    poll_timeout_ms: int = field(
        default_factory=lambda: int(os.getenv('KAFKA_POLL_TIMEOUT_MS', '1000'))
    )
    batch_size: int = field(
        default_factory=lambda: int(os.getenv('KAFKA_BATCH_SIZE', '100'))
    )

    # Producer
    linger_ms: int = field(
        default_factory=lambda: int(os.getenv('KAFKA_LINGER_MS', '20'))
    )
    compression_type: str = field(
        default_factory=lambda: os.getenv('KAFKA_COMPRESSION_TYPE', 'gzip')
    )

    # Schema Registry
    schema_registry_url: str = field(
        default_factory=lambda: os.getenv('KAFKA_SCHEMA_REGISTRY_URL', '')
    )

    # Topics
    topic_prefix: str = field(
        default_factory=lambda: os.getenv('KAFKA_TOPIC_PREFIX', 'janusec.')
    )

    def producer_config(self) -> dict:
        """Return confluent-kafka / aiokafka compatible producer config dict."""
        cfg: dict = {
            'bootstrap.servers': self.bootstrap_servers,
            'security.protocol': self.security_protocol,
            'linger.ms': self.linger_ms,
            'compression.type': self.compression_type,
            'acks': 'all',
            'retries': 5,
            'retry.backoff.ms': 200,
        }
        self._add_sasl(cfg)
        return cfg

    def consumer_config(self, group_id: str | None = None) -> dict:
        """Return confluent-kafka compatible consumer config dict."""
        cfg: dict = {
            'bootstrap.servers': self.bootstrap_servers,
            'security.protocol': self.security_protocol,
            'group.id': group_id or self.consumer_group,
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,
            'max.poll.interval.ms': 300000,
        }
        self._add_sasl(cfg)
        return cfg

    def _add_sasl(self, cfg: dict) -> None:
        if 'SASL' in self.security_protocol.upper():
            cfg['sasl.mechanisms'] = self.sasl_mechanism
            if self.sasl_username:
                cfg['sasl.username'] = self.sasl_username
            if self.sasl_password:
                cfg['sasl.password'] = self.sasl_password
        if 'SSL' in self.security_protocol.upper() and self.ssl_ca_location:
            cfg['ssl.ca.location'] = self.ssl_ca_location

    def topic(self, short_name: str) -> str:
        """Return fully-qualified topic name."""
        if short_name.startswith(self.topic_prefix):
            return short_name
        return f'{self.topic_prefix}{short_name}'


# Module-level singleton
settings = KafkaSettings()
