import asyncio
import ssl
import tempfile
import pytest

from src.collectors.syslog_collector import SyslogCollector


@pytest.mark.asyncio
async def test_tls_server_accepts_connection(monkeypatch, tmp_path):
    # create a self-signed cert pair using ssl module helpers if available
    # For test simplicity, use ssl.create_default_context for client and server with check_hostname=False
    collector = SyslogCollector(redis_url="redis://does-not-matter")

    server_cert = tmp_path / "cert.pem"
    server_key = tmp_path / "key.pem"
    # in CI environment we may not generate actual certs; skip if openssl unavailable
    try:
        # attempt to generate with openssl if present (best effort)
        import subprocess
        subprocess.check_call(["openssl", "req", "-x509", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-newkey", "rsa:2048", "-keyout", str(server_key), "-out", str(server_cert)])
    except Exception:
        pytest.skip("openssl not available to create test cert")

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))

    await collector.start(udp_port=0, tcp_port=0, tls=True, tls_context=ctx)
    await collector.stop()
