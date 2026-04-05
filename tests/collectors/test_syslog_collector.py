import asyncio
import pytest

from src.collectors.syslog_collector import SyslogCollector
from src.collectors.models import CanonicalNetworkEvent


class DummyRedis:
    def __init__(self):
        self.items = []

    async def connect(self):
        return True

    async def push(self, stream_name, payload):
        self.items.append((stream_name, payload))

    async def backlog_len(self, stream_name):
        return len(self.items)

    async def close(self):
        return True


@pytest.mark.asyncio
async def test_syslog_collector_udp_parses_and_pushes(monkeypatch):
    dummy = DummyRedis()

    async def dummy_connect(self):
        return True

    # Patch RedisStreamProducer used inside SyslogCollector
    monkeypatch.setattr("src.collectors.syslog_collector.RedisStreamProducer", lambda url: dummy)

    collector = SyslogCollector(redis_url="redis://does-not-matter")

    # directly call _process_line to avoid networking setup
    line = "<34>1 2025-12-23T12:34:56.000Z myhost app - - - Test message"
    await collector._process_line(line, "udp", ("127.0.0.1", 514))

    # dummy should have one item
    assert len(dummy.items) == 1
    stream, payload = dummy.items[0]
    assert stream == collector.stream_name
    assert payload["message"] and "Test message" in payload["message"]


@pytest.mark.asyncio
async def test_syslog_collector_tcp_parses_framed_and_newline(monkeypatch):
    dummy = DummyRedis()
    monkeypatch.setattr("src.collectors.syslog_collector.RedisStreamProducer", lambda url: dummy)
    collector = SyslogCollector(redis_url="redis://does-not-matter")

    # start an asyncio TCP server using the collector handler
    server = await asyncio.start_server(collector._handle_tcp, host="127.0.0.1", port=0)
    addr = server.sockets[0].getsockname()

    async def client_send(msgs):
        reader, writer = await asyncio.open_connection(host=addr[0], port=addr[1])
        # send octet-count framed message
        framed = f"{len(msgs[0])} {msgs[0]}"
        writer.write(framed.encode())
        await writer.drain()
        # send newline message
        writer.write((msgs[1] + "\n").encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    msgs = ["<34>1 2025-12-23T12:34:56.000Z host1 app - - - framed msg", "<34>1 2025-12-23T12:34:56.000Z host1 app - - - newline msg"]
    await client_send(msgs)
    # give collector a moment to process
    await asyncio.sleep(0.1)
    server.close()
    await server.wait_closed()

    # dummy should have two items
    assert len(dummy.items) >= 2


@pytest.mark.asyncio
async def test_redis_token_bucket(monkeypatch):
    # create a fake Redis client that returns a successful eval
    class FakeRedis:
        async def time(self):
            return (1700000000, 0)

        async def eval(self, script, keys, *args):
            return 1

        async def hgetall(self, key):
            return {"tokens": "10", "last": "1700000000"}

        async def ping(self):
            return True

        async def close(self):
            return True

    dummy_client = FakeRedis()
    # monkeypatch RedisStreamProducer to use fake client
    from src.collectors.redis_producer import RedisStreamProducer

    rp = RedisStreamProducer("redis://x")
    rp._client = dummy_client
    res = await rp.try_acquire_token("rate:1.2.3.4", 100, 100.0)
    assert res is True
    state = await rp.get_token_bucket("rate:1.2.3.4")
    assert state is not None


def test_device_map_lookup(tmp_path):
    # write a small device map
    content = {
        "198.51.100.10": {"tenant_id": "tenant-a", "vendor": "acme", "product": "fw"},
        "subnets": {"10.0.0.0/8": {"tenant_id": "internal", "vendor": "internal"}},
    }
    p = tmp_path / "map.yml"
    import yaml
    p.write_text(yaml.safe_dump(content))

    collector = SyslogCollector(redis_url="redis://x")
    collector.load_device_map(str(p))
    assert collector.device_map.get("198.51.100.10")["tenant_id"] == "tenant-a"
    assert any(net.prefixlen == 8 for net, _ in collector.subnet_map)
