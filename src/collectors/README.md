Collectors Sprint 0 - Quickstart
===============================

This folder contains initial scaffolding for network collectors (syslog/netflow).

Prereqs:
- Redis running (local or remote)
- Python virtualenv with project requirements installed

Example: run a quick redis push smoke test

```powershell
& .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -c "from src.collectors.redis_producer import RedisStreamProducer, asyncio; async def r(): p=RedisStreamProducer('redis://localhost:6379/0'); await p.push('syslog', {'ts':'2025-12-23T00:00:00Z','source':'127.0.0.1','message':'test'})
asyncio.run(r())"
```

Configuration
- See config/collectors.yml.example and config/exporter_device_map.yml.example

Next steps:
- Implement syslog listeners and parsers, push to Redis stream using `RedisStreamProducer`.
