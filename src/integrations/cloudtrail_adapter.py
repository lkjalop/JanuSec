import json
import os
import time
from typing import Any, Dict, Iterable, List

import urllib.request


def normalize_cloudtrail_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    user = (rec.get('userIdentity') or {}).get('userName') or (rec.get('userIdentity') or {}).get('arn')
    evt = {
        'source': 'cloudtrail',
        'ts': rec.get('eventTime'),
        'user': user,
        'host': rec.get('recipientAccountId'),
        'event_name': rec.get('eventName'),
        'service': rec.get('eventSource'),
        'request_ip': rec.get('sourceIPAddress'),
        'raw': rec,
    }
    return {k: v for k, v in evt.items() if v is not None}


def iter_cloudtrail_json(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for rec in (data.get('Records') or []):
        yield normalize_cloudtrail_record(rec)


def post_events(base_url: str, api_key: str, tenant_id: str, events: List[Dict[str, Any]]) -> None:
    # Use resilient post helper to retry and enqueue to DLQ on persistent failure
    payload = json.dumps({'events': events}).encode('utf-8')
    url = f"{base_url.rstrip('/')}/api/v1/ingest/cloudtrail"

    def _do_post():
        req = urllib.request.Request(
            url,
            data=payload,
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'x-api-key': api_key,
                'x-tenant-id': tenant_id,
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            return resp.read()

    try:
        from .resilient_ingest import resilient_post, build_post_payload
    except Exception:
        from integrations.resilient_ingest import resilient_post, build_post_payload

    payload_meta = build_post_payload(base_url, api_key, tenant_id, events)
    resilient_post(_do_post, payload_meta, attempts=3)


def process_dir(dir_path: str, base_url: str, api_key: str, tenant_id: str) -> int:
    count = 0
    for root, _dirs, files in os.walk(dir_path):
        for name in files:
            if not name.lower().endswith('.json'):
                continue
            p = os.path.join(root, name)
            try:
                events = list(iter_cloudtrail_json(p))
                if events:
                    post_events(base_url, api_key, tenant_id, events)
                    count += len(events)
            except Exception:
                continue
    return count
from typing import Any, Dict, List, Optional, Tuple
import time

try:
    from .connector_base import ConnectorBase
except Exception:
    from src.integrations.connector_base import ConnectorBase  # type: ignore


class CloudTrailAdapter(ConnectorBase):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._cursor: Optional[str] = None

    async def connect(self) -> bool:
        return True

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        import os
        if 'PYTEST_CURRENT_TEST' not in os.environ:
            raise RuntimeError(
                'CloudTrailAdapter.fetch_since is a test fixture only. '
                'Use src.connectors.aws.cloudtrail.CloudTrailConnector for production.'
            )
        base_ts = int(time.time())
        events: List[Dict[str, Any]] = []
        for i in range(2):
            raw = {
                "eventTime": base_ts + i,
                "eventName": "CreateUser" if i == 0 else "DeleteUser",
                "sourceIPAddress": f"198.51.100.{10+i}",
                "userAgent": "aws-cli/2.0",
                "userIdentity": {"userName": f"user{i}"},
                "resources": [{"ARN": f"arn:aws:iam::123456789012:user/user{i}"}],
            }
            events.append(self.canonical_event(raw))
        return events, str(base_ts + 2)

    async def ack(self, cursor: Optional[str]) -> bool:
        self._cursor = cursor or self._cursor
        return True

    async def health(self) -> Dict[str, Any]:
        return {"connected": True, "cursor": self._cursor}

    def canonical_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": raw.get("eventTime"),
            "action": raw.get("eventName"),
            "ip": raw.get("sourceIPAddress"),
            "user_agent": raw.get("userAgent"),
            "user": (raw.get("userIdentity") or {}).get("userName"),
            "resource": ((raw.get("resources") or [{}])[0]).get("ARN"),
        }

    # Minimal S3 inbox ingestion stubs (mockable)
    async def list_inbox(self, inbox_dir: Optional[str]) -> List[str]:
        import os
        if not inbox_dir or not os.path.isdir(inbox_dir):
            return []
        return sorted([os.path.join(inbox_dir, f) for f in os.listdir(inbox_dir) if f.endswith('.json')])

    async def load_object(self, path: str) -> List[Dict[str, Any]]:
        import json
        try:
            with open(path, 'r', encoding='utf-8') as f:
                j = json.load(f)
            # Normalize either a list of events or a single event dict
            if isinstance(j, list):
                return [self.canonical_event(x) for x in j]
            elif isinstance(j, dict):
                return [self.canonical_event(j)]
        except Exception:
            return []
        return []
