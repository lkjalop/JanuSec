from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, Optional


def post_webhook(url: Optional[str], payload: Dict[str, Any]) -> None:
    if not url:
        return
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)  # nosec B310
    except Exception:
        return


__all__ = ["post_webhook"]
