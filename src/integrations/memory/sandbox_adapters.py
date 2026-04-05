from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional


class SandboxAdapter:
    name = "base"

    def submit(self, job, analysis: Dict[str, Any]) -> Dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


class LocalSandboxAdapter(SandboxAdapter):
    name = "local"

    def __init__(self, *, path: str | Path = "data/memory_jobs/sandbox_local.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def submit(self, job, analysis: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "adapter": self.name,
            "job_id": getattr(job, "job_id", None),
            "ts": time.time(),
            "verdict": analysis.get("dread", {}).get("damage"),
        }
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload) + "\n")
        except Exception:
            pass
        return payload


class HTTPSandboxAdapter(SandboxAdapter):
    """Generic HTTP sandbox adapter used by Cuckoo/Joe/AnyRun wrappers."""

    def __init__(
        self,
        *,
        name: str,
        endpoint: str,
        token: Optional[str] = None,
        timeout: float = 8.0,
    ) -> None:
        self.name = name
        self.endpoint = endpoint
        self.token = token
        self.timeout = timeout

    def submit(self, job, analysis: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "job_id": getattr(job, "job_id", None),
            "host": getattr(job, "host", None),
            "factors": analysis.get("factors", []),
            "verdict_hint": analysis.get("dread", {}).get("damage"),
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint,
                data=data,
                headers=self._headers(),
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                parsed = json.loads(resp.read().decode("utf-8") or "{}")
        except Exception:
            parsed = {"status": "queued", "adapter": self.name}
        parsed.setdefault("adapter", self.name)
        return parsed

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers


def build_sandbox_adapters() -> list[SandboxAdapter]:
    adapters: list[SandboxAdapter] = []
    names = (os.getenv("MEMORY_SANDBOX_ADAPTERS") or "local").split(",")
    for raw in names:
        name = raw.strip().lower()
        if not name:
            continue
        if name == "local":
            adapters.append(LocalSandboxAdapter())
        elif name == "cuckoo":
            endpoint = os.getenv("CUCKOO_API_ENDPOINT")
            if endpoint:
                adapters.append(
                    HTTPSandboxAdapter(
                        name="cuckoo",
                        endpoint=endpoint,
                        token=os.getenv("CUCKOO_API_TOKEN"),
                    )
                )
        elif name == "joe":
            endpoint = os.getenv("JOE_API_ENDPOINT")
            if endpoint:
                adapters.append(
                    HTTPSandboxAdapter(
                        name="joe",
                        endpoint=endpoint,
                        token=os.getenv("JOE_API_TOKEN"),
                    )
                )
        elif name == "anyrun":
            endpoint = os.getenv("ANYRUN_API_ENDPOINT")
            if endpoint:
                adapters.append(
                    HTTPSandboxAdapter(
                        name="anyrun",
                        endpoint=endpoint,
                        token=os.getenv("ANYRUN_API_TOKEN"),
                    )
                )
    if not adapters:
        adapters.append(LocalSandboxAdapter())
    return adapters


__all__ = ["SandboxAdapter", "LocalSandboxAdapter", "HTTPSandboxAdapter", "build_sandbox_adapters"]
