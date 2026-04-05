from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


class RegistryForensics:
    """ShimCache/AmCache/UserAssist timeline builder with factor tagging."""

    def __init__(
        self,
        *,
        evidence_path: str | Path = "data/memory_jobs/registry_timeline.jsonl",
    ) -> None:
        self.evidence_path = Path(evidence_path)
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)

    def analyze(self, results: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        shimcache = self._normalize_entries(results.get("windows.registry.shimcache"))
        amcache = self._normalize_entries(results.get("windows.registry.amcache"))
        userassist = self._normalize_userassist(results.get("windows.registry.userassist"))
        mru = self._normalize_mru(results.get("windows.registry.mru"))
        browser = self._normalize_browser(results.get("windows.registry.browser_history"))
        timeline: List[Dict[str, Any]] = []
        factors: List[str] = []

        for entry in shimcache[:15]:
            timeline.append(
                {
                    "summary": f"ShimCache: {entry.get('path')} executed (last mod {entry.get('timestamp')})",
                    "ts": entry.get("timestamp") or 0,
                    "source": "shimcache",
                }
            )
            if entry.get("signed") is False:
                factors.append("registry:unsigned_shimcache_entry")
        for entry in amcache[:15]:
            timeline.append(
                {
                    "summary": f"AmCache: {entry.get('path')} hash={entry.get('hash')}",
                    "ts": entry.get("timestamp") or 0,
                    "source": "amcache",
                }
            )
            if entry.get("hash") and entry.get("hash") in self._high_risk_hashes():
                factors.append("registry:known_malware_hash")

        for entry in userassist[:10]:
            timeline.append(
                {
                    "summary": f"UserAssist: {entry.get('path')} runs={entry.get('count')}",
                    "ts": entry.get("last_run") or 0,
                    "source": "userassist",
                }
            )
            if entry.get("count", 0) > 50:
                factors.append("registry:userassist_spike")

        for entry in mru[:10]:
            timeline.append(
                {
                    "summary": f"MRU: {entry.get('path')} opened",
                    "ts": entry.get("timestamp") or 0,
                    "source": "mru",
                }
            )

        for entry in browser[:10]:
            timeline.append(
                {
                    "summary": f"Browser URL: {entry.get('url')} ({entry.get('title')})",
                    "ts": entry.get("timestamp") or 0,
                    "source": "browser",
                }
            )
            if entry.get("suspicious"):
                factors.append("registry:browser_phishing_pattern")

        if not timeline:
            return {}

        payload = {
            "shimcache": shimcache[:50],
            "amcache": amcache[:50],
            "userassist": userassist[:50],
            "mru": mru[:50],
            "browser": browser[:50],
            "timeline": timeline[:30],
            "factors": sorted(set(factors)),
        }
        self._record(payload, metadata or {})
        return payload

    # ------------------------------------------------------------------
    def _normalize_entries(self, raw: Any) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if isinstance(raw, list):
            for row in raw:
                if not isinstance(row, dict):
                    continue
                entries.append(
                    {
                        "path": row.get("path") or row.get("Path") or row.get("Executable") or "",
                        "timestamp": row.get("timestamp") or row.get("LastModified"),
                        "hash": row.get("hash") or row.get("SHA1"),
                        "signed": row.get("Signed"),
                    }
                )
        return entries

    def _normalize_userassist(self, raw: Any) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if isinstance(raw, list):
            for row in raw:
                if not isinstance(row, dict):
                    continue
                entries.append(
                    {
                        "path": row.get("Program") or row.get("path") or "",
                        "count": int(row.get("Count") or row.get("LaunchCount") or 0),
                        "last_run": row.get("LastRun") or row.get("timestamp"),
                    }
                )
        return entries

    def _normalize_mru(self, raw: Any) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if isinstance(raw, list):
            for row in raw:
                if not isinstance(row, dict):
                    continue
                entries.append(
                    {
                        "path": row.get("path") or row.get("Value") or "",
                        "timestamp": row.get("timestamp") or row.get("LastModified") or 0,
                    }
                )
        return entries

    def _normalize_browser(self, raw: Any) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        suspicious_keywords = {"login", "invoice", "reset", "portal"}
        if isinstance(raw, list):
            for row in raw:
                if not isinstance(row, dict):
                    continue
                url = (row.get("url") or row.get("URL") or "").lower()
                title = row.get("title") or row.get("Title") or ""
                entries.append(
                    {
                        "url": url,
                        "title": title,
                        "timestamp": row.get("timestamp") or row.get("LastVisited") or 0,
                        "suspicious": any(keyword in url for keyword in suspicious_keywords),
                    }
                )
        return entries

    def _record(self, payload: Dict[str, Any], metadata: Dict[str, Any]) -> None:
        record = {
            "ts": metadata.get("captured_at") or 0,
            "host": (metadata.get("host") or "").lower(),
            "case_id": metadata.get("case_id"),
            "payload": payload,
        }
        try:
            with self.evidence_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def _high_risk_hashes(self) -> List[str]:
        path = os.getenv("MEMORY_HIGH_RISK_HASHES_PATH")
        if not path:
            return []
        try:
            data = Path(path).read_text(encoding="utf-8").splitlines()
            return [hash.strip().lower() for hash in data if hash.strip()]
        except Exception:
            return []


__all__ = ["RegistryForensics"]
