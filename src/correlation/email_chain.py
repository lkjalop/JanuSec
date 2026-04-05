from __future__ import annotations
import os
import json
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

SESS_DIR = os.getenv("SESSION_PERSIST_DIR", os.path.join("data", "sessions"))


@dataclass
class ChainStage:
    stage: int
    name: str
    timestamp: float
    evidence: str
    confidence: float


@dataclass
class ChainSummary:
    session_id: str
    stages: List[ChainStage]
    severity: str
    avg_confidence: float
    created_ts: float
    mapping: Dict[str, Any]


class EmailChainCorrelator:
    """Lightweight correlation engine MVP for Email→Identity→DevOps→Endpoint.

    Stores sessions as JSON in SESS_DIR and calculates a simple severity/confidence.
    """

    def __init__(self, persist_dir: Optional[str] = None):
        self.persist_dir = persist_dir or SESS_DIR
        os.makedirs(self.persist_dir, exist_ok=True)

    def build_session(
        self,
        email_event: Dict[str, Any],
        identity_events: List[Dict[str, Any]] | None = None,
        devops_events: List[Dict[str, Any]] | None = None,
        endpoint_events: List[Dict[str, Any]] | None = None,
        mapping: Dict[str, str] | None = None,
        window_seconds: int = 72 * 3600,
    ) -> Dict[str, Any]:
        now = time.time()
        stages: List[ChainStage] = []
        # Stage 1
        try:
            stages.append(
                ChainStage(
                    stage=1,
                    name="Developer Phishing Email",
                    timestamp=float(now),
                    evidence=f"Email to {email_event.get('recipient')} : {email_event.get('subject')}",
                    confidence=0.7,
                )
            )
        except Exception:
            pass
        # Stage 2 (identity)
        for ev in (identity_events or []):
            ts = float(ev.get("timestamp") or now)
            if now - ts > window_seconds:
                continue
            et = (ev.get("event_type") or "").lower()
            if et == "oauth_grant":
                stages.append(ChainStage(2, "OAuth Token Granted", ts, f"App: {ev.get('app_name')}", 0.85))
            elif et == "login" and str(ev.get("risk_level")).lower() in {"high", "medium"}:
                stages.append(ChainStage(2, "Suspicious Login", ts, f"IP: {ev.get('ip')}", 0.75))
            elif et in {"npm_login", "pypi_login"}:
                stages.append(ChainStage(2, "Package Registry Login", ts, f"Registry: {et.replace('_login','')}", 0.9))
        # Stage 3 (devops)
        for ev in (devops_events or []):
            ts = float(ev.get("timestamp") or now)
            if now - ts > window_seconds:
                continue
            et = (ev.get("event_type") or "").lower()
            if et in {"repo_clone", "repo_push"}:
                stages.append(ChainStage(3, "Repository Access", ts, f"Repo: {ev.get('repo_name')}", 0.8))
            elif et in {"npm_publish", "pypi_publish"}:
                stages.append(ChainStage(3, "Package Published", ts, f"Package: {ev.get('package_name')}", 0.95))
            elif et == "pipeline_modified":
                stages.append(ChainStage(3, "CI/CD Pipeline Modified", ts, f"Pipeline: {ev.get('pipeline_name')}", 0.85))
            elif et == "secret_accessed":
                stages.append(ChainStage(3, "CI/CD Secret Accessed", ts, f"Secret: {ev.get('secret_name')}", 0.9))
        # Stage 4 (endpoint)
        for ev in (endpoint_events or []):
            ts = float(ev.get("timestamp") or now)
            if now - ts > window_seconds:
                continue
            et = (ev.get("event_type") or "").lower()
            if et == "package_install":
                stages.append(ChainStage(4, "Malicious Package Installed", ts, f"Pkg: {ev.get('package_name')}", 0.9))
            elif et == "process_create":
                pp = str(ev.get("process_path") or "").lower()
                if "node_modules" in pp or "site-packages" in pp:
                    stages.append(ChainStage(4, "Code Execution from Package", ts, f"Process: {ev.get('process_name')}", 0.85))

        if len(stages) >= 4:
            severity = "critical"
        elif len(stages) >= 3:
            severity = "high"
        elif len(stages) >= 2:
            severity = "high"
        else:
            severity = "observe"
        avg_conf = (sum(s.confidence for s in stages) / len(stages)) if stages else 0.0

        sid = f"chain-{int(now*1000)}"
        summary = ChainSummary(
            session_id=sid,
            stages=stages,
            severity=severity,
            avg_confidence=avg_conf,
            created_ts=now,
            mapping=mapping or {},
        )
        self._persist(summary)
        return {
            "session_id": sid,
            "severity": severity,
            "avg_confidence": avg_conf,
            "stages": [asdict(s) for s in stages],
        }

    def _persist(self, summary: ChainSummary) -> None:
        try:
            path = os.path.join(self.persist_dir, f"{summary.session_id}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "session_id": summary.session_id,
                    "severity": summary.severity,
                    "avg_confidence": summary.avg_confidence,
                    "created_ts": summary.created_ts,
                    "stages": [asdict(s) for s in summary.stages],
                    "mapping": summary.mapping,
                }, f, indent=2)
        except Exception:
            pass


__all__ = ["EmailChainCorrelator"]