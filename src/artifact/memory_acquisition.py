from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.utils.webhook_notify import post_webhook

# Canonical default commands for each supported platform
WINDOWS_STEPS = [
    {
        "tool": "WinPMem",
        "command": "winpmem.exe --format raw --output C:\\\\Evidence\\\\{host}_memory.raw",
        "notes": "Run from elevated PowerShell. Output to an encrypted removable drive when possible.",
    },
    {
        "tool": "Secure Courier Upload",
        "command": "janusec-cli courier upload --attestation {attestation_id} --file C:\\\\Evidence\\\\{host}_memory.raw",
        "notes": "Couriers cryptographically attest the upload; hashes logged automatically.",
    },
]

LINUX_STEPS = [
    {
        "tool": "AVML",
        "command": "sudo avml {host}_memory.lime && gzip {host}_memory.lime",
        "notes": "Capture to mounted tmpfs or encrypted volume. Preserve AVML log output.",
    },
    {
        "tool": "Courier Upload",
        "command": "janusec-cli courier upload --attestation {attestation_id} --file {host}_memory.lime.gz",
        "notes": "Courier posts SHA256 + operator signature to attestation log.",
    },
]

MAC_STEPS = [
    {
        "tool": "osxpmem",
        "command": "sudo ./osxpmem --output /tmp/{host}_memory.aff4",
        "notes": "Ensure SIP allowances permit kext loading; capture log stored near dump.",
    },
    {
        "tool": "Courier Upload",
        "command": "janusec-cli courier upload --attestation {attestation_id} --file /tmp/{host}_memory.aff4",
        "notes": "Transfer via encrypted removable media when network restricted.",
    },
]


@dataclass
class AcquisitionPlan:
    attestation_id: str
    host: str
    os_family: str
    case_id: Optional[str]
    tenant_id: Optional[str]
    issued_at: float = field(default_factory=lambda: time.time())
    expires_at: float = 0.0
    steps: List[Dict[str, Any]] = field(default_factory=list)
    courier: Dict[str, Any] = field(default_factory=dict)
    status: str = "issued"
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    revoked: bool = False
    sla_breach: bool = False
    alerts: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "host": self.host,
            "os_family": self.os_family,
            "case_id": self.case_id,
            "tenant_id": self.tenant_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "steps": self.steps,
            "courier": self.courier,
            "status": self.status,
            "evidence": self.evidence,
            "revoked": self.revoked,
            "sla_breach": self.sla_breach,
            "alerts": self.alerts,
        }


class MemoryAcquisitionGuide:
    """Guided acquisition helper that issues WinPMem/AVML playbooks with attestation tracking."""

    def __init__(
        self,
        *,
        template_path: str | Path | None = None,
        manifest_path: str | Path = "data/memory_jobs/acquisition_manifest.json",
        plan_ttl_seconds: Optional[int] = None,
    ) -> None:
        self.template_path = Path(template_path) if template_path else Path("playbooks/templates/forensics_memory.yml")
        self.manifest_path = Path(manifest_path)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.plan_ttl = (
            plan_ttl_seconds
            if plan_ttl_seconds is not None
            else int(os.getenv("COURIER_PLAN_TTL_SECONDS", str(6 * 3600)))
        )
        self.alert_webhook = os.getenv("COURIER_ALERT_WEBHOOK")
        self.soar_webhook = os.getenv("SOAR_ALERT_WEBHOOK")
        self._alert_targets = [hook for hook in (self.alert_webhook, self.soar_webhook) if hook]
        self._lock = threading.RLock()
        self._plans: Dict[str, AcquisitionPlan] = {}
        self.perf_dir = Path(os.getenv("API_STAGE_ARTIFACT_DIR", "logs/perf/api_stage/artifacts"))
        self.perf_dir.mkdir(parents=True, exist_ok=True)
        self._load_existing()

    # ------------------------------------------------------------------ plan issuance / tracking
    def issue_plan(
        self,
        *,
        host: str,
        os_family: str,
        case_id: Optional[str],
        tenant_id: Optional[str],
        courier_profile: Optional[str] = None,
    ) -> AcquisitionPlan:
        attestation_id = f"attest-{uuid.uuid4().hex[:10]}"
        steps = self._platform_steps(os_family.lower(), attestation_id, host)
        courier = self._build_courier_manifest(attestation_id, courier_profile)
        plan = AcquisitionPlan(
            attestation_id=attestation_id,
            host=host,
            os_family=os_family.lower(),
            case_id=case_id,
            tenant_id=tenant_id,
            steps=steps,
            courier=courier,
        )
        plan.expires_at = plan.issued_at + max(self.plan_ttl, 60)
        self._evaluate_plan_state(plan, auto_alert=False)
        with self._lock:
            self._plans[attestation_id] = plan
            self._persist_locked()
        self._write_perf_artifact(plan)
        return plan

    def record_event(
        self,
        attestation_id: str,
        *,
        event: str,
        operator: Optional[str] = None,
        checksum: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ) -> AcquisitionPlan:
        with self._lock:
            plan = self._plans.get(attestation_id)
            if not plan:
                raise KeyError(f"attestation not found: {attestation_id}")
            entry = {
                "ts": time.time(),
                "event": event,
                "operator": operator,
                "checksum": checksum,
                "metadata": metadata or {},
            }
            plan.evidence.append(entry)
            if event == "revoke":
                plan.status = "revoked"
                plan.revoked = True
            elif event in {"uploaded", "analysis_complete"}:
                plan.status = event
            self._evaluate_plan_state(plan, auto_alert=True)
            self._persist_locked()
            self._write_perf_artifact(plan)
            return plan

    def list_plans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            plans = sorted(self._plans.values(), key=lambda p: p.issued_at, reverse=True)
            for plan in plans:
                self._evaluate_plan_state(plan, auto_alert=False)
            self._persist_locked()
            return [plan.to_dict() for plan in plans[:limit]]

    # ------------------------------------------------------------------ helpers
    def _load_existing(self) -> None:
        if not self.manifest_path.exists():
            return
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        manifests = data.get("plans") if isinstance(data, dict) else None
        if not isinstance(manifests, list):
            return
        for payload in manifests:
            if not isinstance(payload, dict):
                continue
            plan = AcquisitionPlan(
                attestation_id=payload.get("attestation_id") or f"attest-{uuid.uuid4().hex[:6]}",
                host=payload.get("host", ""),
                os_family=(payload.get("os_family") or "windows").lower(),
                case_id=payload.get("case_id"),
                tenant_id=payload.get("tenant_id"),
                issued_at=float(payload.get("issued_at") or time.time()),
                expires_at=float(payload.get("expires_at") or 0),
                steps=payload.get("steps") or [],
                courier=payload.get("courier") or {},
                status=payload.get("status") or "issued",
                evidence=payload.get("evidence") or [],
                revoked=bool(payload.get("revoked")),
                sla_breach=bool(payload.get("sla_breach")),
                alerts=payload.get("alerts") or [],
            )
            if not plan.expires_at:
                plan.expires_at = plan.issued_at + max(self.plan_ttl, 60)
            self._evaluate_plan_state(plan, auto_alert=False)
            self._plans[plan.attestation_id] = plan

    def _persist_locked(self) -> None:
        payload = {"plans": [plan.to_dict() for plan in self._plans.values()]}
        try:
            self.manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _platform_steps(self, os_family: str, attestation_id: str, host: str) -> List[Dict[str, Any]]:
        from_template = self._template_steps(os_family)
        steps = from_template or self._default_steps(os_family)
        enriched: List[Dict[str, Any]] = []
        for step in steps:
            template_cmd = step.get("command") or ""
            try:
                rendered_cmd = template_cmd.format(
                    host=host,
                    attestation_id=attestation_id,
                    API_KEY="${API_KEY}",
                )
            except KeyError:
                rendered_cmd = template_cmd
            enriched.append(
                {
                    **step,
                    "command": rendered_cmd,
                }
            )
        return enriched

    def _default_steps(self, os_family: str) -> List[Dict[str, Any]]:
        if os_family == "linux":
            return LINUX_STEPS
        if os_family == "macos":
            return MAC_STEPS
        return WINDOWS_STEPS

    def _template_steps(self, os_family: str) -> Optional[List[Dict[str, Any]]]:
        if not self.template_path.exists():
            return None
        try:
            data = yaml.safe_load(self.template_path.read_text(encoding="utf-8")) or {}
        except Exception:
            return None
        sections = data.get("steps") if isinstance(data, dict) else None
        if not isinstance(sections, list):
            return None
        subset: List[Dict[str, Any]] = []
        for section in sections:
            if not isinstance(section, dict):
                continue
            commands = section.get("commands") or []
            for cmd in commands:
                if not isinstance(cmd, dict):
                    continue
                platforms = set(self._infer_platforms(section.get("name"), cmd.get("tool")) or ["windows", "linux", "macos"])
                if os_family not in platforms:
                    continue
                subset.append(
                    {
                        "title": section.get("name"),
                        "tool": cmd.get("tool"),
                        "command": cmd.get("command"),
                        "notes": cmd.get("notes"),
                    }
                )
        return subset or None

    @staticmethod
    def _infer_platforms(section_name: Optional[str], tool: Optional[str]) -> List[str]:
        label = f"{section_name or ''} {tool or ''}".lower()
        if "windows" in label or "winpmem" in label or "belkasoft" in label:
            return ["windows"]
        if "linux" in label or "avml" in label or "lime" in label:
            return ["linux"]
        if "mac" in label or "osxpmem" in label:
            return ["macos"]
        return []

    def _build_courier_manifest(self, attestation_id: str, courier_profile: Optional[str]) -> Dict[str, Any]:
        profile = courier_profile or os.getenv("MEMORY_COURIER_PROFILE", "default")
        manifest = {
            "profile": profile,
            "attestation_id": attestation_id,
            "chain_of_custody": [
                "Field analyst captures memory image (WinPMem/AVML/osxpmem).",
                "Courier uploads via janusec-cli courier upload with MFA.",
                "Pipeline validates checksum + attestation signature.",
            ],
            "expected_artifacts": [
                "Memory dump file",
                "Acquisition log output",
                "Courier attestation signature",
            ],
        }
        return manifest

    def _evaluate_plan_state(self, plan: AcquisitionPlan, *, auto_alert: bool) -> None:
        now = time.time()
        if not plan.expires_at:
            plan.expires_at = plan.issued_at + max(self.plan_ttl, 60)
        if plan.revoked and auto_alert:
            plan.alerts.append({"ts": now, "kind": "revoked"})
            self._send_alert(plan, "revoked")
        if now > plan.expires_at and plan.status not in {"analysis_complete", "revoked"}:
            if not plan.sla_breach:
                plan.sla_breach = True
                if auto_alert:
                    plan.alerts.append({"ts": now, "kind": "sla_breach"})
                    self._send_alert(plan, "sla_breach")

    def _send_alert(self, plan: AcquisitionPlan, kind: str) -> None:
        payload = {
            "type": "courier_alert",
            "kind": kind,
            "attestation_id": plan.attestation_id,
            "host": plan.host,
            "tenant_id": plan.tenant_id,
            "status": plan.status,
        }
        for hook in self._alert_targets:
            post_webhook(hook, payload)


    def _write_perf_artifact(self, plan: AcquisitionPlan) -> None:
        try:
            path = self.perf_dir / "courier"
            path.mkdir(parents=True, exist_ok=True)
            out = path / f"{plan.attestation_id}.json"
            out.write_text(json.dumps(plan.to_dict(), indent=2), encoding="utf-8")
        except Exception:
            pass


__all__ = ["MemoryAcquisitionGuide", "AcquisitionPlan"]
