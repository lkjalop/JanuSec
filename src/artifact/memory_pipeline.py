from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.artifact.hopgraph_lite import HopGraphLite
from src.artifact.models import ArtifactObservation, ArtifactType, Verdict, stable_artifact_id
from src.integrations.memory.volatility3_adapter import Volatility3Adapter
from src.integrations.memory.rekall_adapter import RekallAdapter
from src.integrations.memory.sandbox_runner import MemorySandboxRunner
from src.artifact.memory_timeline import build_timeline
try:  # pragma: no cover
    from src.artifact.memory_crypto import MemoryKeyManager, EncryptionEnvelope  # type: ignore
except Exception:  # pragma: no cover
    MemoryKeyManager = None  # type: ignore
    EncryptionEnvelope = None  # type: ignore
try:  # pragma: no cover
    from src.artifact.memory_acquisition import MemoryAcquisitionGuide  # type: ignore
except Exception:  # pragma: no cover
    MemoryAcquisitionGuide = None  # type: ignore
try:  # pragma: no cover
    from src.artifact.registry_forensics import RegistryForensics  # type: ignore
except Exception:  # pragma: no cover
    RegistryForensics = None  # type: ignore
try:  # pragma: no cover
    from src.artifact.malware_classifier import MalwareClassifier  # type: ignore
except Exception:  # pragma: no cover
    MalwareClassifier = None  # type: ignore
try:  # pragma: no cover - optional import for richer scoring
    from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model  # type: ignore
except Exception:  # pragma: no cover
    aggregate_threat_model = None  # type: ignore
try:  # pragma: no cover
    from cryptography.fernet import Fernet  # type: ignore
except Exception:  # pragma: no cover
    Fernet = None  # type: ignore

try:  # pragma: no cover - optional hopgraph sink
    from src.graph.unified import UG as UNIFIED_GRAPH  # type: ignore
except Exception:  # pragma: no cover
    UNIFIED_GRAPH = None  # type: ignore
try:  # pragma: no cover - fallback to direct HopGraph import
    from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_HOPGRAPH = None  # type: ignore
try:  # pragma: no cover - job persistence
    from src.artifact.memory_repository import record_memory_job  # type: ignore
except Exception:  # pragma: no cover
    record_memory_job = None  # type: ignore

LOGGER = logging.getLogger(__name__)


@dataclass
class MemoryJob:
    job_id: str
    host: str
    case_id: Optional[str]
    filename: str
    dump_path: Path
    tenant_id: Optional[str] = None
    created_at: float = field(default_factory=lambda: time.time())
    updated_at: float = field(default_factory=lambda: time.time())
    status: str = "queued"
    factors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    plugin_results: Dict[str, Any] = field(default_factory=dict)
    requested_plugins: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    attestation_id: Optional[str] = None


class MemoryPipeline:
    """High-level orchestration for memory dump handling + analysis."""

    DEFAULT_PLUGINS = ["windows.pslist", "windows.dlllist", "windows.malfind", "windows.netscan"]
    SECURE_SUFFIX = ".enc"

    def __init__(
        self,
        *,
        storage_dir: str | Path = "data/memory_jobs",
        signatures_path: str | Path = "data/memory_signatures/signatures.json",
        adapter: Optional[Volatility3Adapter] = None,
        hopgraph: Optional[HopGraphLite] = None,
        graph_sink: Any | None = None,
        rekall_adapter: Optional[RekallAdapter] = None,
        sandbox_runner: Optional[MemorySandboxRunner] = None,
        dump_ttl_seconds: Optional[int] = None,
        key_manager: Optional["MemoryKeyManager"] = None,
        acquisition_guide: Optional["MemoryAcquisitionGuide"] = None,
    ) -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.signatures = self._load_signatures(Path(signatures_path))
        self.adapter = adapter or Volatility3Adapter(default_plugins=self.DEFAULT_PLUGINS)
        self.graph = hopgraph or HopGraphLite()
        self.jobs: Dict[str, MemoryJob] = {}
        self._fernet: Fernet | None = None  # type: ignore[assignment]
        self._xor_key: Optional[bytes] = None
        raw_key = os.getenv("MEMORY_ENCRYPTION_KEY")
        if raw_key:
            if Fernet is not None:
                try:
                    self._fernet = Fernet(raw_key.encode("utf-8"))
                except Exception:
                    self._fernet = None
            if self._fernet is None:
                try:
                    self._xor_key = base64.urlsafe_b64decode(raw_key.encode("utf-8"))
                except Exception:
                    self._xor_key = None
                    LOGGER.warning("memory_pipeline_encryption_key_invalid")
        self.graph_sink = graph_sink or self._discover_graph_sink()
        self.rekall_adapter = rekall_adapter
        if self.rekall_adapter is None and os.getenv("MEMORY_REKALL_ENABLED", "0").lower() in {"1", "true", "yes"}:
            self.rekall_adapter = RekallAdapter()
        self.sandbox_runner = sandbox_runner
        if self.sandbox_runner is None and os.getenv("MEMORY_SANDBOX_ENABLED", "0").lower() in {"1", "true", "yes"}:
            self.sandbox_runner = MemorySandboxRunner()
        if dump_ttl_seconds is not None:
            self.dump_ttl_seconds = dump_ttl_seconds
        else:
            try:
                self.dump_ttl_seconds = int(os.getenv("MEMORY_DUMP_TTL_SECONDS", str(7 * 24 * 3600)))
            except Exception:
                self.dump_ttl_seconds = 7 * 24 * 3600
        self.key_manager = key_manager
        if self.key_manager is None and MemoryKeyManager:
            if os.getenv("MEMORY_KMS_DISABLED", "0").lower() not in {"1", "true", "yes"}:
                self.key_manager = MemoryKeyManager()  # type: ignore[arg-type]
        self.acquisition_guide = acquisition_guide
        if self.acquisition_guide is None and MemoryAcquisitionGuide:
            if os.getenv("MEMORY_ACQUISITION_DISABLED", "0").lower() not in {"1", "true", "yes"}:
                self.acquisition_guide = MemoryAcquisitionGuide()  # type: ignore[arg-type]
        self._job_envelopes: Dict[str, EncryptionEnvelope] = {} if EncryptionEnvelope else {}
        self.registry_forensics = RegistryForensics() if RegistryForensics else None
        self.malware_classifier = MalwareClassifier() if MalwareClassifier else None
        self.perf_dir = Path(os.getenv("API_STAGE_ARTIFACT_DIR", "logs/perf/api_stage/artifacts"))
        self.perf_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ public API
    def submit_job(
        self,
        *,
        host: str,
        case_id: Optional[str],
        filename: str,
        dump_bytes: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        plugins: Optional[Sequence[str]] = None,
    ) -> MemoryJob:
        job_id = f"mem-{uuid.uuid4().hex[:12]}"
        job_dir = self.storage_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        dump_path = job_dir / f"{job_id}.raw"
        job = MemoryJob(
            job_id=job_id,
            host=host,
            case_id=case_id,
            filename=filename,
            dump_path=dump_path,
            tenant_id=(metadata or {}).get("tenant_id"),
            metadata=metadata or {},
            requested_plugins=list(plugins or self.DEFAULT_PLUGINS),
        )
        acquisition_meta = job.metadata.get("acquisition")
        if isinstance(acquisition_meta, dict) and acquisition_meta.get("attestation_id"):
            job.attestation_id = acquisition_meta.get("attestation_id")
        else:
            job.attestation_id = job.metadata.get("attestation_id")
        self._attach_envelope(job)
        encrypted_bytes = self._encrypt_for_job(job, dump_bytes)
        dump_path.write_bytes(encrypted_bytes)
        self.jobs[job_id] = job
        if job.attestation_id:
            self._record_acquisition_event(job.attestation_id, "uploaded", {"job_id": job.job_id})
        LOGGER.info("memory_job_submitted id=%s host=%s size=%s", job_id, host, len(dump_bytes))
        return job

    def process_job(self, job_id: str, *, auto_cleanup: bool = False) -> MemoryJob:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError(f"memory job not found: {job_id}")
        job.status = "running"
        job.updated_at = time.time()
        plaintext_path = self._ensure_plaintext(job.dump_path, job)
        try:
            results = self.adapter.run_plugins(
                plaintext_path,
                plugins=job.requested_plugins,
                profile=job.metadata.get("profile"),
            )
            rekall_results = self._run_rekall(job, plaintext_path)
        finally:
            if auto_cleanup and plaintext_path.exists():
                plaintext_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        job.plugin_results = results
        analysis = self._analyze_results(job, results)
        if rekall_results:
            analysis["rekall"] = rekall_results
        registry_summary = self._analyze_registry(results, job)
        if registry_summary:
            analysis["registry"] = registry_summary
            registry_factors = registry_summary.get("factors") or []
            if registry_factors:
                analysis.setdefault("factors", [])
                analysis["factors"].extend(registry_factors)
        timeline = build_timeline(
            job,
            results,
            rekall_results,
            platform=job.metadata.get("platform"),
            sandbox_policy=job.metadata.get("sandbox_policy"),
            registry_entries=(registry_summary or {}).get("timeline"),
        )
        analysis["timeline"] = timeline
        job.timeline = timeline
        sandbox_info = self._maybe_run_sandbox(job, analysis)
        if sandbox_info:
            analysis["sandbox"] = sandbox_info
        malware_family = self._classify_malware(results, sandbox_info)
        if malware_family:
            analysis["malware_family"] = malware_family
            fam = malware_family.get("family")
            if fam:
                analysis.setdefault("factors", [])
                analysis["factors"].append(f"malware:{fam}")
        job.metadata["analysis"] = analysis
        job.factors = analysis.get("factors", [])
        job.status = "completed"
        job.updated_at = time.time()
        summary_path = job.dump_path.with_suffix(".json")
        summary_path.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        self._persist_job_summary(job, analysis)
        self._rotate_old_dumps()
        if job.attestation_id:
            self._record_acquisition_event(job.attestation_id, "analysis_complete", {"job_id": job.job_id})
        LOGGER.info("memory_job_completed id=%s factors=%s", job_id, len(job.factors))
        return job

    # ------------------------------------------------------------------ helpers
    def _ensure_plaintext(self, path: Path, job: Optional[MemoryJob] = None) -> Path:
        envelope = None
        if job and self._job_envelopes is not None:
            envelope = self._job_envelopes.get(job.job_id)
            if not envelope and self.key_manager and job.metadata.get("encryption"):
                descriptor = job.metadata.get("encryption")
                if isinstance(descriptor, dict):
                    try:
                        envelope = self.key_manager.resume_envelope(descriptor)
                    except Exception:
                        envelope = None
                    if envelope:
                        self._job_envelopes[job.job_id] = envelope
        if envelope:
            decrypted = path.with_suffix(".dec")
            if decrypted.exists():
                return decrypted
            cipher_bytes = path.read_bytes()
            decrypted.write_bytes(envelope.decrypt(cipher_bytes))
            return decrypted
        if self._fernet:
            return path
        if not self._xor_key:
            return path
        decrypted = path.with_suffix(".dec")
        if decrypted.exists():
            return decrypted
        cipher_bytes = path.read_bytes()
        decrypted.write_bytes(self._decrypt(cipher_bytes))
        return decrypted

    def _attach_envelope(self, job: MemoryJob) -> None:
        if not self.key_manager or EncryptionEnvelope is None:
            return
        try:
            envelope = self.key_manager.issue_envelope(job.tenant_id)
        except Exception:
            LOGGER.warning("memory_key_issue_failed tenant=%s", job.tenant_id, exc_info=True)
            return
        self._job_envelopes[job.job_id] = envelope
        job.metadata.setdefault("encryption", envelope.describe())
        try:
            manifest = self.key_manager.describe_scope(job.tenant_id) if hasattr(self.key_manager, "describe_scope") else None
            if manifest:
                job.metadata["encryption_manifest"] = manifest
        except Exception:
            pass

    def _encrypt(self, data: bytes) -> bytes:
        if self._fernet:
            return self._fernet.encrypt(data)
        if self._xor_key:
            return bytes(b ^ self._xor_key[i % len(self._xor_key)] for i, b in enumerate(data))
        return data

    def _encrypt_for_job(self, job: MemoryJob, data: bytes) -> bytes:
        envelope = self._job_envelopes.get(job.job_id) if self._job_envelopes else None
        if envelope:
            return envelope.encrypt(data)
        return self._encrypt(data)

    def _decrypt(self, data: bytes) -> bytes:
        if self._fernet:
            try:
                return self._fernet.decrypt(data)
            except Exception:
                LOGGER.warning("memory_pipeline_decrypt_failed")
                return b""
        if self._xor_key:
            return bytes(b ^ self._xor_key[i % len(self._xor_key)] for i, b in enumerate(data))
        return data

    def _load_signatures(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            LOGGER.warning("memory_signatures_load_failed path=%s", path)
            return {}

    def _analyze_results(self, job: MemoryJob, results: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        hopgraph_edges: List[Dict[str, Any]] = []
        factors: List[str] = []
        kill_chain: List[str] = []
        mitre_tags: List[str] = []
        dread_breakdown: Dict[str, float] = {}

        pslist = (
            results.get("windows.pslist")
            or results.get("pslist")
            or results.get("windows.pslist.windows")
        )
        dlllist = results.get("windows.dlllist") or results.get("dlllist")
        malfind = results.get("windows.malfind") or results.get("malfind")
        netscan = results.get("windows.netscan") or results.get("netscan")

        suspicious = self._match_process_signatures(pslist)
        if suspicious:
            factors.extend(["memory:suspicious_process", "process_injection"])
            kill_chain.append("Installation")
            mitre_tags.append("T1055")
            dread_breakdown = self._merge_dread(dread_breakdown, 0.7, 0.6, 0.6, 0.5, 0.5)
            findings.extend(suspicious)
            hopgraph_edges.extend(self._build_process_edges(job, suspicious))

        injection_hits = self._analyze_malfind(malfind)
        if injection_hits:
            factors.append("memory:suspicious_injection")
            kill_chain.append("Installation")
            mitre_tags.extend(["T1055"])
            dread_breakdown = self._merge_dread(dread_breakdown, 0.8, 0.5, 0.6, 0.7, 0.4)
            findings.extend(injection_hits)
            hopgraph_edges.extend(self._build_malfind_edges(job, injection_hits))

        dll_hits = self._match_dll_signatures(dlllist)
        if dll_hits:
            factors.append("memory:dll_anomaly")
            kill_chain.append("Execution")
            mitre_tags.extend(["T1218"])
            dread_breakdown = self._merge_dread(dread_breakdown, 0.6, 0.5, 0.4, 0.4, 0.5)
            findings.extend(dll_hits)
            hopgraph_edges.extend(self._build_dll_edges(job, dll_hits))

        beacon_edges = self._analyze_netscan(job, netscan)
        if beacon_edges:
            factors.append("memory:beacon_context")
            kill_chain.append("Command and Control")
            mitre_tags.extend(["T1071"])
            dread_breakdown = self._merge_dread(dread_breakdown, 0.5, 0.5, 0.6, 0.4, 0.6)
            hopgraph_edges.extend(beacon_edges)

        if not dread_breakdown:
            dread_breakdown = {k: 0.0 for k in ("damage", "repro", "exploit", "affected_users", "discoverability")}

        threat_model: Dict[str, Any] = {}
        if aggregate_threat_model:
            try:
                threat_model = aggregate_threat_model(factors) or {}
            except Exception:
                threat_model = {}

        if threat_model:
            dread_from_model = threat_model.get("dread") or {}
            if isinstance(dread_from_model, dict):
                components = dread_from_model.get("max_components") or dread_from_model
                if isinstance(components, dict):
                    for key, value in components.items():
                        try:
                            numeric = float(value)
                        except Exception:
                            continue
                        dread_breakdown[key] = max(dread_breakdown.get(key, 0.0), numeric)
            tm_mitre = threat_model.get("mitre") or []
            if tm_mitre:
                mitre_tags.extend([tag for tag in tm_mitre if tag not in mitre_tags])
            maestro_meta = threat_model.get("maestro") or {}
            maestro_phases: List[str] = []
            if isinstance(maestro_meta, dict):
                primary = maestro_meta.get("primary")
                if isinstance(primary, str):
                    maestro_phases.append(primary)
                for phase, _count in maestro_meta.get("phases") or []:
                    if isinstance(phase, str):
                        maestro_phases.append(phase)
            if maestro_phases:
                kill_chain.extend([kc for kc in maestro_phases if kc not in kill_chain])

        # Update HopGraph for each suspicious process
        for proc in findings:
            if proc.get("type") != "process":
                continue
            obs = ArtifactObservation(
                artifact_id=stable_artifact_id(job.host, proc.get("path"), proc.get("sha256"), ArtifactType.EXECUTABLE),
                sha256=proc.get("sha256"),
                artifact_type=ArtifactType.EXECUTABLE,
                host=job.host,
                path=proc.get("path"),
                name=proc.get("image") or proc.get("name") or "unknown",
                raw=proc,
                factors=factors,
                mitre=list(dict.fromkeys(mitre_tags)),
                verdict=Verdict.SUSPICIOUS,
            )
            self.graph.update(obs)

        analysis = {
            "job_id": job.job_id,
            "host": job.host,
            "case_id": job.case_id,
            "findings": findings,
            "factors": list(dict.fromkeys(factors)),
            "hopgraph_edges": hopgraph_edges,
            "kill_chain": list(dict.fromkeys(kill_chain)),
            "mitre": list(dict.fromkeys(mitre_tags)),
            "dread": dread_breakdown,
            "requested_artifacts": self._collected_artifacts(results),
        }
        if threat_model:
            analysis["threat_model"] = threat_model
        self._emit_graph_edges(job, hopgraph_edges, factors, mitre_tags)
        return analysis

    def _run_rekall(self, job: MemoryJob, dump_path: Path) -> Optional[Dict[str, Any]]:
        if not self.rekall_adapter:
            return None
        try:
            return self.rekall_adapter.run_plugins(
                dump_path,
                profile=job.metadata.get("profile"),
            )
        except Exception:
            LOGGER.warning("memory_rekall_run_failed id=%s", job.job_id, exc_info=True)
            return None

    # ------------------------------------------------------------------ signature helpers
    def _match_process_signatures(self, pslist) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        if not isinstance(pslist, list):
            return matches
        process_sigs = self.signatures.get("processes") or []
        lolbins = {((n or "").lower()) for n in self.signatures.get("lolbin_processes") or []}
        for entry in pslist:
            image = str(entry.get("ImageFileName") or entry.get("image") or "").lower()
            if not image:
                continue
            for sig in process_sigs:
                sig_name = str(sig.get("name") or "").lower()
                if sig_name and sig_name in image:
                    matches.append({"type": "process", "image": image, "pid": entry.get("PID") or entry.get("pid"), "threat": sig.get("threat"), "metadata": sig})
                    break
            if image in lolbins:
                matches.append(
                    {
                        "type": "process",
                        "image": image,
                        "pid": entry.get("PID") or entry.get("pid"),
                        "threat": "LOLBIN execution from memory",
                        "metadata": {"mitre": ["T1218"], "kill_chain": ["Execution"]},
                    }
                )
        return matches

    def _match_dll_signatures(self, dlllist) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        if not isinstance(dlllist, list):
            return matches
        dll_sigs = self.signatures.get("dlls") or []
        for entry in dlllist:
            name = str(entry.get("BaseDllName") or entry.get("name") or "").lower()
            if not name:
                continue
            for sig in dll_sigs:
                sig_name = str(sig.get("name") or "").lower()
                if sig_name and sig_name in name:
                    matches.append({"type": "dll", "name": name, "pid": entry.get("PID") or entry.get("pid"), "threat": sig.get("threat"), "metadata": sig})
                    break
        return matches

    def _analyze_malfind(self, malfind) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        if not isinstance(malfind, list):
            return hits
        for entry in malfind:
            hit = {
                "type": "malfind",
                "pid": entry.get("PID") or entry.get("pid"),
                "process": entry.get("Process") or entry.get("image"),
                "tag": entry.get("Tag"),
                "protection": entry.get("Protection"),
                "threat": "Injected code region detected",
                "mitre": ["T1055"],
                "kill_chain": ["Installation"],
            }
            hits.append(hit)
        return hits

    def _analyze_netscan(self, job: MemoryJob, netscan) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        if not isinstance(netscan, list):
            return edges
        beacon_terms = {term.lower() for term in (self.signatures.get("beacon_strings") or [])}
        for entry in netscan:
            dst = entry.get("ForeignAddr") or entry.get("dst") or ""
            image = (entry.get("Process") or entry.get("image") or "").lower()
            if not dst or not image:
                continue
            if beacon_terms and not any(term in (entry.get("Info") or "").lower() for term in beacon_terms):
                continue
            edges.append(
                {
                    "source": image,
                    "source_type": "process",
                    "source_node": self._process_node(job.host, image),
                    "target": dst,
                    "target_type": "network",
                    "target_node": self._network_node(dst),
                    "edge_type": "memory_beacon",
                    "host": job.host,
                    "metadata": entry,
                }
            )
        return edges

    def _build_process_edges(self, job: MemoryJob, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        for proc in processes:
            pid = proc.get("pid")
            src_label = proc.get("image")
            edges.append(
                {
                    "source": src_label,
                    "source_type": "process",
                    "source_node": self._process_node(job.host, src_label),
                    "target": f"{job.host}:{pid}",
                    "target_type": "process_instance",
                    "target_node": self._process_instance_node(job.host, pid),
                    "edge_type": "memory_process",
                    "host": job.host,
                    "metadata": proc,
                }
            )
        return edges

    def _build_malfind_edges(self, job: MemoryJob, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        for hit in hits:
            pid = hit.get("pid")
            proc = hit.get("process")
            edges.append(
                {
                    "source": proc,
                    "source_type": "process",
                    "source_node": self._process_node(job.host, proc),
                    "target": f"{job.host}:{pid}",
                    "target_type": "process_instance",
                    "target_node": self._process_instance_node(job.host, pid),
                    "edge_type": "memory_injection",
                    "host": job.host,
                    "metadata": hit,
                }
            )
        return edges

    def _build_dll_edges(self, job: MemoryJob, dlls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        for dll in dlls:
            pid = dll.get("pid")
            name = dll.get("name")
            edges.append(
                {
                    "source": name,
                    "source_type": "dll",
                    "source_node": self._dll_node(name),
                    "target": f"{job.host}:{pid}",
                    "target_type": "process_instance",
                    "target_node": self._process_instance_node(job.host, pid),
                    "edge_type": "memory_dll",
                    "host": job.host,
                    "metadata": dll,
                }
            )
        return edges

    def _collected_artifacts(self, results: Dict[str, Any]) -> List[str]:
        artifacts = []
        for key in ("windows.pslist", "windows.dlllist", "windows.malfind"):
            if key in results and results[key]:
                artifacts.append(key.split(".")[-1])
        return artifacts

    @staticmethod
    def _merge_dread(
        dread: Dict[str, float],
        damage: float,
        repro: float,
        exploit: float,
        affected_users: float,
        discoverability: float,
    ) -> Dict[str, float]:
        dread = dict(dread or {})
        dread["damage"] = max(dread.get("damage", 0.0), damage)
        dread["repro"] = max(dread.get("repro", 0.0), repro)
        dread["exploit"] = max(dread.get("exploit", 0.0), exploit)
        dread["affected_users"] = max(dread.get("affected_users", 0.0), affected_users)
        dread["discoverability"] = max(dread.get("discoverability", 0.0), discoverability)
        return dread

    # ------------------------------------------------------------------ graph + node helpers
    def _discover_graph_sink(self) -> Any | None:
        if UNIFIED_GRAPH is not None:
            return UNIFIED_GRAPH
        if GLOBAL_HOPGRAPH is not None:
            return GLOBAL_HOPGRAPH
        return None

    def _emit_graph_edges(self, job: MemoryJob, edges: List[Dict[str, Any]], factors: List[str], mitre_tags: List[str]) -> None:
        sink = self.graph_sink
        if not sink or not edges:
            return
        for edge in edges:
            src_node = edge.get("source_node") or self._canonical_node(edge.get("source"), edge.get("source_type"), job.host)
            dst_node = edge.get("target_node") or self._canonical_node(edge.get("target"), edge.get("target_type"), job.host)
            if not src_node or not dst_node:
                continue
            attrs = {
                "host": job.host,
                "case_id": job.case_id,
                "source_label": edge.get("source"),
                "target_label": edge.get("target"),
                "edge_metadata": edge.get("metadata"),
                "factors": factors,
                "mitre": mitre_tags,
                "requested_plugins": job.requested_plugins,
            }
            try:
                sink.add_edge(
                    src_node,
                    dst_node,
                    edge.get("edge_type", "memory"),
                    source="memory_pipeline",
                    attrs=attrs,
                )
            except Exception:
                continue

    def _canonical_node(self, value: Any, node_type: Optional[str], host: str) -> Optional[str]:
        if not value:
            return None
        node_type = (node_type or "").lower()
        if node_type == "process":
            return self._process_node(host, value)
        if node_type in {"process_instance", "pid"}:
            return self._process_instance_node(host, value)
        if node_type in {"dll", "module"}:
            return self._dll_node(value)
        if node_type in {"network", "ip"}:
            return self._network_node(str(value))
        if node_type == "host":
            return f"host:{host}"
        return None

    def _persist_job_summary(self, job: MemoryJob, analysis: Dict[str, Any]) -> None:
        if record_memory_job is None:
            return
        try:
            edge_list = analysis.get("hopgraph_edges") or []
            edge_types = {
                edge.get("edge_type")
                for edge in edge_list
                if isinstance(edge, dict) and edge.get("edge_type")
            }
            payload = {
                "job_id": job.job_id,
                "host": job.host,
                "case_id": job.case_id or "",
                "tenant_id": job.tenant_id or "",
                "created_at": job.created_at,
                "updated_at": job.updated_at,
                "factors": list(job.factors or []),
                "kill_chain": analysis.get("kill_chain") or [],
                "mitre": analysis.get("mitre") or [],
                "threat_model": analysis.get("threat_model") or {},
                "requested_artifacts": analysis.get("requested_artifacts") or [],
                "artifact_url": f"/api/v1/forensics/memory/{job.job_id}",
                "hopgraph_edge_stats": {
                    "count": len(edge_list),
                    "types": sorted(t for t in edge_types if t)[:6],
                    "sample": edge_list[:3],
                },
                "timeline": analysis.get("timeline") or [],
                "sandbox": analysis.get("sandbox") or {},
                "registry_timeline": (analysis.get("registry") or {}).get("timeline") or [],
                "malware_family": analysis.get("malware_family") or {},
                "encryption": job.metadata.get("encryption") or {},
            }
            record_memory_job(payload)
        except Exception:
            LOGGER.debug("memory_job_persist_failed id=%s", job.job_id, exc_info=True)

    def _maybe_run_sandbox(self, job: MemoryJob, analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        runner = self.sandbox_runner
        if not runner:
            return None
        should_run = bool(job.metadata.get("run_sandbox")) or os.getenv("MEMORY_SANDBOX_DEFAULT", "0").lower() in {"1", "true", "yes"}
        if not should_run:
            return None
        try:
            return runner.submit(job, analysis)
        except Exception:
            LOGGER.warning("memory_sandbox_submit_failed id=%s", job.job_id, exc_info=True)
            return None

    def _rotate_old_dumps(self) -> None:
        ttl = getattr(self, "dump_ttl_seconds", None)
        if not ttl or ttl <= 0:
            return
        cutoff = time.time() - ttl
        try:
            for raw in self.storage_dir.rglob("*.raw"):
                try:
                    if raw.stat().st_mtime < cutoff:
                        raw.unlink(missing_ok=True)  # type: ignore[arg-type]
                        dec = raw.with_suffix(".dec")
                        if dec.exists():
                            dec.unlink(missing_ok=True)  # type: ignore[arg-type]
                        enc_meta = raw.with_suffix(".json")
                        if enc_meta.exists():
                            enc_meta.unlink(missing_ok=True)  # type: ignore[arg-type]
                        self._log_ttl_deletion(raw)
                except Exception:
                    continue
        except Exception:
            LOGGER.debug("memory_dump_rotation_failed", exc_info=True)

    def _record_acquisition_event(self, attestation_id: str, event: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        guide = self.acquisition_guide
        if not guide:
            return
        try:
            guide.record_event(attestation_id, event=event, metadata=metadata)
        except KeyError:
            LOGGER.debug("memory_acquisition_event_skip attestation=%s missing", attestation_id)
        except Exception:
            LOGGER.warning("memory_acquisition_event_failed attestation=%s", attestation_id, exc_info=True)

    def _analyze_registry(self, results: Dict[str, Any], job: MemoryJob) -> Optional[Dict[str, Any]]:
        if not self.registry_forensics:
            return None
        try:
            metadata = {"host": job.host, "case_id": job.case_id, "captured_at": job.created_at}
            return self.registry_forensics.analyze(results, metadata) or None
        except Exception:
            LOGGER.debug("registry_forensics_failed id=%s", job.job_id, exc_info=True)
            return None

    def _classify_malware(self, results: Dict[str, Any], sandbox_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        if not self.malware_classifier:
            return None
        try:
            return self.malware_classifier.classify(
                processes=results.get("windows.pslist") or results.get("pslist") or [],
                dlls=results.get("windows.dlllist") or results.get("dlllist") or [],
                netscan=results.get("windows.netscan") or results.get("netscan") or [],
                sandbox_submissions=(sandbox_info or {}).get("submissions"),
            )
        except Exception:
            LOGGER.debug("malware_classification_failed", exc_info=True)
            return None

    def _emit_perf_artifact(self, job: MemoryJob, analysis: Dict[str, Any]) -> None:
        try:
            path = self.perf_dir / "memory"
            path.mkdir(parents=True, exist_ok=True)
            out = path / f"{job.job_id}.json"
            payload = {
                "job_id": job.job_id,
                "host": job.host,
                "tenant_id": job.tenant_id,
                "factors": analysis.get("factors"),
                "timeline": analysis.get("timeline"),
                "registry": analysis.get("registry"),
                "malware_family": analysis.get("malware_family"),
            }
            out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _log_ttl_deletion(self, raw: Path) -> None:
        log_path = self.storage_dir / "ttl_log.jsonl"
        record = {"ts": time.time(), "path": str(raw)}
        try:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def _process_node(self, host: str, name: Any) -> Optional[str]:
        if not name:
            return None
        label = str(name).strip().lower()
        if not label:
            return None
        return f"process:{host}:{label}"

    def _process_instance_node(self, host: str, pid: Any) -> Optional[str]:
        if pid is None or pid == "":
            return None
        return f"process_instance:{host}:{pid}"

    def _dll_node(self, name: Any) -> Optional[str]:
        if not name:
            return None
        label = str(name).strip().lower()
        if not label:
            return None
        return f"dll:{label}"

    def _network_node(self, addr: str) -> Optional[str]:
        if not addr:
            return None
        label = str(addr).strip().lower()
        if not label:
            return None
        return f"network:{label}"


__all__ = ["MemoryPipeline", "MemoryJob"]
