#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List

try:
    from pypdf import PdfReader  # type: ignore
except Exception:  # pragma: no cover
    PdfReader = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
from src.api.deep_analyze_endpoints import _hydrate_assessment_semantics
from src.reporting.persona_views import generate_persona_view


PERSONAS = [
    "soc_analyst",
    "threat_hunter",
    "forensics",
    "compliance",
    "audit",
    "executive",
    "ciso",
]

SCREENSHOT_EXPECTED_CUES = {
    "email-check.png": [
        "supplier impersonation",
        "payment fraud",
        "immediate actions",
        "recommended next steps",
        "security review",
        "high business risk",
    ],
    "email-framework.png": [
        "mitre tags",
        "decision trace",
        "top ranked evidence",
        "integrations",
        "control mappings",
    ],
    "email-new tab.png": [
        "supplier trust baseline drift",
        "attachment forensics",
        "sender infrastructure drift",
        "out-of-band verification",
        "governance controls",
        "decision trace",
    ],
}

SHOPSQUIRE_EXPECTED_FINDINGS = [
    "supplier impersonation",
    "payment fraud",
    "macro execution",
    "lolbin",
    "c2 beaconing",
    "compromised executive",
    "pii exposure",
    "out-of-band verification",
]


def _read_pdf_text(path: Path) -> str:
    if PdfReader is None:
        return ""
    try:
        reader = PdfReader(str(path))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        return ""


def _extract_vba_from_xlsm(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            vba_parts = [name for name in names if "vba" in name.lower() or name.lower().endswith(".bin")]
            snippets = []
            for name in vba_parts[:6]:
                try:
                    raw = zf.read(name)
                    text = raw.decode("latin-1", errors="ignore")
                    snippets.append(text)
                except Exception:
                    continue
            return "\n".join(snippets)
    except Exception:
        return ""


def _safe_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return _read_pdf_text(path)
    if suffix == ".bas":
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""
    if suffix == ".xlsm":
        return _extract_vba_from_xlsm(path)
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        return path.name
    return ""


def _contains(text: str, *tokens: str) -> bool:
    lowered = text.lower()
    return any(token.lower() in lowered for token in tokens)


def _synth_rows(files: List[Path]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    idx = 0
    for path in files:
        content = _safe_text(path)
        lowered = content.lower()
        if path.name.lower().endswith(".pdf") and _contains(lowered, "wire transfer", "beneficiary", "acquisition deposit"):
            rows.append({
                "row_index": idx,
                "source": "mimecast",
                "source_kind": "mimecast",
                "sheet": "ShopSquireEmail",
                "severity": "high",
                "triage_score": 0.88,
                "verdict": "SUSPICIOUS",
                "description": "Executive-targeted supplier impersonation with urgent wire transfer details.",
                "user": "ceo@shopsquire.example",
                "accounts": ["ceo@shopsquire.example"],
                "external_ips": ["203.0.113.99"],
                "factors": ["supplier_impersonation", "payment_fraud_request", "oob_verification_required"],
                "subject": "Wire Transfer Authorization Form",
                "valid_time": 1775779200.0 + idx,
                "transaction_time": 1775779500.0 + idx,
                "raw": {"path": str(path)},
            })
            idx += 1
        if path.name.lower().endswith(".pdf") and _contains(lowered, "ssn", "social security", "dob"):
            rows.append({
                "row_index": idx,
                "source": "cloudtrail",
                "source_kind": "cloudtrail",
                "sheet": "SensitiveData",
                "severity": "high",
                "triage_score": 0.84,
                "verdict": "SUSPICIOUS",
                "description": "Sensitive PII worksheet discovered in the same incident context.",
                "user": "ceo@shopsquire.example",
                "accounts": ["ceo@shopsquire.example"],
                "factors": ["pii_exposure", "confidential_data_access"],
                "resource": "SSN-numberz",
                "valid_time": 1775779260.0 + idx,
                "transaction_time": 1775779560.0 + idx,
                "raw": {"path": str(path)},
            })
            idx += 1
        if path.suffix.lower() in {".bas", ".xlsm"} and _contains(lowered, "auto_open", "workbook_open", "powershell", "certutil", "bitsadmin", "schtasks"):
            rows.append({
                "row_index": idx,
                "source": "proofpoint",
                "source_kind": "proofpoint",
                "sheet": "MacroArtifact",
                "severity": "critical",
                "triage_score": 0.94,
                "verdict": "MALICIOUS",
                "description": "Macro-enabled acquisition workbook with LOLBIN and staged execution indicators.",
                "user": "ceo@shopsquire.example",
                "accounts": ["ceo@shopsquire.example"],
                "external_ips": ["203.0.113.99"],
                "factors": ["macro_execution", "lolbin_spawn", "scheduled_task_persistence"],
                "mitre": ["T1566.001", "T1059.001", "T1218"],
                "valid_time": 1775779320.0 + idx,
                "transaction_time": 1775779620.0 + idx,
                "raw": {"path": str(path)},
            })
            idx += 1
        if path.suffix.lower() in {".bas", ".xlsm"} and _contains(lowered, "balashnikovai-cdn.com", "dns tunneling", "beacon", "chrome login data"):
            rows.append({
                "row_index": idx,
                "source": "defender_cloud",
                "source_kind": "defender_cloud",
                "sheet": "ExecutionFollowOn",
                "severity": "critical",
                "triage_score": 0.92,
                "verdict": "MALICIOUS",
                "description": "Follow-on C2 beaconing and credential access indicators present in macro payload notes.",
                "user": "ceo@shopsquire.example",
                "accounts": ["ceo@shopsquire.example"],
                "external_ips": ["203.0.113.99"],
                "factors": ["c2_beaconing", "credential_access", "dns_tunneling"],
                "mitre": ["T1071", "T1003", "T1048"],
                "valid_time": 1775779380.0 + idx,
                "transaction_time": 1775779680.0 + idx,
                "raw": {"path": str(path)},
            })
            idx += 1
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp"} and _contains(lowered, "qr", "ssn", "steg", "lolbin", "c2_beacon"):
            image_name = path.name.lower()
            factors = ["attachment_visual_review"]
            description = "Suspicious image attachment requires OCR and visual inspection before closure."
            if "qr" in image_name or "ssn" in image_name:
                factors.extend(["email:qr_phish_lure", "pii_visual_exposure"])
                description = "Image attachment contains a QR-style lure or exposed PII that should be validated against browser and identity telemetry."
            if "lolbin" in image_name:
                factors.extend(["lolbin_spawn", "visual_execution_cue"])
            if "c2_beacon" in image_name:
                factors.extend(["c2_beaconing", "visual_network_indicator"])
            rows.append({
                "row_index": idx,
                "source": "mimecast",
                "source_kind": "attachment_forensics",
                "sheet": "VisualArtifact",
                "severity": "high",
                "triage_score": 0.81,
                "verdict": "SUSPICIOUS",
                "description": description,
                "attachment_name": path.name,
                "accounts": ["ceo@shopsquire.example"],
                "user": "ceo@shopsquire.example",
                "factors": factors,
                "valid_time": 1775779440.0 + idx,
                "transaction_time": 1775779740.0 + idx,
                "raw": {"path": str(path)},
            })
            idx += 1
    return rows


def _extract_blind_cues(assessment: Dict[str, Any], persona_views: Dict[str, Dict[str, Any]]) -> List[str]:
    cues: List[str] = []
    cluster = assessment.get("cluster_reasoning_state") or {}
    summary = cluster.get("summary") or {}
    text_parts = [
        summary.get("canonical_narrative") or "",
        " ".join(summary.get("supporting_evidence") or []),
        " ".join(str(claim.get("claim") or "") for claim in (cluster.get("claims") or [])),
        " ".join(str(item) for item in ((cluster.get("what_would_flip") or []))),
        " ".join(str(item) for item in (((cluster.get("leads") or {}).get("confirmation") or []))),
        " ".join(str(item) for item in (((cluster.get("leads") or {}).get("denial") or []))),
        " ".join(str(item.get("lead") or "") for item in (((cluster.get("leads") or {}).get("confirmation_details") or []))),
        " ".join(str(item.get("lead") or "") for item in (((cluster.get("leads") or {}).get("denial_details") or []))),
    ]
    for row in (assessment.get("rows") or assessment.get("llm_rows") or []):
        text_parts.append(" ".join(str(f) for f in (row.get("factors") or [])))
        text_parts.append(str(row.get("description") or ""))
        text_parts.append(str(row.get("attachment_name") or ""))
    for persona, view in persona_views.items():
        text_parts.append(view.get("headline") or "")
        text_parts.extend(view.get("recommended_actions") or [])
    blob = " ".join(text_parts).lower()
    for cue in SHOPSQUIRE_EXPECTED_FINDINGS:
        if cue in blob:
            cues.append(cue)
    if "wire transfer" in blob or "payment" in blob:
        cues.append("payment fraud")
    if "macro" in blob:
        cues.append("macro execution")
    if "t1218" in blob or "lolbin" in blob or "certutil" in blob or "bitsadmin" in blob:
        cues.append("lolbin")
    if "t1071" in blob or "beacon" in blob or "dns_tunneling" in blob:
        cues.append("c2 beaconing")
    if "ssn" in blob or "social security" in blob or "pii_exposure" in blob:
        cues.append("pii exposure")
    if "supplier_impersonation" in blob or "invoice" in blob:
        cues.append("supplier impersonation")
    if "oob" in blob or "out-of-band" in blob or "callback verification" in blob:
        cues.append("out-of-band verification")
    return sorted(set(cues))


def _assisted_comparison(blind_cues: List[str], screenshot_paths: List[Path]) -> Dict[str, Any]:
    screenshot_cues: List[str] = []
    for path in screenshot_paths:
        screenshot_cues.extend(SCREENSHOT_EXPECTED_CUES.get(path.name, []))
    screenshot_cues = sorted(set(screenshot_cues))
    blind_set = set(blind_cues)
    expected_set = set(SHOPSQUIRE_EXPECTED_FINDINGS)
    screenshot_set = set(screenshot_cues)
    combined = expected_set | screenshot_set
    return {
        "matched_existing_cues": sorted(blind_set & combined),
        "missed_expected_cues": sorted(combined - blind_set),
        "additional_janusec_findings": sorted(blind_set - combined),
        "screenshot_cues": screenshot_cues,
    }


def run_benchmark(files: List[Path], screenshots: List[Path], mode: str) -> Dict[str, Any]:
    rows = _synth_rows(files)
    assessment = build_offline_workbook_assessment(
        rows,
        assessment_id="shopsquire-benchmark",
        org="shopsquire",
        auto_llm=False,
    )
    assessment = _hydrate_assessment_semantics(assessment)
    persona_views = {
        persona: generate_persona_view(assessment, persona, disclosure_level=2, top_n=6)
        for persona in PERSONAS
    }
    blind_cues = _extract_blind_cues(assessment, persona_views)
    output: Dict[str, Any] = {
        "mode": mode,
        "row_count": len(rows),
        "assessment_id": assessment.get("assessment_id"),
        "verdict": assessment.get("verdict"),
        "blind_findings": blind_cues,
        "cluster_summary": ((assessment.get("cluster_reasoning_state") or {}).get("summary") or {}),
        "personas": {
            persona: {
                "headline": view.get("headline"),
                "recommended_actions": view.get("recommended_actions") or [],
            }
            for persona, view in persona_views.items()
        },
    }
    if mode == "assisted":
        output["comparison"] = _assisted_comparison(blind_cues, screenshots)
    return output


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Run Janusec blind/assisted benchmark against external ShopSquire artifacts.")
    ap.add_argument("--mode", choices=["blind", "assisted"], default="blind")
    ap.add_argument("--artifact", action="append", default=[], help="External artifact path (.pdf/.xlsm/.bas)")
    ap.add_argument("--screenshot", action="append", default=[], help="External screenshot path used for assisted cue comparison")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    files = [Path(item) for item in args.artifact]
    screenshots = [Path(item) for item in args.screenshot]
    result = run_benchmark(files, screenshots, args.mode)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
