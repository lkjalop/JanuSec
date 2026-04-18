"""EXPAND engine — Phase 3 P1 backend.

Builds entity-scoped investigation expansions for investigate task cards.

Public API
----------
extract_task_entity_slice(task, investigate_record, assessment)
    -> dict  (rows, entity_fields, check_results)

build_expand_prompt(task_text, entity_slice, persona)
    -> str

call_expand_llm(prompt, llm_client, persona, max_tokens)
    -> dict  (subtasks, iocs, confidence, summary)

get_expand_cache_path(assessment_id, task_id)
    -> str | None

load_expand_cache(assessment_id, task_id)
    -> dict | None

save_expand_cache(assessment_id, task_id, result)
    -> None
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from src.analysis.expand_checks import (
    extract_entity_fields,
    run_all_checks,
)

# ── Constants ────────────────────────────────────────────────────────────────

EXPAND_CACHE_DIR = os.getenv("EXPAND_CACHE_DIR", os.path.join(os.path.dirname(__file__), "../../data/expand_cache"))
EXPAND_MAX_TOKENS = min(int(os.getenv("EXPAND_MAX_TOKENS", "700")), 1500)

_PERSONA_INSTRUCTIONS: Dict[str, str] = {
    "soc": (
        "You are a Tier-2 SOC analyst performing deep-dive investigation. "
        "Focus on IOCs, lateral movement paths, and MITRE ATT&CK techniques. "
        "Be specific about artifacts and evidence."
    ),
    "ciso": (
        "You are a CISO briefing an executive. "
        "Focus on business impact, blast radius, and executive risk summary. "
        "Keep technical detail minimal — lead with business consequence."
    ),
    "compliance": (
        "You are a compliance officer reviewing for regulatory exposure. "
        "Focus on data access events, PII handling, regulatory frameworks (GDPR, HIPAA, PCI-DSS). "
        "Identify which controls may have failed."
    ),
    "hunter": (
        "You are a threat hunter. "
        "Focus on TTPs, evasion techniques, and hunting hypotheses for this entity. "
        "Suggest specific queries or hunt pivots."
    ),
    "ir": (
        "You are an incident responder. "
        "Focus on containment actions, remediation steps, and evidence preservation. "
        "Prioritize timeline reconstruction and root-cause identification."
    ),
    "forensics": (
        "You are a digital forensics analyst. Focus on volatile evidence "
        "preservation, artifact collection order (memory → disk → network), "
        "hashing, and chain of custody. Every recommendation must state what "
        "artifact to collect, from which host, and with which tool."
    ),
    "mssp": (
        "You are an MSSP tier-2 lead. Focus on customer SLA clocks, "
        "tenant isolation, the customer-facing status update, and what "
        "needs to go in the escalation package to the customer's security team."
    ),
}

_SCOPE_GUARD = (
    "Respond ONLY about the specific task and entities provided. "
    "Do not reference events or entities outside the evidence slice. "
    "Stay within the provided context window."
)

_OUTPUT_SCHEMA = """
Respond with a JSON object matching this schema exactly:
{
  "summary": "<1-2 sentence summary describing the attack chain>",
  "confidence": <0.0-1.0>,
  "subtasks": [
    {
      "id": "<short-id>",
      "action": "<specific verb phrase — what to do>",
      "entity": "<entity involved — user, IP, host, or domain>",
      "priority": "high|medium|low",
      "success_criteria": "<one sentence — how you know this subtask is complete>",
      "verification": "<tool or query to run to verify — e.g. KQL, Splunk, EDR query>"
    },
    ...
  ],
  "iocs": [
    {"type": "ip|hash|domain|user|host|process", "value": "<value>", "context": "<why flagged>"},
    ...
  ],
  "mitre_techniques": ["T1xxx", ...],
  "next_pivot": "<single recommended next investigation step>"
}
IMPORTANT: Every subtask MUST include success_criteria and verification. Emit JSON only — no markdown, no prose outside the JSON.
"""


# ── Entity slice extraction ──────────────────────────────────────────────────

def _text_mentions_entity(text: str, entity: str) -> bool:
    """Case-insensitive whole-word-ish entity presence check."""
    if not entity or not text:
        return False
    return entity.lower() in text.lower()


# ── Phase B: Cluster-aware row selection ─────────────────────────────────────

_STATE_PRIORITY = {
    "confirmed_malicious": 0,
    "needs_investigation": 1,
    "script_kiddie":       2,
    "reviewed_benign":     3,
}

_SEVERITY_PRIORITY = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}


def _row_risk_score(row: Dict) -> int:
    """Lower = higher priority. Combines review_state, severity, and threat_confidence."""
    state = str(row.get("review_state", "") or "")
    state_pri = 4
    for key, pri in _STATE_PRIORITY.items():
        if state.startswith(key):
            state_pri = pri
            break

    sev = str(row.get("severity", "") or "").lower()
    sev_pri = _SEVERITY_PRIORITY.get(sev, 4)

    # Numeric override: threat_confidence or risk_score
    num_pri = state_pri
    for num_key in ("risk_score", "threat_confidence"):
        try:
            val = float(row.get(num_key, 0) or 0)
            if val >= 90:   num_pri = min(num_pri, 0)
            elif val >= 50: num_pri = min(num_pri, 1)
            elif val >= 20: num_pri = min(num_pri, 2)
        except Exception:
            pass

    return min(state_pri, num_pri, sev_pri)


def cluster_aware_row_select(
    rows: List[Dict],
    k_clusters: int = 5,
    n_per_cluster: int = 6,
    hard_cap: int = 30,
) -> List[Dict]:
    """Phase B: cluster-first row selection.

    Problem: a script_kiddie spray of 847 events at low priority would consume
    all 30 global slots under naive severity sort, burying the PHANTOM-MERIDIAN
    C2 chain and Harbourside BEC events.

    Solution:
      1. Group rows by dominant entity (src_ip → user → host → "unknown")
      2. Score each cluster by its highest-priority row
      3. Select top-K clusters
      4. Take top-N rows per cluster (by within-cluster severity)
      5. Total rows ≤ K × N ≤ hard_cap

    Result: PHANTOM-MERIDIAN (5 confirmed_malicious) gets 5 rows,
    script_kiddie spray gets 1 representative row.
    """
    from collections import defaultdict

    if not rows:
        return []

    # Assign each row to a cluster by dominant entity
    clusters: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        # Entity priority: src_ip beats user beats host beats dst_ip
        key = (
            r.get("src_ip") or r.get("source_ip")
            or r.get("user") or r.get("username") or r.get("email")
            or r.get("host") or r.get("hostname")
            or r.get("dst_ip")
            or "unknown"
        )
        clusters[str(key)].append(r)

    # Score each cluster by its best row (lowest _row_risk_score = highest priority)
    def _cluster_score(cluster_rows: List[Dict]) -> tuple:
        best_risk = min(_row_risk_score(r) for r in cluster_rows)
        # Secondary: larger clusters of same priority rank higher (more evidence)
        return (best_risk, -len(cluster_rows))

    top_clusters = sorted(clusters.values(), key=_cluster_score)[:k_clusters]

    result: List[Dict] = []
    for cluster_rows in top_clusters:
        # Within each cluster: sort by row risk, then timestamp
        sorted_cluster = sorted(
            cluster_rows,
            key=lambda r: (_row_risk_score(r), str(r.get("ts", "") or "")),
        )
        result.extend(sorted_cluster[:n_per_cluster])

    return result[:hard_cap]


def extract_task_entity_slice(
    task_text: str,
    investigate_record: Dict[str, Any],
    assessment: Dict[str, Any],
) -> Dict[str, Any]:
    """Extract the rows most relevant to a given task description.

    Strategy:
    1. Parse entity fields from ALL assessment rows.
    2. Find which canonical entities (users, ips, hosts) appear in task_text.
    3. Collect rows that contain those entities.
    4. Fallback to evidence_table rows from the investigate record if nothing matched.
    5. Run OPT-1 + OPT-2 checks on the slice.

    Returns a dict with keys:
      rows         — list of matching row dicts
      entity_fields — OPT-1 entity resolution on slice
      check_results — list of CheckResult.to_dict() from OPT-2
      matched_entities — which entities drove the slice
    """
    all_rows: List[Dict] = (
        assessment.get("llm_rows") or assessment.get("rows") or []
    )

    # OPT-1 on full row set to find canonical entities
    all_entities = extract_entity_fields(all_rows)

    # Which entities appear in task_text?
    matched: Dict[str, List[str]] = {}
    for category, values in all_entities.items():
        hits = [v for v in values if _text_mentions_entity(task_text, v)]
        if hits:
            matched[category] = hits

    # Collect rows that contain at least one matched entity
    slice_rows: List[Dict] = []
    seen_indices: set = set()

    if matched:
        all_matched_values = {v for vals in matched.values() for v in vals}
        _IP_KEYS = ("src_ip", "source_ip", "ip", "client_ip", "remote_ip", "dst_ip", "dest_ip")
        _USER_KEYS = ("user", "username", "user_name", "userId", "user_id", "upn", "email")
        _HOST_KEYS = ("host", "hostname", "device", "computer", "endpoint")
        _DOMAIN_KEYS = ("dns_query", "sni", "domain", "fqdn", "url")

        for row in all_rows:
            row_vals = set()
            for k in _USER_KEYS + _IP_KEYS + _HOST_KEYS + _DOMAIN_KEYS:
                v = row.get(k)
                if v and isinstance(v, str):
                    row_vals.add(v.strip())
            # Also check for partial domain matches (e.g. task mentions "update-cdn-svc.net"
            # and row has dns_query "c2-cmd.update-cdn-svc.net")
            if not (row_vals & all_matched_values):
                for matched_val in all_matched_values:
                    if any(matched_val in str(row.get(k, "")) for k in _DOMAIN_KEYS):
                        row_vals.add(matched_val)
                        break
            if row_vals & all_matched_values:
                idx = row.get("row_index")
                key = id(row) if idx is None else idx
                if key not in seen_indices:
                    seen_indices.add(key)
                    slice_rows.append(row)

    # Fallback: use evidence_table rows from investigate record
    if not slice_rows:
        evidence_table = investigate_record.get("evidence_table") or []
        evidence_indices = {
            e.get("row_index") for e in evidence_table if e.get("row_index") is not None
        }
        slice_rows = [r for r in all_rows if r.get("row_index") in evidence_indices]

    # Cluster-aware selection — replaces naive global top-30 cap
    slice_rows = cluster_aware_row_select(slice_rows, k_clusters=5, n_per_cluster=6)

    # OPT-1 + OPT-2 on the slice
    entity_fields = extract_entity_fields(slice_rows)
    check_results = [cr.to_dict() for cr in run_all_checks(slice_rows)]

    return {
        "rows": slice_rows,
        "entity_fields": entity_fields,
        "check_results": check_results,
        "matched_entities": matched,
    }


# ── Prompt builder ────────────────────────────────────────────────────────────

def _format_rows_for_prompt(rows: List[Dict], max_rows: int = 15) -> str:
    """Compact row serialisation for prompt injection."""
    parts = []
    for i, row in enumerate(rows[:max_rows]):
        # Include the most diagnostic fields only
        snippet = {
            k: row[k]
            for k in (
                "row_index", "ts", "timestamp", "event_type", "user", "host",
                "process", "command_line", "src_ip", "mitre_technique",
                "severity", "verdict", "ml_score",
            )
            if row.get(k) is not None
        }
        parts.append(f"  [{i}] {json.dumps(snippet, default=str)}")
    return "\n".join(parts)


def build_expand_prompt(
    task_text: str,
    entity_slice: Dict[str, Any],
    persona: str = "soc",
) -> str:
    """Build the expand prompt for the LLM.

    Returns the full prompt string.
    """
    persona_instructions = _PERSONA_INSTRUCTIONS.get(persona, _PERSONA_INSTRUCTIONS["soc"])

    rows = entity_slice.get("rows") or []
    entity_fields = entity_slice.get("entity_fields") or {}
    check_results = entity_slice.get("check_results") or []

    # Summarise triggered checks
    triggered = [c for c in check_results if c.get("triggered")]
    check_block = ""
    if triggered:
        check_lines = [
            f"  [{c['check_id']}] {c['label']}: {c['detail'][:200]}"
            for c in triggered
        ]
        check_block = "Automated checks triggered:\n" + "\n".join(check_lines)

    entity_block = "Entities in scope:\n" + "\n".join(
        f"  {cat}: {', '.join(vals[:5])}"
        for cat, vals in entity_fields.items()
        if vals
    )

    rows_block = f"Evidence rows ({len(rows)} total, showing up to 15):\n" + _format_rows_for_prompt(rows)

    prompt = f"""{persona_instructions}

{_SCOPE_GUARD}

Task to expand:
  {task_text}

{entity_block}

{check_block}

{rows_block}

{_OUTPUT_SCHEMA}"""

    return prompt.strip()


# ── LLM call ─────────────────────────────────────────────────────────────────

_PERSONA_FALLBACK_TASKS: Dict[str, List[Dict[str, Any]]] = {
    "soc": [
        {"id": "soc-1", "action": "Disable sessions for affected accounts", "priority": "high",
         "success_criteria": "No active sessions; confirm in Okta/AAD session dashboard",
         "verification": "Okta Admin > Sessions: zero active sessions for entity"},
        {"id": "soc-2", "action": "Revoke OAuth/refresh tokens for affected principals", "priority": "high",
         "success_criteria": "All refresh tokens invalidated; next API call returns 401",
         "verification": "Graph API: GET /users/{id}/oauth2PermissionGrants returns empty"},
        {"id": "soc-3", "action": "Block identified external IPs at egress firewall", "priority": "high",
         "success_criteria": "No outbound traffic to attacker IPs in next 15-min window",
         "verification": "Firewall deny log confirms block; zero hits in SIEM for blocked IPs"},
        {"id": "soc-4", "action": "Query blast radius: same source IP → other accounts in last 24h", "priority": "medium",
         "success_criteria": "All affected accounts identified and remediated",
         "verification": "SIEM query returns zero unreviewed accounts matching same src_ip"},
    ],
    "hunter": [
        {"id": "hunter-1", "action": "Pivot on source IP across all SIEM indexes for 72h window", "priority": "high",
         "success_criteria": "Full lateral movement chain mapped; no unknown hosts",
         "verification": "HopGraph shows complete path with no dangling nodes"},
        {"id": "hunter-2", "action": "IoC expansion: WHOIS, passive DNS, TLS JA3 fingerprint", "priority": "medium",
         "success_criteria": "All related infrastructure identified and blocked",
         "verification": "Threat intel feed updated; all pivot IPs appear in blocklist"},
        {"id": "hunter-3", "action": "Check SMB/RDP/WinRM auth from attacker IP across domain", "priority": "medium",
         "success_criteria": "No successful lateral auth from attacker source",
         "verification": "Windows Security Event 4624 — zero successes from attacker IP range"},
    ],
    "ciso": [
        {"id": "ciso-1", "action": "Classify incident severity per internal matrix (Sev-1/2/3)", "priority": "high",
         "success_criteria": "Severity documented, IR war room activated if Sev-1",
         "verification": "INC ticket severity field set; stakeholders notified per runbook"},
        {"id": "ciso-2", "action": "Identify business owner of affected data/system; notify", "priority": "high",
         "success_criteria": "Owner acknowledged; data sensitivity confirmed",
         "verification": "Confirmation email from owner received within 1 business hour"},
        {"id": "ciso-3", "action": "Decide on regulatory/legal notification clock start", "priority": "high",
         "success_criteria": "Legal counsel briefed; notification obligation documented",
         "verification": "Notification decision recorded in INC with timestamp"},
    ],
    "forensics": [
        {"id": "fx-1", "action": "Capture volatile memory from affected hosts BEFORE containment reboot", "priority": "high",
         "success_criteria": "RAM image acquired, SHA-256 hash recorded, chain of custody started",
         "verification": "WinPMEM/LiME dump file present with hash and collector signature"},
        {"id": "fx-2", "action": "Hash and preserve $MFT, event logs, prefetch, registry hives", "priority": "high",
         "success_criteria": "All artifacts hashed, copied to evidence store, original untouched",
         "verification": "Evidence log entry with collection time, examiner, hash for each artifact"},
        {"id": "fx-3", "action": "Record collection order + examiner + timestamp for chain of custody", "priority": "high",
         "success_criteria": "Chain-of-custody form signed; admissible for legal proceedings",
         "verification": "CoC document filed in case management system"},
    ],
    "compliance": [
        {"id": "cmp-1", "action": "Map event to control IDs: ISO 27001 A.16.1, NIST CSF RS.RP, Essential Eight ML1-4", "priority": "high",
         "success_criteria": "Control failure documented; gap remediation ticket raised",
         "verification": "GRC system shows updated control assessment with evidence"},
        {"id": "cmp-2", "action": "Start notification clock: NDB 30d, GDPR 72h, APRA CPS 234 72h", "priority": "high",
         "success_criteria": "Regulator notified within deadline or exemption documented",
         "verification": "Notification submission reference number obtained"},
        {"id": "cmp-3", "action": "Capture retention evidence for audit trail", "priority": "medium",
         "success_criteria": "All evidence retained per policy; destruction moratorium active",
         "verification": "Legal hold order confirmed in evidence management system"},
    ],
    "mssp": [
        {"id": "mssp-1", "action": "Send customer T+0 status update per SLA", "priority": "high",
         "success_criteria": "Customer acknowledged; SLA clock recorded in ticketing system",
         "verification": "Customer reply received; SLA timer started in PSA tool"},
        {"id": "mssp-2", "action": "Prepare escalation package: timeline, IoCs, recommended actions", "priority": "high",
         "success_criteria": "Package delivered to customer CISO; actions acknowledged",
         "verification": "Secure file transfer confirmed; customer CISO sign-off obtained"},
        {"id": "mssp-3", "action": "Confirm tenant isolation — no cross-customer data exposure", "priority": "high",
         "success_criteria": "Blast radius confirmed as single-tenant; no cross-contamination",
         "verification": "Tenant isolation audit log reviewed; zero shared resource hits"},
    ],
    "ir": [
        {"id": "ir-1", "action": "Establish incident commander + scribe; start timeline", "priority": "high",
         "success_criteria": "IC assigned; live timeline doc open; war room bridge active",
         "verification": "INC ticket has IC field set and timeline doc URL attached"},
        {"id": "ir-2", "action": "Identify scope and make containment decision (isolate vs monitor)", "priority": "high",
         "success_criteria": "Containment decision documented with rationale",
         "verification": "INC ticket shows containment_decision field with timestamp"},
        {"id": "ir-3", "action": "Preserve evidence before any remediation action", "priority": "high",
         "success_criteria": "Evidence preservation complete before first remediation step",
         "verification": "Evidence log timestamp precedes first remediation action timestamp"},
    ],
}


def _build_fallback_result(persona: str, entity_slice: Optional[Dict] = None) -> Dict[str, Any]:
    subtasks = [dict(st) for st in _PERSONA_FALLBACK_TASKS.get(persona, _PERSONA_FALLBACK_TASKS["soc"])]
    rows = (entity_slice or {}).get("rows") or []
    row_refs = [r.get("row_index") for r in rows[:10] if isinstance(r, dict) and r.get("row_index") is not None]
    # Extract top entities from entity_slice to ground subtasks
    ef = (entity_slice or {}).get("entity_fields") or {}
    top_entities: List[str] = []
    for cat in ("users", "ips", "hosts", "domains", "processes"):
        top_entities.extend(ef.get(cat) or [])
    if not top_entities:
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key in ("user", "username", "email", "host", "hostname", "src_ip", "source_ip", "dst_ip", "domain", "process"):
                val = row.get(key)
                if val:
                    top_entities.append(str(val))
                    break
            if top_entities:
                break
    top_entity = top_entities[0] if top_entities else None
    for st in subtasks:
        st["evidence_refs"] = row_refs
        st["persona"] = persona
        if top_entity and "{entity}" not in st["action"]:
            st["entity"] = top_entity
        if not st.get("success_criteria"):
            target = st.get("entity") or top_entity or "the scoped cluster"
            st["success_criteria"] = f"{target} is verified, contained or cleared; no matching follow-up alerts remain open."
        if not st.get("verification"):
            st["verification"] = "Validate completion against the referenced evidence rows and current SIEM/EDR state."
    return {
        "summary": f"Deterministic {persona} fallback — LLM unavailable, using rule-based checklist.",
        "confidence": 0.0,
        "subtasks": subtasks,
        "iocs": [],
        "mitre_techniques": [],
        "next_pivot": "",
        "fallback_generated": True,
        "fallback_reason": "llm_unavailable",
    }


def _parse_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """Extract and parse the first JSON object found in text."""
    if not text:
        return None
    # strip markdown code fences if present
    text = re.sub(r"^```[a-z]*\n?", "", text.strip())
    text = re.sub(r"```$", "", text.strip())
    try:
        return json.loads(text)
    except Exception:
        pass
    # Try to find first { ... } block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass
    return None


def call_expand_llm(
    prompt: str,
    llm_client: Any,
    persona: str = "soc",
    max_tokens: int = EXPAND_MAX_TOKENS,
    entity_slice: Optional[Dict] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Call LLM with the expand prompt and return parsed JSON result.

    Falls back to persona-specific deterministic checklist on any error.
    """
    _base_keys = {"summary", "confidence", "subtasks", "iocs", "mitre_techniques", "next_pivot"}

    if llm_client is None:
        return _build_fallback_result(persona, entity_slice)

    try:
        overrides = {"model": model, "ollama_model": model} if model else None
        if model:
            try:
                resp = llm_client.generate(prompt, max_tokens=max_tokens, overrides=overrides, model=model)
            except TypeError:
                resp = llm_client.generate(prompt, max_tokens=max_tokens, overrides=overrides)
        else:
            resp = llm_client.generate(prompt, max_tokens=max_tokens)
        if isinstance(resp, dict):
            text = resp.get("text") or ""
        else:
            text = str(resp)

        parsed = _parse_json_from_text(text)
        if parsed and isinstance(parsed, dict):
            result = _build_fallback_result(persona, entity_slice)
            result.update(parsed)
            result["fallback_generated"] = False
            result.pop("fallback_reason", None)
            # Backfill success_criteria/verification if model omitted them
            for st in result.get("subtasks") or []:
                if not st.get("success_criteria"):
                    st["success_criteria"] = f"Confirm {st.get('action', 'this step')} completed — no further indicators present"
                if not st.get("verification"):
                    st["verification"] = "Check SIEM / EDR for follow-up alerts in next 15-minute window"
            return result
    except Exception:
        pass

    fallback = _build_fallback_result(persona, entity_slice)
    if model:
        fallback["fallback_reason"] = "model_unavailable"
        fallback["requested_model"] = model
    return fallback


# ── OPT-3: SQLite expand cache ────────────────────────────────────────────────

def _ensure_cache_dir() -> str:
    os.makedirs(EXPAND_CACHE_DIR, exist_ok=True)
    return EXPAND_CACHE_DIR


def get_expand_cache_path(assessment_id: str, task_id: str) -> Optional[str]:
    """Return the file path for the expand cache entry, or None if unresolvable."""
    try:
        _ensure_cache_dir()
        safe_aid = re.sub(r"[^a-zA-Z0-9_\-]", "_", assessment_id)[:64]
        safe_tid = re.sub(r"[^a-zA-Z0-9_\-]", "_", task_id)[:64]
        return os.path.join(EXPAND_CACHE_DIR, f"{safe_aid}__{safe_tid}.json")
    except Exception:
        return None


def load_expand_cache(
    assessment_id: str,
    task_id: str,
    ttl_seconds: int = 3600,
) -> Optional[Dict[str, Any]]:
    """Load a cached expand result. Returns None if missing or expired."""
    path = get_expand_cache_path(assessment_id, task_id)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            entry = json.load(fh)
        if time.time() - entry.get("cached_at", 0) > ttl_seconds:
            return None
        return entry.get("result")
    except Exception:
        return None


def save_expand_cache(
    assessment_id: str,
    task_id: str,
    result: Dict[str, Any],
) -> None:
    """Persist an expand result to the file cache."""
    path = get_expand_cache_path(assessment_id, task_id)
    if not path:
        return
    try:
        entry = {"cached_at": time.time(), "result": result}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(entry, fh)
        os.replace(tmp, path)
    except Exception:
        pass


def make_task_id(task_text: str, persona: str = "soc") -> str:
    """Stable task ID from task text + persona (SHA-256 prefix)."""
    raw = f"{persona}::{task_text.strip().lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
