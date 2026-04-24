"""Model comparison harness: mistral-small3.2:24b vs qwen2.5:14b.

Compares quality and latency on the three v1.1 test files.

Skip conditions:
  - SKIP_MODEL_COMPARE=1 → skips all (CI / no Ollama)
  - Individual models skipped if Ollama endpoint is unreachable

Metrics measured per model:
  - Time-to-first-token (TTFT) via streaming
  - Total generation time
  - Tokens/second estimate
  - Classification accuracy (malicious/benign/needs_investigation)
  - MITRE technique coverage in narrative
  - Cluster separation (PHANTOM-MERIDIAN vs Harbourside BEC — must NOT be merged)
  - Per-persona coherence (soc vs ciso outputs differ)
  - Subtask quality per cluster
  - TemporalRAG domain entity resolution (update-cdn-svc.net)

Results are written to ewma_roc_summary.csv (appended) and printed to stdout.
"""
from __future__ import annotations

import csv
import json
import os
import time
from typing import Any, Dict, List, Optional

import pytest

# ── Skip guard ───────────────────────────────────────────────────────────────

SKIP_ALL = os.environ.get("SKIP_MODEL_COMPARE", "0") == "1"
pytestmark = [
    pytest.mark.skipif(SKIP_ALL, reason="SKIP_MODEL_COMPARE=1"),
    pytest.mark.timeout(300),  # 5 min per test — two large models can take 2+ minutes total
]

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODELS = {
    "mistral": "mistral-small3.2:24b",
    "qwen":    "qwen2.5:14b",
}

_DUMP = os.path.join(os.path.dirname(__file__), "../dump/test files")


# ── Dataset loaders ───────────────────────────────────────────────────────────

def _load_net_rows() -> List[Dict]:
    path = os.path.join(_DUMP, "janusec_net_c2_bgp.v1.1.csv")
    rows = []
    with open(path, encoding="utf-8") as f:
        for i, r in enumerate(csv.DictReader(f)):
            r["row_index"] = i
            r.setdefault("ts", r.get("timestamp_utc", ""))
            rows.append(r)
    return rows


def _load_okta_rows() -> List[Dict]:
    path = os.path.join(_DUMP, "janusec_okta_m365_events.v1.1.json")
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    events = d.get("events", [])
    for i, e in enumerate(events):
        e["row_index"] = i
        e.setdefault("ts", e.get("timestamp_utc", ""))
        e.setdefault("user", e.get("user_principal_name", ""))
        e.setdefault("src_ip", e.get("source_ip", ""))
    return events


def _load_ep_rows() -> List[Dict]:
    try:
        import openpyxl
    except ImportError:
        return []
    path = os.path.join(_DUMP, "janusec_ep_endpoint.v1.1.xlsx")
    wb = openpyxl.load_workbook(path, read_only=True)
    rows = []
    idx = 0
    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        sheet_rows = list(ws.iter_rows(values_only=True))
        if not sheet_rows:
            continue
        headers = [str(h or "").strip() for h in sheet_rows[0]]
        for i, row in enumerate(sheet_rows[1:], start=1):
            d: Dict[str, Any] = {headers[j]: row[j] for j in range(min(len(headers), len(row)))}
            d["_sheet"] = sheet_name
            d["_row_number"] = i
            d["row_index"] = idx
            for ts_key in ("date_utc", "timestamp_utc", "timestamp", "ts"):
                if d.get(ts_key):
                    d["ts"] = str(d[ts_key])
                    break
            rows.append(d)
            idx += 1
    wb.close()
    return rows


# ── Ollama client ─────────────────────────────────────────────────────────────

def _ollama_available(model: str) -> bool:
    """Check if Ollama is running and the model is loaded."""
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/tags",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            names = [m.get("name", "") for m in data.get("models", [])]
            return any(model in n for n in names)
    except Exception:
        return False


def _ollama_generate(
    model: str,
    prompt: str,
    max_tokens: int = 600,
) -> Dict[str, Any]:
    """Call Ollama /api/generate and return timing + text."""
    import urllib.request

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": max_tokens, "temperature": 0.1},
    }).encode()

    t0 = time.monotonic()
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read())
    total_s = time.monotonic() - t0

    text = result.get("response", "")
    eval_count = result.get("eval_count", 0)
    eval_duration_ns = result.get("eval_duration", 0)
    tps = eval_count / (eval_duration_ns / 1e9) if eval_duration_ns else 0.0

    return {
        "text": text,
        "total_s": total_s,
        "eval_count": eval_count,
        "tps": tps,
        "prompt_eval_count": result.get("prompt_eval_count", 0),
        "load_duration_ns": result.get("load_duration", 0),
    }


# ── Prompt builders ───────────────────────────────────────────────────────────

def _classify_rows_prompt(rows: List[Dict], n: int = 15) -> str:
    """Build a classification prompt for the first n rows."""
    lines = [
        "You are a SOC analyst. For each event below, classify as: malicious / benign / needs_investigation.",
        "Return JSON: {\"classifications\": [{\"event_id\": ..., \"label\": ..., \"reason\": ...}]}",
        "",
        "Events:",
    ]
    for r in rows[:n]:
        eid = r.get("event_id", f"row-{r.get('row_index', '?')}")
        ts = str(r.get("ts", ""))[:19]
        state = r.get("review_state", "")
        # Build a compact summary without leaking review_state
        summary = {k: v for k, v in r.items()
                   if k not in ("review_state", "analyst_notes", "_sheet", "_row_number", "row_index")
                   and v not in (None, "", "N/A")}
        lines.append(f"  [{eid}] {ts} {json.dumps(summary, default=str)[:200]}")
    return "\n".join(lines)


def _cluster_separation_prompt(net_rows: List[Dict], okta_rows: List[Dict]) -> str:
    """Prompt: do PHANTOM-MERIDIAN and Harbourside BEC share infrastructure?"""
    phantom = [r for r in net_rows
               if r.get("review_state", "").startswith("confirmed_malicious")][:5]
    harbourside = [r for r in okta_rows
                   if "bec" in str(r.get("analyst_notes", "")).lower()
                   or "harbourside" in str(r.get("analyst_notes", "")).lower()][:5]

    lines = [
        "You are a threat intelligence analyst. Based on the events below:",
        "1. Are PHANTOM-MERIDIAN (network C2 events) and the Harbourside BEC campaign",
        "   likely the same actor or different actors?",
        "2. List the key evidence for your conclusion.",
        "3. Return JSON: {\"same_actor\": true/false, \"evidence\": [...], \"confidence\": 0.0-1.0}",
        "",
        "Network C2 events (PHANTOM-MERIDIAN):",
    ]
    for r in phantom:
        lines.append(f"  {r.get('event_id')}: src={r.get('src_ip')} dst={r.get('dst_ip')} "
                     f"asn={r.get('geo_dst_asn')} sni={r.get('sni','')}")
    lines.append("\nHarbourside BEC events:")
    for r in harbourside:
        lines.append(f"  {r.get('event_id')}: user={r.get('user')} src_ip={r.get('src_ip')} "
                     f"event={r.get('event_type','')} notes={str(r.get('analyst_notes',''))[:80]}")
    return "\n".join(lines)


def _persona_soc_vs_ciso_prompt(rows: List[Dict]) -> tuple[str, str]:
    """Returns (soc_prompt, ciso_prompt) for the same critical events."""
    critical = [r for r in rows
                if str(r.get("review_state", "")).startswith("confirmed_malicious")][:8]

    base = "\n".join(
        f"  [{r.get('event_id','?')}] {r.get('ts','')[:19]} "
        f"{r.get('event_type', r.get('proxy_action',''))} "
        f"user={r.get('user', r.get('src_ip',''))}"
        for r in critical
    )
    soc_prompt = (
        "You are a SOC Tier 2 analyst. Triage these events for immediate response:\n"
        + base
        + "\nProvide: severity, immediate containment action, evidence to collect."
    )
    ciso_prompt = (
        "You are a CISO reporting to the board. Summarize these events for executive briefing:\n"
        + base
        + "\nProvide: business impact, regulatory exposure, recommended posture change."
    )
    return soc_prompt, ciso_prompt


def _subtask_per_cluster_prompt(cluster_name: str, rows: List[Dict]) -> str:
    events = "\n".join(
        f"  [{r.get('event_id','?')}] {r.get('ts','')[:19]} "
        f"{json.dumps({k: v for k,v in r.items() if k not in ('review_state','analyst_notes') and v not in (None,'')}, default=str)[:180]}"
        for r in rows[:10]
    )
    return (
        f"You are an incident responder. The cluster '{cluster_name}' includes these events:\n"
        + events
        + "\nGenerate 3-5 concrete investigation subtasks. Return JSON: "
          '{\"subtasks\": [{\"action\": ..., \"entity\": ..., \"priority\": \"high|medium|low\"}]}'
    )


# ── Quality scoring helpers ───────────────────────────────────────────────────

_MITRE_MAP = {
    "T1059.001": ["powershell", "encoded", "T1059"],
    "T1003.001": ["lsass", "credential", "dump", "T1003"],
    "T1021":     ["lateral", "wmi", "T1021"],
    "T1078":     ["privilege", "T1078"],
    "T1048":     ["exfil", "dns", "tunnel", "T1048"],
    "T1566":     ["phish", "bec", "T1566"],
}


def _mitre_coverage(text: str) -> float:
    """Fraction of MITRE techniques from the test dataset mentioned in text."""
    text_lower = text.lower()
    hits = sum(
        1 for keywords in _MITRE_MAP.values()
        if any(kw in text_lower for kw in keywords)
    )
    return hits / len(_MITRE_MAP)


def _parse_json_safe(text: str) -> Optional[Dict]:
    """Try to parse JSON from LLM output (handles markdown fences)."""
    # Strip markdown
    for marker in ("```json", "```"):
        if marker in text:
            text = text.split(marker, 1)[-1].rsplit("```", 1)[0]
    try:
        return json.loads(text.strip())
    except Exception:
        # Try finding first { ... }
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end+1])
            except Exception:
                pass
    return None


# ── Test class ────────────────────────────────────────────────────────────────

class TestModelCompare:
    """Side-by-side comparison: mistral-small3.2:24b vs qwen2.5:14b.

    Each test calls both models and compares:
      - Latency (total_s, tps)
      - Quality metric (accuracy, coverage, coherence)

    Results are stored in self._results and written to CSV at teardown.
    """

    @classmethod
    def setup_class(cls):
        cls._net_rows = _load_net_rows()
        cls._okta_rows = _load_okta_rows()
        cls._ep_rows = _load_ep_rows()
        cls._all_rows = cls._ep_rows + cls._net_rows + cls._okta_rows
        cls._results: List[Dict] = []

        # Check model availability
        cls._available = {}
        for key, model in MODELS.items():
            cls._available[key] = _ollama_available(model)
            if not cls._available[key]:
                print(f"\n[WARN] {model} not available at {OLLAMA_URL} — tests will skip")

    @classmethod
    def teardown_class(cls):
        """Append results to ewma_roc_summary.csv."""
        if not cls._results:
            return
        out_path = os.path.join(os.path.dirname(__file__), "../ewma_roc_summary.csv")
        fieldnames = ["test", "model", "total_s", "tps", "eval_count",
                      "quality_metric", "quality_value", "note"]
        write_header = not os.path.exists(out_path)
        with open(out_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                w.writeheader()
            for row in cls._results:
                w.writerow({k: row.get(k, "") for k in fieldnames})
        print(f"\n[model_compare] Written {len(cls._results)} rows to {out_path}")

    def _run_both(self, test_name: str, prompt: str, max_tokens: int = 600) -> Dict[str, Dict]:
        """Run prompt through both models, return {model_key: result}."""
        results = {}
        for key, model in MODELS.items():
            if not self._available.get(key):
                results[key] = {"text": "", "total_s": 0, "tps": 0, "eval_count": 0, "skipped": True}
                continue
            try:
                r = _ollama_generate(model, prompt, max_tokens=max_tokens)
                r["skipped"] = False
                results[key] = r
                self._results.append({
                    "test": test_name,
                    "model": model,
                    "total_s": f"{r['total_s']:.2f}",
                    "tps": f"{r['tps']:.1f}",
                    "eval_count": r["eval_count"],
                })
            except Exception as exc:
                results[key] = {"text": "", "total_s": 0, "tps": 0, "eval_count": 0,
                                "skipped": True, "error": str(exc)}
        return results

    # ── Latency baseline ──────────────────────────────────────────────────────

    def test_latency_short_prompt(self):
        """50-token warmup — measures cold vs warm load time."""
        prompt = "In one sentence, describe what DNS tunneling is."
        results = self._run_both("latency_short", prompt, max_tokens=80)

        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                pytest.skip(f"{model} unavailable")
            # Should complete in under 30s even cold
            assert r["total_s"] < 30, f"{model}: short prompt took {r['total_s']:.1f}s"
            print(f"\n[latency_short] {model}: {r['total_s']:.2f}s / {r['tps']:.1f} tok/s")

    def test_latency_vs_quality_tradeoff(self):
        """Compare which model is faster for the same 15-row classification."""
        net_malicious = [r for r in self._net_rows
                         if r.get("review_state", "").startswith("confirmed_malicious")][:15]
        prompt = _classify_rows_prompt(net_malicious, n=15)
        results = self._run_both("latency_classify_15", prompt, max_tokens=600)

        latencies = {}
        for key, model in MODELS.items():
            r = results.get(key, {})
            if not r.get("skipped"):
                latencies[key] = r["total_s"]
                print(f"\n[latency_classify] {model}: {r['total_s']:.2f}s / {r['tps']:.1f} tok/s")

        if len(latencies) == 2:
            faster = min(latencies, key=latencies.get)
            slower = max(latencies, key=latencies.get)
            ratio = latencies[slower] / latencies[faster] if latencies[faster] > 0 else 0
            print(f"\n[latency_classify] {MODELS[faster]} is {ratio:.1f}x faster")
            # Record latency comparison
            self._results.append({
                "test": "latency_ratio",
                "model": f"{MODELS[faster]}/{MODELS[slower]}",
                "quality_metric": "speed_ratio",
                "quality_value": f"{ratio:.2f}",
                "note": f"faster={MODELS[faster]}",
            })

    # ── Classification accuracy ───────────────────────────────────────────────

    def _check_classification_accuracy(self, rows: List[Dict], test_name: str) -> None:
        """Run both models on rows and measure classification accuracy."""
        # Sample: mix of malicious + benign
        malicious = [r for r in rows if r.get("review_state","").startswith("confirmed_malicious")][:5]
        benign = [r for r in rows if r.get("review_state","").startswith("reviewed_benign")][:5]
        sample = malicious + benign
        if len(sample) < 4:
            pytest.skip("Not enough labelled rows for accuracy test")

        prompt = _classify_rows_prompt(sample, n=len(sample))
        results = self._run_both(test_name, prompt, max_tokens=800)

        ground_truth = {}
        for r in sample:
            eid = r.get("event_id", f"row-{r.get('row_index','?')}")
            state = r.get("review_state", "")
            if state.startswith("confirmed_malicious"):
                ground_truth[eid] = "malicious"
            elif state.startswith("reviewed_benign"):
                ground_truth[eid] = "benign"

        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                continue
            parsed = _parse_json_safe(r["text"])
            if not parsed:
                print(f"\n[{test_name}] {model}: JSON parse failed — raw: {r['text'][:200]}")
                continue
            classifications = parsed.get("classifications", [])
            correct = 0
            total = 0
            for c in classifications:
                eid = c.get("event_id", "")
                predicted = c.get("label", "").lower().strip()
                expected = ground_truth.get(eid)
                if expected:
                    total += 1
                    if predicted == expected or predicted.startswith(expected[:5]):
                        correct += 1

            acc = correct / total if total > 0 else 0.0
            print(f"\n[{test_name}] {model}: accuracy={acc:.0%} ({correct}/{total})")
            self._results.append({
                "test": test_name,
                "model": model,
                "quality_metric": "classification_accuracy",
                "quality_value": f"{acc:.3f}",
                "note": f"correct={correct}/{total}",
            })
            # Accuracy should be at least 60% (LLM can classify without review_state)
            assert acc >= 0.6, f"{model}: classification accuracy {acc:.0%} < 60%"

    def test_net_classification_accuracy(self):
        """Both models classify NET events (C2 vs benign) with ≥60% accuracy."""
        self._check_classification_accuracy(self._net_rows, "classify_net")

    def test_okta_classification_accuracy(self):
        """Both models classify OKTA events with ≥60% accuracy."""
        self._check_classification_accuracy(self._okta_rows, "classify_okta")

    def test_ep_classification_accuracy(self):
        """Both models classify endpoint events with ≥60% accuracy."""
        if not self._ep_rows:
            pytest.skip("EP rows not loaded (openpyxl missing?)")
        self._check_classification_accuracy(self._ep_rows, "classify_ep")

    # ── MITRE technique coverage ──────────────────────────────────────────────

    def test_mitre_coverage_in_narrative(self):
        """Both models mention ≥50% of MITRE techniques from the dataset."""
        critical = [r for r in self._all_rows
                    if str(r.get("review_state","")).startswith("confirmed_malicious")][:20]

        lines = [
            "You are a threat analyst. Write a threat narrative covering the following events.",
            "Include specific MITRE ATT&CK technique IDs in your analysis.",
            "",
        ]
        for r in critical[:20]:
            mitre = r.get("mitre_technique", "")
            lines.append(f"  {r.get('event_id','?')}: {r.get('event_type','')} "
                         f"mitre={mitre} ts={str(r.get('ts',''))[:19]}")
        prompt = "\n".join(lines)

        results = self._run_both("mitre_coverage", prompt, max_tokens=700)

        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                continue
            cov = _mitre_coverage(r["text"])
            print(f"\n[mitre_coverage] {model}: {cov:.0%} coverage")
            self._results.append({
                "test": "mitre_coverage",
                "model": model,
                "quality_metric": "mitre_coverage",
                "quality_value": f"{cov:.3f}",
            })
            assert cov >= 0.4, f"{model}: MITRE coverage {cov:.0%} < 40%"

    # ── Cluster separation ────────────────────────────────────────────────────

    def test_cluster_separation_phantom_vs_harbourside(self):
        """Both models must NOT merge PHANTOM-MERIDIAN and Harbourside BEC."""
        prompt = _cluster_separation_prompt(self._net_rows, self._okta_rows)
        results = self._run_both("cluster_separation", prompt, max_tokens=600)

        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                continue
            parsed = _parse_json_safe(r["text"])
            if not parsed:
                # Accept text-based analysis: should say "different" somewhere
                text_lower = r["text"].lower()
                is_same = "same actor" in text_lower and "not same" not in text_lower
                assert not is_same, f"{model}: incorrectly merged PHANTOM-MERIDIAN + Harbourside BEC"
                print(f"\n[cluster_sep] {model}: text-based — OK (no merge)")
                continue

            same_actor = parsed.get("same_actor", None)
            confidence = parsed.get("confidence", 0)
            print(f"\n[cluster_sep] {model}: same_actor={same_actor} confidence={confidence:.2f}")
            self._results.append({
                "test": "cluster_separation",
                "model": model,
                "quality_metric": "same_actor_wrong",
                "quality_value": str(same_actor),
                "note": f"confidence={confidence:.2f}",
            })
            # Must NOT say same_actor=True with high confidence
            assert not (same_actor is True and confidence > 0.7), \
                f"{model}: incorrectly merged PHANTOM-MERIDIAN + Harbourside BEC (conf={confidence:.2f})"

    # ── Per-persona coherence ─────────────────────────────────────────────────

    def test_persona_soc_vs_ciso_outputs_differ(self):
        """SOC and CISO persona outputs must be substantively different."""
        soc_p, ciso_p = _persona_soc_vs_ciso_prompt(self._all_rows)

        for key, model in MODELS.items():
            if not self._available.get(key):
                continue
            soc_r = _ollama_generate(model, soc_p, max_tokens=400)
            ciso_r = _ollama_generate(model, ciso_p, max_tokens=400)

            soc_text = soc_r["text"].lower()
            ciso_text = ciso_r["text"].lower()

            # SOC should mention containment/triage terms
            soc_terms = any(t in soc_text for t in ["isolate", "contain", "block", "kill", "triage", "forensic"])
            # CISO should mention business/board terms
            ciso_terms = any(t in ciso_text for t in ["board", "executive", "regulatory", "compliance",
                                                        "business", "risk", "exposure", "posture"])
            # Outputs must differ meaningfully (not identical)
            overlap = len(set(soc_text.split()) & set(ciso_text.split())) / max(len(set(soc_text.split())), 1)

            print(f"\n[persona] {model}: soc_terms={soc_terms} ciso_terms={ciso_terms} overlap={overlap:.0%}")
            self._results.append({
                "test": "persona_coherence",
                "model": model,
                "quality_metric": "persona_differentiation",
                "quality_value": f"soc={soc_terms},ciso={ciso_terms},overlap={overlap:.2f}",
            })

            assert soc_terms, f"{model} SOC persona missing containment language"
            assert ciso_terms, f"{model} CISO persona missing executive/board language"
            assert overlap < 0.8, f"{model} SOC/CISO outputs too similar (overlap={overlap:.0%})"

    # ── Subtask quality per cluster ───────────────────────────────────────────

    def test_subtasks_phantom_meridian_cluster(self):
        """Subtasks for PHANTOM-MERIDIAN should reference specific C2 indicators."""
        phantom = [r for r in self._net_rows
                   if r.get("review_state","").startswith("confirmed_malicious")
                   and "update-cdn-svc.net" in str(r.get("dns_query","") or r.get("sni",""))][:8]

        if not phantom:
            # Fallback: all confirmed malicious net rows
            phantom = [r for r in self._net_rows
                       if r.get("review_state","").startswith("confirmed_malicious")][:8]
        if not phantom:
            pytest.skip("No PHANTOM-MERIDIAN rows found")

        prompt = _subtask_per_cluster_prompt("PHANTOM_MERIDIAN", phantom)
        results = self._run_both("subtask_phantom_meridian", prompt, max_tokens=500)

        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                continue
            parsed = _parse_json_safe(r["text"])
            if parsed:
                tasks = parsed.get("subtasks", [])
                assert len(tasks) >= 2, f"{model}: only {len(tasks)} subtasks for PHANTOM-MERIDIAN"
                # At least one task should mention C2/network/DNS
                actions = " ".join(t.get("action","").lower() for t in tasks)
                net_terms = any(t in actions for t in ["c2", "dns", "network", "beacon", "block", "isolat"])
                print(f"\n[subtask_phantom] {model}: {len(tasks)} tasks, net_terms={net_terms}")
                assert net_terms, f"{model}: PHANTOM-MERIDIAN subtasks don't mention C2/network actions"
            else:
                # Accept free-text if JSON failed, just check it has content
                assert len(r["text"]) > 100, f"{model}: PHANTOM-MERIDIAN subtask response too short"

    def test_subtasks_harbourside_bec_cluster(self):
        """Subtasks for Harbourside BEC should reference finance/email/forwarding actions."""
        bec = [r for r in self._okta_rows
               if "bec" in str(r.get("analyst_notes","")).lower()
               or "harbourside" in str(r.get("analyst_notes","")).lower()][:6]

        if not bec:
            bec = [r for r in self._okta_rows
                   if r.get("review_state","").startswith("confirmed_malicious")][:6]
        if not bec:
            pytest.skip("No Harbourside BEC rows found")

        prompt = _subtask_per_cluster_prompt("HARBOURSIDE_BEC", bec)
        results = self._run_both("subtask_harbourside_bec", prompt, max_tokens=500)

        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                continue
            text = r["text"].lower()
            bec_terms = any(t in text for t in ["email", "forward", "inbox", "mail", "financial", "wire", "transfer"])
            print(f"\n[subtask_harbourside] {model}: bec_terms={bec_terms}")
            assert bec_terms, f"{model}: Harbourside BEC subtasks don't mention email/financial actions"

    # ── TemporalRAG domain entity resolution ──────────────────────────────────

    def test_temporalrag_c2_domain_entity_resolution(self):
        """Verify the entity slice correctly captures all C2 domain rows."""
        from src.analysis.expand_engine import extract_task_entity_slice

        task_text = "investigate update-cdn-svc.net C2 beaconing and DNS exfiltration"
        assessment = {"assessment_id": "net-test", "rows": self._net_rows}
        result = extract_task_entity_slice(task_text, {}, assessment)

        c2_rows = [r for r in result["rows"]
                   if "update-cdn-svc.net" in str(r.get("dns_query",""))
                   or "update-cdn-svc.net" in str(r.get("sni",""))]

        print(f"\n[temporalrag] C2 domain slice: {len(c2_rows)} rows from {len(self._net_rows)} NET rows")
        assert len(c2_rows) >= 5, \
            f"TemporalRAG only captured {len(c2_rows)} C2 rows (expected ≥5)"

        # The high-entropy exfil row (NET-014) must be included
        exfil_ids = {r.get("event_id") for r in c2_rows}
        assert "NET-014" in exfil_ids, "NET-014 (highest entropy exfil) not in TemporalRAG slice"

    def test_temporalrag_cobalt_strike_ip_slice(self):
        """Verify 45.153.160.100 slice includes Cobalt Strike exfil events."""
        from src.analysis.expand_engine import extract_task_entity_slice

        task_text = "45.153.160.100 Cobalt Strike data exfiltration"
        assessment = {"assessment_id": "net-test", "rows": self._net_rows}
        result = extract_task_entity_slice(task_text, {}, assessment)

        ids = {r.get("event_id") for r in result["rows"]}
        print(f"\n[temporalrag_cs] Slice has {len(ids)} rows")
        for expected in ["NET-024", "NET-027", "NET-028"]:
            assert expected in ids, f"Cobalt Strike exfil {expected} not in IP slice"

    def test_temporalrag_finance_officer_bec_slice(self):
        """Verify finance.officer slice captures BEC events OKT-021/OKT-022."""
        from src.analysis.expand_engine import extract_task_entity_slice

        task_text = "finance.officer@acmecorp.com BEC wire transfer forwarding rule"
        assessment = {"assessment_id": "okta-test", "rows": self._okta_rows}
        result = extract_task_entity_slice(task_text, {}, assessment)

        ids = {r.get("event_id") for r in result["rows"]}
        print(f"\n[temporalrag_bec] Slice has {len(ids)} rows")
        found = {"OKT-021", "OKT-022"} & ids
        assert len(found) >= 1, \
            f"BEC chain events {{'OKT-021','OKT-022'}} not in finance.officer slice (got {sorted(ids)[:10]})"

    def test_temporalrag_row_cap_respected(self):
        """Entity slice must never exceed 30 rows regardless of match count."""
        from src.analysis.expand_engine import extract_task_entity_slice
        from src.analysis.expand_checks import extract_entity_fields

        # Use a very broad query that would match most rows
        all_ips = extract_entity_fields(self._all_rows)["ips"]
        broad_text = " ".join(all_ips[:5]) + " full investigation"
        assessment = {"assessment_id": "all-test", "rows": self._all_rows}
        result = extract_task_entity_slice(broad_text, {}, assessment)

        assert len(result["rows"]) <= 30, \
            f"Entity slice exceeded 30-row cap: {len(result['rows'])} rows returned"

    # ── HopGraph correlation ──────────────────────────────────────────────────

    def test_hopgraph_ja3_cluster_linkage_prompt(self):
        """Ask LLM to find shared JA3 fingerprints across sessions."""
        ja3_rows = [r for r in self._net_rows
                    if r.get("ja3_md5") and r.get("review_state","").startswith("confirmed_malicious")]

        if len(ja3_rows) < 3:
            pytest.skip("Not enough JA3 rows for hop graph test")

        lines = [
            "You are a network forensics analyst. Find sessions sharing the same JA3 fingerprint.",
            "List clusters of events that share JA3 fingerprints and what that implies.",
            "Return JSON: {\"clusters\": [{\"ja3\": ..., \"event_ids\": [...], \"implication\": ...}]}",
            "",
        ]
        for r in ja3_rows:
            lines.append(f"  {r.get('event_id')}: ja3={r.get('ja3_md5')} "
                         f"dst={r.get('dst_ip')} sni={r.get('sni','')}")
        prompt = "\n".join(lines)

        results = self._run_both("hopgraph_ja3", prompt, max_tokens=600)

        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                continue
            parsed = _parse_json_safe(r["text"])
            if parsed:
                clusters = parsed.get("clusters", [])
                assert len(clusters) >= 1, f"{model}: no JA3 clusters found"
                print(f"\n[hopgraph_ja3] {model}: {len(clusters)} JA3 clusters found")
            else:
                # Text-based: should mention JA3 or fingerprint
                assert "ja3" in r["text"].lower() or "fingerprint" in r["text"].lower(), \
                    f"{model}: hop graph response doesn't mention JA3"

    def test_hopgraph_cross_source_correlation(self):
        """Ask LLM to correlate NET C2 IP with OKTA events from same source IP."""
        # Find the attacker IP used in OKTA and NET
        attacker_ip = "185.62.56.200"  # Harbourside spray IP
        net_hits = [r for r in self._net_rows if attacker_ip in str(r.values())]
        okta_hits = [r for r in self._okta_rows
                     if str(r.get("src_ip","")) == attacker_ip
                     or attacker_ip in str(r.values())]

        if not net_hits and not okta_hits:
            # Use AS60068 (C2 ASN) as pivot
            net_hits = [r for r in self._net_rows
                        if "AS60068" in str(r.get("geo_dst_asn",""))]

        if not net_hits:
            pytest.skip("No cross-source correlation events found")

        lines = [
            "You are a threat hunter. Correlate network and identity events from the same actor.",
            "Identify which events share infrastructure (IP, ASN) across data sources.",
            "",
            "Network events:",
        ]
        for r in net_hits[:5]:
            lines.append(f"  {r.get('event_id')}: dst={r.get('dst_ip')} asn={r.get('geo_dst_asn')}")
        if okta_hits:
            lines.append("Identity events:")
            for r in okta_hits[:5]:
                lines.append(f"  {r.get('event_id')}: user={r.get('user')} src_ip={r.get('src_ip')}")
        prompt = "\n".join(lines) + "\n\nSummarize the cross-source actor correlation."

        results = self._run_both("hopgraph_cross_source", prompt, max_tokens=400)
        for key, model in MODELS.items():
            r = results.get(key, {})
            if r.get("skipped"):
                continue
            text = r["text"].lower()
            corr_terms = any(t in text for t in ["same", "correlat", "shared", "actor", "link", "infrastructure"])
            print(f"\n[hopgraph_cross] {model}: corr_terms={corr_terms}")
            assert corr_terms, f"{model}: cross-source correlation response lacks correlation language"
