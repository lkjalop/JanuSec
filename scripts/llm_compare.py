"""Enterprise LLM narrator benchmark.

Compares multiple Ollama models on real VESPER + Meridian fixture data.

14 scored metrics per (model, cluster) pair:
  1.  verdict_gap       — 0=exact match, >0=underclaim, <0=overclaim
  2.  llm_conf          — confidence reported by LLM
  3.  conf_delta        — |llm_conf - deterministic_conf|
  4.  kc_recall         — kill-chain stage recall vs expected ground truth
  5.  kc_count          — number of kill-chain stages named
  6.  entity_recall     — fraction of evidence entities referenced in narrative
  7.  hallucinated_entities — names in narrative NOT present in evidence rows
  8.  schema_score      — required-field completeness (0.0–1.0)
  9.  json_valid        — 1 if output parsed cleanly, 0 if fallback triggered
 10.  row_citation_prec — fraction of cited row IDs that exist in evidence_preview
 11.  tool_specificity  — avg word-count of "tool" field in next_steps
 12.  ns_count          — number of next-steps returned
 13.  ns_p1_count       — number with priority==P1
 14.  elapsed_s         — wall time for LLM call

Santos cases are run as gate only (not scored) — we check that LLM does NOT claim
VALIDATED_BREACH for benign reference clusters.

Usage:
    python scripts/llm_compare.py
    python scripts/llm_compare.py --models qwen2.5:14b deepseek-r1:14b
    python scripts/llm_compare.py --no-vesper           # skip VESPER (faster)
    python scripts/llm_compare.py --ablate              # run prompt ablations

Results are timestamped and appended to scripts/llm_compare_results.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import requests

from src.core.ingest.cluster_narrator import _build_prompt, _parse_llm_output

# ── Constants ─────────────────────────────────────────────────────────────────

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODELS = ["deepseek-r1:14b", "qwen2.5:14b", "qwen3:14b"]
RESULTS_FILE = ROOT / "scripts" / "llm_compare_results.json"

VALID_VERDICTS = {
    "VALIDATED_BREACH", "SUSPECTED_BREACH", "BENIGN_EXPECTED",
    "REQUIRES_INVESTIGATION", "INSUFFICIENT_EVIDENCE",
}
VERDICT_RANK = {
    "INSUFFICIENT_EVIDENCE": 0, "BENIGN_EXPECTED": 1,
    "REQUIRES_INVESTIGATION": 2, "SUSPECTED_BREACH": 3, "VALIDATED_BREACH": 4,
}

EXPECTED_KC: dict[str, set[str]] = {
    "vesper": {"lateral_movement", "exfiltration", "credential_access", "execution"},
    "vesper_multisource": {"lateral_movement", "exfiltration", "credential_access", "execution"},
    "meridian": {"exfiltration", "collection"},
}

REQUIRED_FIELDS = {
    "verdict", "confidence", "kill_chain_stage", "kill_chain_stages",
    "ioc_summary", "attack_narrative", "evidence_refs", "next_steps",
}

# ── Fixture loading ───────────────────────────────────────────────────────────

def _fixture_path(name: str) -> Path:
    return ROOT / "tests" / "fixtures" / "assessments" / "quality" / f"{name}.json"


def load_fixture(name: str) -> dict:
    p = _fixture_path(name)
    if not p.exists():
        raise FileNotFoundError(f"Fixture not found: {p}")
    with open(p) as f:
        return json.load(f)


def fixture_hash(assessment: dict) -> str:
    rows = assessment.get("rows") or assessment.get("clusters") or []
    h = hashlib.md5(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()[:10]
    return h


def prompt_hash(prompt: str) -> str:
    return hashlib.md5(prompt.encode()).hexdigest()[:10]


def top_clusters(assessment: dict, n: int = 3, verdict_filter: str | None = None) -> list[dict]:
    clusters = assessment.get("clusters") or []
    seen_ids: set[str] = set()
    selected = []
    for cl in sorted(clusters, key=lambda c: float(c.get("confidence") or 0), reverse=True):
        cid = cl.get("cluster_id", "")
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        if verdict_filter and (cl.get("final_verdict") or cl.get("verdict") or "") != verdict_filter:
            continue
        selected.append(cl)
        if len(selected) >= n:
            break
    return selected


# ── Ollama call ───────────────────────────────────────────────────────────────

def call_ollama(
    model: str,
    prompt: str,
    max_tokens: int = 1100,
    timeout: int = 180,
) -> tuple[str, float, bool]:
    """Return (raw_text, elapsed_seconds, timed_out)."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": max_tokens, "temperature": 0.1},
    }
    if any(m in model for m in ("qwen3", "deepseek-r1")):
        payload["think"] = False
    t0 = time.time()
    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=timeout)
        elapsed = time.time() - t0
        resp.raise_for_status()
        raw = resp.json().get("response", "")
        return raw, elapsed, False
    except requests.exceptions.Timeout:
        return "", time.time() - t0, True
    except Exception as exc:
        raise RuntimeError(f"Ollama call failed: {exc}") from exc


# ── Scoring ───────────────────────────────────────────────────────────────────

def _extract_real_entities(cluster: dict) -> set[str]:
    ep = cluster.get("evidence_preview") or []
    entities: set[str] = set()
    entity_fields = (
        "user_canonical", "src_ip", "hostname", "userPrincipalName",
        "account_name", "host", "user", "src_host", "domain_controller",
        "client_address", "service_name", "spn", "dst_ip",
    )
    for row in ep:
        for field in entity_fields:
            v = str(row.get(field) or "").strip().lower()
            if v and v not in ("-", "none", "null", "-1") and len(v) > 3:
                entities.add(v)
            # Also add just the hostname part of FQDNs (e.g., "dc-ves-01" from "dc-ves-01.acme-vesper.local")
            if "." in v:
                short = v.split(".")[0]
                if len(short) > 3:
                    entities.add(short)
    return entities


def _detect_hallucinated_entities(parsed: dict, real_entities: set[str]) -> list[str]:
    """Find person/IP/hostname tokens in narrative that are NOT in real evidence."""
    narrative = (parsed.get("attack_narrative") or "") + " " + (parsed.get("ioc_summary") or "")
    # Extract quoted tokens and camelCase words that look like entity names
    candidates = set()
    # IPs
    for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", narrative):
        candidates.add(ip.lower())
    # usernames / hostnames (word.word or UPPER-WORD patterns)
    for token in re.findall(r"\b[A-Za-z][A-Za-z0-9]{2,}\.[A-Za-z][A-Za-z0-9]{2,}\b", narrative):
        candidates.add(token.lower())
    for token in re.findall(r"\b[A-Z]{2,3}-[A-Z0-9]{2,}-\d+\b", narrative):
        candidates.add(token.lower())
    hallucinated = [c for c in candidates if c not in real_entities]
    return hallucinated[:10]


def _row_citation_precision(parsed: dict, evidence_preview: list[dict]) -> float:
    """Fraction of evidence_refs that correspond to a real row index."""
    refs = parsed.get("evidence_refs") or []
    if not refs:
        return 0.0
    real_indices = {str(r.get("row_index") or i) for i, r in enumerate(evidence_preview)}
    real_indices |= {str(i) for i in range(len(evidence_preview))}
    matched = sum(1 for r in refs if str(r) in real_indices)
    return round(matched / len(refs), 2)


def _tool_specificity(parsed: dict) -> float:
    """Average word-count in the 'tool' field of next_steps (proxy for specificity)."""
    ns = parsed.get("next_steps") or parsed.get("recommended_actions") or []
    tool_words = [len(str(s.get("tool") or "").split()) for s in ns if s.get("tool")]
    return round(sum(tool_words) / len(tool_words), 2) if tool_words else 0.0


def score_response(
    parsed: dict,
    cluster: dict,
    dataset_name: str,
    raw: str,
    elapsed: float,
    timed_out: bool,
) -> dict[str, Any]:
    det_verdict = (cluster.get("final_verdict") or cluster.get("verdict") or "").upper()
    det_conf = float(cluster.get("confidence") or 0)

    llm_verdict = str(parsed.get("verdict") or "").upper()
    llm_rank = VERDICT_RANK.get(llm_verdict, -1)
    det_rank = VERDICT_RANK.get(det_verdict, 2)
    llm_conf = float(parsed.get("confidence") or 0)

    # 1-3: verdict + confidence
    verdict_gap = det_rank - llm_rank
    conf_delta = round(abs(llm_conf - det_conf), 3)

    # 4-5: kill-chain recall
    kc_stages = set(parsed.get("kill_chain_stages") or
                    ([parsed["kill_chain_stage"]] if parsed.get("kill_chain_stage") else []))
    kc_stages.discard("unknown")
    expected_kc = EXPECTED_KC.get(dataset_name.lower(), set())
    kc_recall = round(len(kc_stages & expected_kc) / len(expected_kc), 2) if expected_kc else 0.0
    kc_count = len(kc_stages)

    # 6-7: entity recall + hallucinations
    real_entities = _extract_real_entities(cluster)
    narrative_lower = (parsed.get("attack_narrative") or "").lower()
    ioc_lower = (parsed.get("ioc_summary") or "").lower()
    combined = narrative_lower + " " + ioc_lower
    entities_found = sum(1 for e in real_entities if e in combined)
    entity_recall = round(entities_found / len(real_entities), 2) if real_entities else 0.0
    hallucinated = _detect_hallucinated_entities(parsed, real_entities)

    # 8: schema compliance
    present = {k for k in REQUIRED_FIELDS if parsed.get(k)}
    schema_score = round(len(present) / len(REQUIRED_FIELDS), 2)

    # 9: JSON validity (1 if clean parse, 0 if we got the fallback structure)
    json_valid = 1 if (parsed.get("_narrator_source") != "fallback" and
                       llm_verdict in VALID_VERDICTS) else 0

    # 10: row-citation precision
    ep = cluster.get("evidence_preview") or []
    row_cit_prec = _row_citation_precision(parsed, ep)

    # 11: tool specificity
    tool_spec = _tool_specificity(parsed)

    # 12-13: next-steps counts
    ns = parsed.get("next_steps") or parsed.get("recommended_actions") or []
    ns_count = len(ns)
    ns_p1 = sum(1 for s in ns if s.get("priority") == "P1")
    ns_with_tool = sum(1 for s in ns if s.get("tool") and len(str(s.get("tool"))) > 3)

    # 14: elapsed + timeout
    return {
        # Verdict
        "verdict_gap": verdict_gap,
        "llm_verdict": llm_verdict,
        "det_verdict": det_verdict,
        "llm_conf": round(llm_conf, 2),
        "det_conf": round(det_conf, 2),
        "conf_delta": conf_delta,
        # Kill-chain
        "kc_recall": kc_recall,
        "kc_count": kc_count,
        "kc_stages": sorted(kc_stages),
        # Entities
        "entity_recall": entity_recall,
        "real_entities_checked": len(real_entities),
        "entities_found": entities_found,
        "hallucinated_entities": hallucinated,
        "hallucinated_count": len(hallucinated),
        # Schema
        "schema_score": schema_score,
        "json_valid": json_valid,
        # Citation precision
        "row_citation_prec": row_cit_prec,
        # Tool specificity
        "tool_specificity": tool_spec,
        # Next-steps
        "ns_count": ns_count,
        "ns_p1_count": ns_p1,
        "ns_with_tool": ns_with_tool,
        # Timing
        "elapsed_s": round(elapsed, 1),
        "timed_out": timed_out,
        # Extra info
        "narrative_len": len(parsed.get("attack_narrative") or ""),
        "raw_len": len(raw),
    }


# ── Ablation variants ─────────────────────────────────────────────────────────

def build_ablation_prompt(cluster: dict, evidence: list[dict], ablation: str) -> str:
    """Build a prompt variant with one component removed for ablation testing."""
    if ablation == "no_anchor":
        # Remove DETERMINISTIC CLASSIFICATION block from standard prompt
        full = _build_prompt(cluster, evidence)
        return re.sub(r"(?s)={5,} DETERMINISTIC CLASSIFICATION.*?={5,}", "", full).strip()
    if ablation == "no_factor_humanize":
        # Stub: inject raw keys instead of humanized labels
        cluster_stub = dict(cluster)
        cluster_stub["_ablation_raw_tags"] = True
        return _build_prompt(cluster_stub, evidence)
    if ablation == "no_evidence":
        # Empty evidence list
        return _build_prompt(cluster, [])
    if ablation == "standard":
        return _build_prompt(cluster, evidence)
    raise ValueError(f"Unknown ablation: {ablation!r}")


# ── Santos gate ───────────────────────────────────────────────────────────────

def run_santos_gate(model: str, fixture: dict) -> dict[str, Any]:
    """Verify LLM does NOT claim VALIDATED_BREACH on benign clusters."""
    benign_clusters = top_clusters(fixture, n=2, verdict_filter="BENIGN_EXPECTED")
    if not benign_clusters:
        return {"skipped": True, "reason": "no BENIGN_EXPECTED clusters in Santos fixture"}

    failures = []
    for cl in benign_clusters:
        ep = cl.get("evidence_preview") or []
        if not ep:
            continue
        prompt = _build_prompt(cl, ep)
        try:
            raw, elapsed, timed_out = call_ollama(model, prompt, max_tokens=600, timeout=90)
        except RuntimeError as exc:
            failures.append({"cluster_id": cl.get("cluster_id"), "error": str(exc)})
            continue
        parsed = _parse_llm_output(raw, cl.get("cluster_id", "?"))
        llm_v = str(parsed.get("verdict") or "").upper()
        if llm_v == "VALIDATED_BREACH":
            failures.append({
                "cluster_id": cl.get("cluster_id"),
                "llm_verdict": llm_v,
                "llm_conf": parsed.get("confidence"),
                "elapsed_s": round(elapsed, 1),
            })

    return {
        "benign_clusters_tested": len(benign_clusters),
        "false_positives": len(failures),
        "failures": failures,
        "gate_passed": len(failures) == 0,
    }


# ── Main comparison ───────────────────────────────────────────────────────────

def _print_scores(key: str, scores: dict[str, Any]) -> None:
    gap_str = "=" if scores["verdict_gap"] == 0 else (
        f"v{scores['verdict_gap']}" if scores["verdict_gap"] > 0 else f"^{abs(scores['verdict_gap'])}"
    )
    jv = "[JSON OK]" if scores["json_valid"] else "[FALLBACK]"
    to = " [TIMEOUT]" if scores.get("timed_out") else ""
    print(f"    verdict: {scores['det_verdict']} -> {scores['llm_verdict']}  {gap_str}  {jv}{to}")
    print(f"    conf:    det={scores['det_conf']} llm={scores['llm_conf']} delta={scores['conf_delta']}")
    print(f"    kc:      {scores['kc_stages']} (recall={scores['kc_recall']}, count={scores['kc_count']})")
    print(f"    entity:  {scores['entities_found']}/{scores['real_entities_checked']} (recall={scores['entity_recall']})"
          f"  hallucinated={scores['hallucinated_count']}")
    print(f"    schema:  {scores['schema_score']}  row_cit_prec={scores['row_citation_prec']}"
          f"  tool_spec={scores['tool_specificity']}")
    print(f"    nextstep:{scores['ns_count']} steps, {scores['ns_p1_count']} P1, {scores['ns_with_tool']} w/ tool")
    print(f"    time:    {scores['elapsed_s']}s | raw_len={scores['raw_len']}")
    if scores["hallucinated_count"] > 0:
        print(f"    HALLUCINATED: {scores['hallucinated_entities'][:5]}")


def run_comparison(
    models: list[str],
    datasets: list[tuple[str, dict]],
    run_ablations: bool = False,
    max_clusters: int = 2,
) -> dict[str, Any]:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    all_results: dict[str, Any] = {
        "_run_id": run_id,
        "_timestamp": run_id,
        "_models": models,
        "_datasets": [ds for ds, _ in datasets],
    }

    ablations = ["standard", "no_anchor", "no_evidence"] if run_ablations else ["standard"]

    for ds_name, assessment in datasets:
        f_hash = fixture_hash(assessment)
        print(f"\n{'='*72}")
        print(f"DATASET: {ds_name.upper()}  fixture_hash={f_hash}")
        print(f"{'='*72}")

        clusters = top_clusters(assessment, n=max_clusters)
        all_rows = assessment.get("rows") or []

        for cl_idx, cluster in enumerate(clusters):
            cl_id = cluster.get("cluster_id", f"cl{cl_idx}")[:40]
            det_v = cluster.get("final_verdict") or cluster.get("verdict") or "?"
            ep = cluster.get("evidence_preview") or []
            print(f"\n  Cluster {cl_idx+1}/{len(clusters)}: {cl_id}")
            print(f"  det_verdict={det_v}  conf={cluster.get('confidence')}  ep_rows={len(ep)}")
            ft = cluster.get("factor_tags") or {}
            ft_keys = list(ft.keys())[:6] if isinstance(ft, dict) else list(ft)[:6]
            print(f"  factor_tags: {ft_keys}")

            if not ep:
                print("  [SKIP] No evidence_preview — cannot build prompt")
                continue

            for abl in ablations:
                prompt = build_ablation_prompt(cluster, ep, abl)
                p_hash = prompt_hash(prompt)
                abl_label = f"[abl:{abl}]" if abl != "standard" else ""
                print(f"\n  Ablation: {abl}  prompt_hash={p_hash}  prompt_len={len(prompt)}")

                for model in models:
                    print(f"\n    >> {model}{abl_label}")
                    key = f"{ds_name}__cl{cl_idx+1}__{model}__{abl}"
                    try:
                        raw, elapsed, timed_out = call_ollama(model, prompt, max_tokens=1100)
                        parsed = _parse_llm_output(raw, cl_id)
                        scores = score_response(parsed, cluster, ds_name, raw, elapsed, timed_out)
                        all_results[key] = {
                            "scores": scores,
                            "fixture_hash": f_hash,
                            "prompt_hash": p_hash,
                            "ablation": abl,
                            "model": model,
                            "dataset": ds_name,
                            "cluster_id": cl_id,
                        }
                        _print_scores(key, scores)

                    except Exception as exc:
                        print(f"    ERROR: {exc}")
                        all_results[key] = {"error": str(exc), "model": model, "dataset": ds_name}

    # Santos gate
    santos_path = ROOT / "tests" / "fixtures" / "assessments" / "quality" / "santos_assessment.json"
    if santos_path.exists():
        print(f"\n{'='*72}")
        print("SANTOS FALSE-POSITIVE GATE")
        print(f"{'='*72}")
        santos = json.loads(santos_path.read_text())
        for model in models:
            print(f"\n  Model: {model}")
            gate_result = run_santos_gate(model, santos)
            all_results[f"santos_gate__{model}"] = gate_result
            status = "PASS" if gate_result.get("gate_passed") else "FAIL"
            print(f"  Gate: {status}  FPs: {gate_result.get('false_positives', 0)}/{gate_result.get('benign_clusters_tested', 0)}")
            if gate_result.get("failures"):
                for f in gate_result["failures"]:
                    print(f"    FP: cluster={f.get('cluster_id')} verdict={f.get('llm_verdict')}")
    else:
        print(f"\n[INFO] Santos fixture not found at {santos_path} — skipping gate")

    # Summary table
    print(f"\n\n{'='*72}")
    print("SUMMARY TABLE (standard ablation only)")
    print(f"{'='*72}")
    hdr = f"{'Key':<52} {'Verdict':>16} {'G':>2} {'KC':>4} {'Ent':>5} {'Hal':>4} {'Sch':>5} {'T':>5}s"
    print(hdr)
    print("-" * 72)
    for key, res in sorted(all_results.items()):
        if key.startswith("_") or "__standard" not in key:
            continue
        if "error" in res:
            print(f"{key:<52} ERROR")
            continue
        s = res["scores"]
        g = "=" if s["verdict_gap"] == 0 else ("v" if s["verdict_gap"] > 0 else "^")
        to_mark = "T" if s.get("timed_out") else " "
        print(
            f"{key:<52} {s['llm_verdict']:>16} {g}{s['verdict_gap']:>1}"
            f" {s['kc_count']:>4} {s['entity_recall']:>5}"
            f" {s['hallucinated_count']:>4} {s['schema_score']:>5}"
            f" {to_mark}{s['elapsed_s']:>4}s"
        )

    # Persist results (append to historical log)
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE) as f:
            history = json.load(f)
        if not isinstance(history, list):
            history = [history]
    else:
        history = []
    history.append(all_results)
    with open(RESULTS_FILE, "w") as f:
        json.dump(history, f, indent=2, default=lambda o: list(o) if isinstance(o, set) else str(o))
    print(f"\nResults appended to {RESULTS_FILE}  (run_id={run_id})")

    return all_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Janusec LLM narrator benchmark")
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS, help="Ollama model names")
    parser.add_argument("--no-vesper", action="store_true", help="Skip VESPER dataset")
    parser.add_argument("--no-meridian", action="store_true", help="Skip Meridian dataset")
    parser.add_argument("--ablate", action="store_true", help="Run prompt ablation variants")
    parser.add_argument("--max-clusters", type=int, default=2, help="Max clusters per dataset")
    args = parser.parse_args()

    datasets: list[tuple[str, dict]] = []

    if not args.no_vesper:
        vesper_ms = ROOT / "tests" / "fixtures" / "assessments" / "quality" / "vesper_multisource.json"
        if vesper_ms.exists():
            print(f"[INFO] Loading VESPER multi-source fixture")
            datasets.append(("vesper_multisource", json.loads(vesper_ms.read_text())))
        else:
            # Fall back to old vesper fixture
            try:
                datasets.append(("vesper", load_fixture("vesper_assessment")))
                print(f"[INFO] Loaded vesper_assessment.json (stale row_refs — consider rebuild)")
            except FileNotFoundError:
                print(f"[WARN] No VESPER fixture found — run scripts/build_vesper_fixture.py")

    if not args.no_meridian:
        try:
            datasets.append(("meridian", load_fixture("meridian_assessment")))
            print(f"[INFO] Loaded Meridian fixture")
        except FileNotFoundError:
            print(f"[WARN] Meridian fixture not found — skipping")

    if not datasets:
        print("ERROR: No datasets available. Exiting.")
        sys.exit(1)

    run_comparison(
        models=args.models,
        datasets=datasets,
        run_ablations=args.ablate,
        max_clusters=args.max_clusters,
    )


if __name__ == "__main__":
    main()
