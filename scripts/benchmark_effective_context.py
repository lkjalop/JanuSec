"""Measure effective cyber-evidence context, not advertised context length.

The benchmark places evidence for three separate cases among deterministic
distractors and asks the model to return case membership plus evidence IDs.
Results are append-only JSONL so provider failures remain visible.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


NEEDLES = [
    {"evidence_id": "ev-james-entry", "case": "james", "fact": "Excel spawned cmd and encoded PowerShell on ws-james."},
    {"evidence_id": "ev-wei-forward", "case": "wei", "fact": "Wei created an external mailbox forwarding rule to sinobiz-sg.com."},
    {"evidence_id": "ev-crawler-get", "case": "crawler", "fact": "185.234.219.47 successfully downloaded an internal brief from a public S3 prefix."},
]


def _prompt(target_tokens: int, packs: list[dict[str, Any]] | None = None) -> tuple[str, dict[str, str]]:
    if packs:
        rows: list[tuple[str, dict[str, Any]]] = []
        ownership: dict[str, str] = {}
        for pack in packs:
            case_id = str(pack.get("case_id") or "unknown")
            for row in pack.get("supporting_evidence") or []:
                if not isinstance(row, dict):
                    continue
                rid = str(row.get("evidence_id") or row.get("record_id") or row.get("id") or "")
                if not rid:
                    continue
                ownership[rid] = case_id
                rows.append((case_id, row))
        # Round-robin the cases so evidence for one case cannot occupy only one
        # end of a long prompt. Use real retrieved records; never synthetic facts.
        rows.sort(key=lambda item: (str(item[1].get("occurred_at") or item[1].get("timestamp") or ""), item[0]))
        budget_chars = max(4000, int(target_tokens * 3.2))
        blocks: list[str] = []
        used = 0
        for case_id, row in rows:
            block = json.dumps({"case_id": case_id, "evidence": row}, ensure_ascii=False, separators=(",", ":")) + "\n"
            if used + len(block) > budget_chars and blocks:
                break
            blocks.append(block)
            used += len(block)
        case_ids = sorted({case for case, _ in rows})
        prompt = (
            "The following records come from immutable, separately retrieved Evidence Packs. "
            "Do not merge cases. Return JSON only as {cases:{case_id:{summary:string,evidence_ids:[string]}},"
            "uncertainties:[string]}. Cite at most 8 supplied evidence IDs per case and make no unsupported claim. "
            f"Required case IDs: {case_ids}.\n" + "".join(blocks)
        )
        return prompt, ownership
    distractor = "Benign service heartbeat completed successfully with no data transfer.\n"
    target_chars = max(1000, target_tokens * 4)
    middle = distractor * max(1, target_chars // len(distractor))
    thirds = len(middle) // 3
    corpus = middle[:thirds] + json.dumps(NEEDLES[0]) + middle[thirds:2 * thirds] + json.dumps(NEEDLES[1]) + middle[2 * thirds:] + json.dumps(NEEDLES[2])
    return (
        "Partition the following telemetry into james, wei, and crawler. Return JSON only as "
        "{cases:{case:[evidence_id]}, excluded:[]}. Never merge cases.\n" + corpus
    ), {item["evidence_id"]: item["case"] for item in NEEDLES}


def _run(model: str, context_tokens: int, timeout: int, packs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    prompt, ownership = _prompt(context_tokens, packs)
    payload = json.dumps({
        "model": model, "prompt": prompt, "stream": False, "think": False,
        "format": "json", "options": {"num_ctx": context_tokens, "num_predict": 768, "temperature": 0},
    }).encode()
    started = time.perf_counter()
    request = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read())
        output = json.loads(raw.get("response") or "{}")
        cases = output.get("cases") if isinstance(output, dict) else {}
        if packs:
            cited: list[tuple[str, str]] = []
            for case_id, value in (cases or {}).items():
                refs = value.get("evidence_ids") if isinstance(value, dict) else value if isinstance(value, list) else []
                cited.extend((str(case_id), str(ref)) for ref in refs or [])
            valid = sum(1 for case_id, ref in cited if ownership.get(ref) == case_id)
            covered = {case_id for case_id, ref in cited if ownership.get(ref) == case_id}
            expected_cases = {str(pack.get("case_id")) for pack in packs}
            return {
                "status": "ok", "output": output,
                "evidence_recall": len(covered) / max(1, len(expected_cases)),
                "separation": valid / max(1, len(cited)),
                "unsupported_citation_rate": 1 - (valid / max(1, len(cited))),
                "cited_count": len(cited), "cases_covered": sorted(covered),
                "effective_prompt_tokens_estimate": round(len(prompt) / 4),
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "prompt_eval_count": raw.get("prompt_eval_count"), "eval_count": raw.get("eval_count"),
                "empty_response": not bool(raw.get("response")),
            }
        found = {
            item["evidence_id"]
            for item in NEEDLES
            if item["evidence_id"] in set((cases or {}).get(item["case"]) or [])
        }
        return {
            "status": "ok", "output": output, "evidence_recall": len(found) / len(NEEDLES),
            "separation": 1.0 if len(found) == len(NEEDLES) else len(found) / len(NEEDLES),
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "prompt_eval_count": raw.get("prompt_eval_count"), "eval_count": raw.get("eval_count"),
            "empty_response": not bool(raw.get("response")),
        }
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            detail = ""
        return {
            "status": "failed", "error": f"HTTPError:{exc.code}", "provider_error": detail,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}:{str(exc)[:300]}", "latency_ms": round((time.perf_counter() - started) * 1000, 2)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+", default=["qwen3:14b", "qwen3.8:27b"])
    parser.add_argument("--contexts", nargs="+", type=int, default=[8192, 16384, 32768, 65536])
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--output", type=Path, default=Path("dump/reports/effective-context-benchmark.jsonl"))
    parser.add_argument("--evidence-pack", action="append", type=Path, default=[])
    args = parser.parse_args()
    packs: list[dict[str, Any]] = []
    for path in args.evidence_pack:
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(loaded, str):
            loaded = json.loads(loaded)
        if not isinstance(loaded, dict):
            raise ValueError(f"invalid evidence pack: {path}")
        packs.append(loaded)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as handle:
        for model in args.models:
            for context in args.contexts:
                record = {
                    "benchmark_id": "janusec.evidence-pack-context/v1" if packs else "janusec.literal-case-partition-smoke/v1",
                    "run_at": dt.datetime.now(dt.timezone.utc).isoformat(), "model": model,
                    "context_tokens": context, **_run(model, context, args.timeout, packs or None),
                }
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                handle.flush()
                print(json.dumps(record, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
