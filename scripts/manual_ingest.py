"""Manual ingestion helper.

Usage: python scripts/manual_ingest.py tests/fixtures/azure_defender/sample1.json

The script instantiates an EventPipeline with a minimal config, loads a
single JSON event (or an array) and runs it through the pipeline. It then
calls the local LLM summarizer to produce tier-1 and tier-2 summaries and
prints explainable enrichment metadata where available.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
import os
import sys

# Ensure the repository root is on sys.path so `import src.*` works
_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from src.core.event_pipeline.pipeline import EventPipeline
# For a lightweight manual ingestion run, prefer only the ebpf_analysis stage
try:
    from src.core.event_pipeline.stages import ebpf_analysis_stage, STAGE_DEFINITIONS as _ALL_STAGES  # type: ignore
except Exception:
    ebpf_analysis_stage = None
    _ALL_STAGES = None
from src.llm.local_summarizer import summarize_tier1, summarize_tier2


async def run(event_obj: dict) -> None:
    # Minimal config object (can be extended)
    class C: pass
    cfg = C()
    # Pipeline instantiation
    pipeline = EventPipeline(cfg)
    # If available, restrict stages to only the ebpf analysis stage to avoid
    # importing heavy optional modules during this lightweight demo.
    if ebpf_analysis_stage is not None:
        try:
            from src.core.event_pipeline.stages import StageDefinition
            # Build a minimal stage definition list with just ebpf_analysis
            pipeline_stage_defs = [StageDefinition('ebpf_analysis', ebpf_analysis_stage)]
            # Patch the module-level STAGE_DEFINITIONS used by the pipeline
            import src.core.event_pipeline.stages as _st
            _st.STAGE_DEFINITIONS = pipeline_stage_defs
        except Exception:
            pass
    try:
        await pipeline.initialize()
    except Exception:
        pass
    result = await pipeline.process_event(event_obj)
    print('\n--- Pipeline Result ---')
    print('event_id:', result.event_id)
    print('stage:', result.stage)
    print('confidence:', result.confidence)
    print('factors:', result.factors)
    print('processing_time_ms:', getattr(result, 'processing_time', None) or getattr(result, 'processing_time', None))
    print('\n--- Enrichment Metadata ---')
    print(json.dumps(result.metadata or {}, indent=2))

    # Prepare text to summarize: factors + a short event text
    text = f"Event ID: {result.event_id}\nFactors: {', '.join(result.factors or [])}\nEvent: {json.dumps(event_obj)}"

    print('\n--- Tier-1 Summary (triage) ---')
    print(summarize_tier1(text))

    print('\n--- Tier-2 Summary (detailed) ---')
    print(summarize_tier2(text))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print('Usage: python scripts/manual_ingest.py <path-to-json-event>')
        return 2
    p = Path(argv[1])
    if not p.exists():
        print('File not found:', p)
        return 1
    raw = p.read_text(encoding='utf-8')
    try:
        payload = json.loads(raw)
    except Exception:
        print('Failed to parse JSON')
        return 1
    # Support either single dict or list
    if isinstance(payload, list) and payload:
        event = payload[0]
    elif isinstance(payload, dict):
        event = payload
    else:
        print('Unsupported JSON payload; expected object or array')
        return 1
    asyncio.run(run(event))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
