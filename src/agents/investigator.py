"""
Investigator agent — executes plan steps using the tool registry.

For each PlanStep from the Planner:
  1. Classify the action via autonomy_gate
  2. If Zone 0 → skip (blocked)
  3. If Zone 1 → execute tool immediately (all Zone 1 steps run in parallel)
  4. If Zone 2/3 → queue proposed action, skip execution
  5. Sanitise output through PII redactor
  6. Scan for prompt injection in results
  7. Track cumulative scope
  8. Return RawFinding list

Scatter-gather: all Zone 1 plan steps are dispatched concurrently via asyncio.gather.
Synchronous tools run in a thread-pool executor (asyncio.to_thread).  The autonomy
gate is evaluated sequentially first so scope limits and injection scans are
deterministic, then only AUTO steps are fanned-out for parallel execution.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.agents.autonomy_gate import (
    ScopeTracker,
    enforce,
    scan_prompt_injection,
)
from src.agents.tools.registry import get_tool
from src.agents.types import (
    ActionZone,
    InvestigationContext,
    InvestigationPlan,
    ProposedAction,
    RawFinding,
)
from src.privacy.redaction import redact_for_llm

LOGGER = logging.getLogger(__name__)

# Fields to redact before passing tool results to LLM context
_SENSITIVE_RESULT_FIELDS = ["password", "secret", "token", "key", "credential", "cookie"]


async def investigate(
    plan: InvestigationPlan,
    context: InvestigationContext,
    *,
    scope: Optional[ScopeTracker] = None,
) -> tuple[List[RawFinding], List[ProposedAction]]:
    """Execute all steps in the plan, respecting autonomy boundaries.

    Zone classification is done sequentially (deterministic scope tracking);
    Zone 1 (AUTO) tool calls are then dispatched in parallel via asyncio.gather.

    Returns:
        (raw_findings, proposed_actions)
        - raw_findings: unverified results from Zone 1 tool executions
        - proposed_actions: Zone 2/3 actions queued for human approval
    """
    if scope is None:
        scope = ScopeTracker(
            max_bytes=context.max_tokens * 4,  # rough char estimate
            max_queries=context.max_queries,
        )

    proposed: List[ProposedAction] = []
    # Steps classified as AUTO and ready to execute: (idx, step, tool_fn)
    auto_steps: list = []

    # ── Phase 1: Sequential autonomy gate (deterministic) ────────────────────
    for idx, step in enumerate(plan.steps):
        LOGGER.info("cycle %d step %d: %s (%s)",
                     plan.cycle, idx, step.tool, step.reason[:80])

        # Inject assessment_id and tenant context into params
        step.params.setdefault("assessment_id", context.assessment_id)
        step.params.setdefault("tenant_id", context.tenant_id)

        zone, action = enforce(
            step.tool,
            step.params,
            context=context,
            scope=scope,
            cycle=plan.cycle,
            step=idx,
            hypothesis=plan.hypothesis,
            reason=step.reason,
        )

        if zone == ActionZone.BLOCKED:
            LOGGER.warning("step %d BLOCKED: %s", idx, step.tool)
            continue

        if zone in (ActionZone.PROPOSE, ActionZone.ESCALATE):
            if action:
                proposed.append(action)
            LOGGER.info("step %d queued for approval: %s (zone %d)",
                         idx, step.tool, int(zone))
            continue

        tool_fn = get_tool(step.tool)
        if tool_fn is None:
            LOGGER.error(
                "investigator: unknown tool %r at step %d — check tool registry",
                step.tool, idx,
            )
            auto_steps.append((idx, step, None))
            continue

        auto_steps.append((idx, step, tool_fn))

    if not auto_steps:
        return [], proposed

    # ── Phase 2: Parallel tool execution (scatter-gather) ────────────────────
    async def _run_one(idx: int, step, tool_fn) -> RawFinding:
        if tool_fn is None:
            return RawFinding(
                step_index=idx,
                tool=step.tool,
                summary=f"[ERROR] Tool not found: {step.tool!r}. Step skipped.",
                evidence={"error": "tool_not_registered", "tool": step.tool},
            )
        try:
            # Run sync tools in the thread pool so they don't block the event loop.
            # Async tools are awaited directly (none currently, but future-safe).
            if asyncio.iscoroutinefunction(tool_fn):
                result = await tool_fn(step.params)
            else:
                result = await asyncio.to_thread(tool_fn, step.params)
        except Exception as exc:
            LOGGER.exception("tool %s failed at step %d", step.tool, idx)
            return RawFinding(step_index=idx, tool=step.tool, summary=f"Tool error: {exc}")

        data_bytes = result.get("data_volume_bytes", 0)
        scope.record(data_bytes=data_bytes, queries=1)

        evidence = result.get("evidence", {})
        if isinstance(evidence, dict):
            evidence = redact_for_llm(evidence, sensitive_fields=_SENSITIVE_RESULT_FIELDS)

        summary = result.get("summary", "")
        if scan_prompt_injection(summary):
            LOGGER.error("PROMPT INJECTION detected in tool %s output!", step.tool)
            summary = "[REDACTED — prompt injection detected]"
            evidence = {"warning": "prompt injection detected in tool output"}

        return RawFinding(
            step_index=idx,
            tool=step.tool,
            summary=summary,
            evidence=evidence,
            source_count=result.get("source_count", 1),
            data_volume_bytes=data_bytes,
        )

    raw_results = await asyncio.gather(
        *[_run_one(idx, step, fn) for idx, step, fn in auto_steps],
        return_exceptions=True,
    )

    findings: List[RawFinding] = []
    for res in raw_results:
        if isinstance(res, Exception):
            LOGGER.warning("scatter-gather step raised: %s", res)
        elif isinstance(res, RawFinding):
            findings.append(res)

    return findings, proposed
