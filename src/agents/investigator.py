"""
Investigator agent — executes plan steps using the tool registry.

For each PlanStep from the Planner:
  1. Classify the action via autonomy_gate
  2. If Zone 0 → skip (blocked)
  3. If Zone 1 → execute tool immediately
  4. If Zone 2/3 → queue proposed action, skip execution
  5. Sanitise output through PII redactor
  6. Scan for prompt injection in results
  7. Track cumulative scope
  8. Return RawFinding list
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

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

    findings: List[RawFinding] = []
    proposed: List[ProposedAction] = []

    for idx, step in enumerate(plan.steps):
        LOGGER.info("cycle %d step %d: %s (%s)",
                     plan.cycle, idx, step.tool, step.reason[:80])

        # Inject assessment_id into params (tools need it for scoping)
        step.params.setdefault("assessment_id", context.assessment_id)

        # Classify and enforce
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

        # Zone 1: execute the tool
        tool_fn = get_tool(step.tool)
        if tool_fn is None:
            LOGGER.error(
                "investigator: unknown tool %r at step %d — investigation step produced no output; "
                "check tool registry registration",
                step.tool, idx,
            )
            findings.append(RawFinding(
                step_index=idx,
                tool=step.tool,
                summary=f"[ERROR] Tool not found: {step.tool!r}. Step skipped — results are incomplete.",
                evidence={"error": "tool_not_registered", "tool": step.tool},
            ))
            continue

        try:
            result = tool_fn(step.params)
        except Exception as exc:
            LOGGER.exception("tool %s failed at step %d", step.tool, idx)
            findings.append(RawFinding(
                step_index=idx,
                tool=step.tool,
                summary=f"Tool error: {exc}",
            ))
            continue

        # Track cumulative scope
        data_bytes = result.get("data_volume_bytes", 0)
        scope.record(data_bytes=data_bytes, queries=1)

        # PII redaction on evidence before it enters agent context
        evidence = result.get("evidence", {})
        if isinstance(evidence, dict):
            evidence = redact_for_llm(evidence, sensitive_fields=_SENSITIVE_RESULT_FIELDS)

        # Prompt injection scan on summary
        summary = result.get("summary", "")
        if scan_prompt_injection(summary):
            LOGGER.error("PROMPT INJECTION detected in tool %s output!", step.tool)
            summary = "[REDACTED — prompt injection detected]"
            evidence = {"warning": "prompt injection detected in tool output"}

        findings.append(RawFinding(
            step_index=idx,
            tool=step.tool,
            summary=summary,
            evidence=evidence,
            source_count=result.get("source_count", 1),
            data_volume_bytes=data_bytes,
        ))

    return findings, proposed
