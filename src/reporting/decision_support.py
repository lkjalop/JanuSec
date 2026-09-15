from typing import Dict, Any, List
from datetime import datetime, timedelta

from src.reporting.schemas import DecisionGate, DecisionType, PersonaType, ActionUrgency


class DecisionSupportEngine:
    """Generate decision gates for budget, containment, blocklist, disclosure, escalation.

    This implementation returns typed `DecisionGate` objects (Pydantic models)
    and populates `action_endpoint` and `action_payload_template` to enable
    one-click actions from the UI.
    """

    def generate(self, report: Dict[str, Any]) -> List[DecisionGate]:
        gates: List[DecisionGate] = []
        severity = (report.get("risk_quantification", {}).get("severity") or "LOW").upper()
        verdict = (report.get("verdict", {}).get("final_verdict") or "REVIEW").upper()
        confidence = float(report.get("verdict", {}).get("final_confidence", 0.0))

        # Budget approval gate for high severity
        if severity in ("CRITICAL", "HIGH"):
            expected_loss = int(report.get("risk_quantification", {}).get("expected_loss_usd", 0) or 0)
            amount = min(int(expected_loss * 0.1), 100_000)
            dg = DecisionGate(
                gate_id=f"budget_{report.get('report_id','')}_{int(datetime.utcnow().timestamp())}",
                decision_type=DecisionType.APPROVE_BUDGET,
                persona=PersonaType.EXECUTIVE,
                urgency=ActionUrgency.IMMEDIATE if severity == "CRITICAL" else ActionUrgency.URGENT,
                question=f"Approve ${amount:,} incident response retainer?",
                context=f"Expected loss ${expected_loss:,}, confidence {confidence:.0%}",
                options=[{"label": "Approve", "recommended": True}, {"label": "Defer", "recommended": False}, {"label": "Decline", "recommended": False}],
                recommended_option="Approve",
                recommendation_confidence=confidence,
                recommendation_reasoning="Estimated loss and high severity trigger approval recommendation",
                action_endpoint="/api/v1/actions/approve_budget",
                action_payload_template={"report_id": report.get("report_id"), "amount_usd": amount},
                deadline=(datetime.utcnow() + timedelta(hours=4)),
            )
            gates.append(dg)

        # Containment/isolation gate for threat or suspicious
        if verdict in ("THREAT", "SUSPICIOUS"):
            affected = self._extract_entities(report, prefix="host:")
            if affected:
                dg = DecisionGate(
                    gate_id=f"isolate_{report.get('report_id','')}_{int(datetime.utcnow().timestamp())}",
                    decision_type=DecisionType.CONTAIN,
                    persona=PersonaType.SOC_ANALYST,
                    urgency=ActionUrgency.IMMEDIATE,
                    question=f"Isolate {len(affected)} affected endpoint(s)?",
                    context=f"Hosts: {', '.join(affected[:5])}",
                    options=[{"label": "Isolate All", "recommended": True}, {"label": "Isolate Critical", "recommended": False}, {"label": "Monitor Only", "recommended": False}],
                    recommended_option="Isolate All",
                    recommendation_confidence=confidence,
                    action_endpoint="/api/v1/actions/isolate",
                    action_payload_template={"hosts": affected, "report_id": report.get("report_id")},
                    deadline=(datetime.utcnow() + timedelta(minutes=30)),
                )
                gates.append(dg)

        # Blocklist update gate when IOCs present
        iocs = self._extract_iocs(report)
        ioc_count = sum(len(v) for v in iocs.values())
        if ioc_count:
            payload_tpl = {"report_id": report.get("report_id"), "iocs": iocs}
            dg = DecisionGate(
                gate_id=f"block_{report.get('report_id','')}_{int(datetime.utcnow().timestamp())}",
                decision_type=DecisionType.REMEDIATE,
                persona=PersonaType.SOC_ANALYST,
                urgency=ActionUrgency.URGENT,
                question=f"Add {ioc_count} IOCs to blocklist?",
                context=f"IPs: {', '.join(iocs.get('ip', [])[:3])} | Domains: {', '.join(iocs.get('domain', [])[:3])}",
                options=[{"label": "Block All", "recommended": True}, {"label": "Block After Review", "recommended": False}],
                recommended_option="Block All",
                recommendation_confidence=confidence,
                action_endpoint="/api/v1/actions/block",
                action_payload_template=payload_tpl,
            )
            gates.append(dg)

        # Disclosure/notification gate when exfiltration events detected
        if any("exfiltration" in str(evt.get("event_type", "")).lower() for evt in report.get("attack_timeline", [])):
            dg = DecisionGate(
                gate_id=f"disclose_{report.get('report_id','')}_{int(datetime.utcnow().timestamp())}",
                decision_type=DecisionType.NOTIFY,
                persona=PersonaType.COMPLIANCE,
                urgency=ActionUrgency.URGENT,
                question="Initiate breach notification process?",
                context="GDPR/Regulatory timelines apply",
                options=[{"label": "Notify Legal", "recommended": True}, {"label": "Wait for Investigation", "recommended": False}],
                recommended_option="Notify Legal",
                recommendation_confidence=confidence,
                action_endpoint="/api/v1/actions/create_ticket",
                action_payload_template={"report_id": report.get("report_id"), "title": "Breach notification - legal review"},
                deadline=(datetime.utcnow() + timedelta(hours=24)),
            )
            gates.append(dg)

        # Investigation escalation gate: fires for any THREAT/SUSPICIOUS verdict
        # (not just low-confidence), because even well-evidenced threats require
        # a Tier-2 deep-dive or SOC lead review to proceed to containment.
        if verdict in ("THREAT", "SUSPICIOUS", "REVIEW"):
            urgency = ActionUrgency.IMMEDIATE if verdict == "THREAT" else ActionUrgency.URGENT
            question = (
                "Escalate to Tier 2 / deep investigation?"
                if confidence < 0.65
                else "Confirm and escalate to Tier 2 for authorisation?"
            )
            context = f"Verdict: {verdict} | Confidence: {confidence:.0%}"
            dg = DecisionGate(
                gate_id=f"escalate_{report.get('report_id','')}_{int(datetime.utcnow().timestamp())}",
                decision_type=DecisionType.ESCALATE,
                persona=PersonaType.SOC_ANALYST,
                urgency=urgency,
                question=question,
                context=context,
                options=[{"label": "Escalate", "recommended": True}, {"label": "Add to Review Queue", "recommended": False}],
                recommended_option="Escalate",
                recommendation_confidence=confidence,
                action_endpoint="/api/v1/actions/create_ticket",
                action_payload_template={"report_id": report.get("report_id"), "priority": "high", "title": "Escalation: deep investigation required"},
            )
            gates.append(dg)

        return gates

    def _extract_entities(self, report: Dict[str, Any], prefix: str) -> List[str]:
        out: List[str] = []
        seen = set()
        for evt in report.get("attack_timeline", []):
            entity = evt.get("entity")
            if entity and isinstance(entity, str) and entity.startswith(prefix) and entity not in seen:
                out.append(entity.replace(prefix, ""))
                seen.add(entity)
        return out

    def _extract_iocs(self, report: Dict[str, Any]) -> Dict[str, List[str]]:
        iocs = {"ip": [], "domain": [], "hash": [], "email": []}
        seen = {k: set() for k in iocs.keys()}
        for ev in report.get("evidence_items", []):
            for t, vals in (ev.get("extracted_iocs", {}) or {}).items():
                if t in iocs:
                    for v in vals:
                        if v not in seen[t]:
                            seen[t].add(v)
                            iocs[t].append(v)
        return iocs
