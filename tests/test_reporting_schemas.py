import json
from src.reporting.schemas import DecisionGate, FeedbackCapture
from src.reporting.decision_support import DecisionSupportEngine


def test_decision_gate_serialization():
    dg = DecisionGate(
        gate_id="g1",
        decision_type="contain",
        persona="soc_analyst",
        urgency="immediate",
        question="Isolate host?",
        context="Test",
        options=[{"label":"Isolate","recommended":True}],
    )
    s = dg.model_dump_json()
    assert 'gate_id' in s
    d = json.loads(s)
    assert d['gate_id'] == 'g1'


def test_feedback_capture_model():
    fb = FeedbackCapture(
        feedback_id="fb1",
        report_id="r1",
        analyst_id="a1",
        correction_type="false_positive",
        original_value="THREAT",
        corrected_value="CLEAN",
        correction_reasoning="Not a threat",
    )
    j = fb.model_dump_json()
    assert 'feedback_id' in j


def test_decision_support_generates_gates():
    engine = DecisionSupportEngine()
    report = {
        'report_id': 'r1',
        'risk_quantification': {'severity': 'HIGH', 'expected_loss_usd': 100000},
        'verdict': {'final_verdict': 'THREAT', 'final_confidence': 0.95},
        'attack_timeline': [{'event_type': 'exfiltration', 'entity': 'host:host1'}],
        'evidence_items': [],
    }
    gates = engine.generate(report)
    assert isinstance(gates, list)
    assert any(getattr(g, 'decision_type', None) for g in gates)
