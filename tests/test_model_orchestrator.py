from core.hunt.model_orchestrator import select_model


def test_model_selection_severity_high():
    dec = select_model(severity=0.9, confidence=0.9, budget_remaining_ratio=1.0, availability={0:True,1:True,2:True,3:True,4:False})
    assert dec.tier == 3

def test_model_selection_low_severity():
    dec = select_model(severity=0.1, confidence=0.9, budget_remaining_ratio=1.0, availability={0:True})
    assert dec.tier == 0

def test_model_selection_escalation_due_confidence():
    dec = select_model(severity=0.4, confidence=0.2, budget_remaining_ratio=1.0, availability={0:True,1:True,2:True,3:True})
    # base desired tier 1, escalated to 2
    assert dec.tier == 2
