from src.core.accuracy_loop import AccuracyLoop
from src.core.agent_harness import SessionLog


def test_accuracy_loop_stops_on_no_evidence_gain_and_audits_every_step(tmp_path):
    loop = AccuracyLoop(SessionLog(tmp_path), max_iterations=5)
    result = loop.run(
        tenant_id="acme",
        case_id="c1",
        session_id="s1",
        evidence_pack={"pack_id": "ep2_x", "content_hash": "a" * 64},
        maker=lambda pack, feedback: {"text": "candidate", "feedback_seen": bool(feedback)},
        checker=lambda claim, pack: {"action": "refine", "support_ids": ["e1"], "gaps": ["endpoint missing"]},
        critic=lambda claim, check: {"alternative": "benign admin"},
    )
    assert result.iterations == 2
    assert result.stop_reason == "no_evidence_gain"
    events = loop.log.read("acme", "s1")
    assert events[0]["event_type"] == "evidence_pack_bound"
    assert events[-1]["event_type"] == "loop_completed"


def test_accuracy_loop_accepts_checker_verdict_not_model_confidence(tmp_path):
    result = AccuracyLoop(SessionLog(tmp_path)).run(
        tenant_id="acme",
        case_id="c1",
        session_id="s2",
        evidence_pack={"content_hash": "b" * 64},
        maker=lambda pack, feedback: {"confidence": 1.0},
        checker=lambda claim, pack: {"action": "accept", "support_ids": ["e1", "e2"]},
        critic=lambda claim, check: {},
    )
    assert result.stop_reason == "verified" and result.iterations == 1
