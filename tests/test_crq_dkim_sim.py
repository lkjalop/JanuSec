from src.simulations.crq_dkim_sim import run_permutations, prewarm_ollama


def test_run_permutations_and_escalation():
    results = run_permutations()
    assert isinstance(results, list)
    # ensure we saw varied adjusted composites and at least one escalation
    composites = {r.get('adjusted_composite') for r in results}
    assert len(composites) > 1
    assert any(r.get('escalate') for r in results)


def test_prewarm_ollama_noop():
    res = prewarm_ollama()
    # we only assert it returns a dict; it may be unavailable in CI/dev machines
    assert isinstance(res, dict)
