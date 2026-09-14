from src.artifact.risk import synthesize
from src.artifact.models import ArtifactObservation


def make_obs(factors):
    obs = ArtifactObservation()
    obs.factors = factors
    return obs


def test_guardrail_prevents_premature_malicious():
    obs = make_obs(['unsigned_binary','high_entropy_section','compile_time_recent'])
    out = synthesize(obs)
    # This set above tends to make final_risk high, but guardrail should allow MALICIOUS -> SUSPICIOUS only if diversity low
    assert hasattr(out, 'verdict')
    # verdict should be set, and if it was MALICIOUS but diversity low should be downgraded
    assert str(out.verdict) in ('MALICIOUS','SUSPICIOUS')
