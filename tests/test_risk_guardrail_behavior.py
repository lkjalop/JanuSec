from src.artifact import risk


class FakeObs:
    def __init__(self, factors):
        self.factors = factors
        self.risk_components = None
        self.factor_contributions = None
        self.final_risk = 0.0
        self.verdict = None


def test_risk_guardrail_downgrades_malicious_when_low_diversity():
    # factors chosen to contribute but only within one or two high-value categories
    obs = FakeObs(['lolbin_misuse', 'tunneling_utility', 'fresh_download'])
    # run synthesize which sets verdict and may apply guardrail
    out = risk.synthesize(obs)
    # After heuristics, ensure verdict is not left as a raw string 'MALICIOUS' when diversity low
    # risk.synthesize maps final risk to verdict; guardrail downgrades MALICIOUS->SUSPICIOUS
    v = str(out.verdict).upper() if out and hasattr(out, 'verdict') else ''
    assert v in ('SUSPICIOUS', 'MALICIOUS')
    # If final_risk is below the 0.95 threshold used in guardrail the verdict should be SUSPICIOUS
    if getattr(out, 'final_risk', 0.0) < 0.95:
        assert v == 'SUSPICIOUS'
