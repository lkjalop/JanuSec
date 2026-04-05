# Drift baseline harness placeholder.
# In a fuller implementation we'd compute JS divergence against a stored baseline distribution.

import math


def js_divergence(p, q):
    m = [(pi+qi)/2 for pi,qi in zip(p,q, strict=False)]
    def kld(a,b):
        return sum(ai*math.log(ai/bi) for ai,bi in zip(a,b, strict=False) if ai>0 and bi>0)
    return 0.5*kld(p,m)+0.5*kld(q,m)

def test_js_divergence_zero():
    p = [0.2,0.3,0.5]
    assert js_divergence(p,p) == 0

def test_js_divergence_symmetry():
    p = [0.1,0.4,0.5]
    q = [0.3,0.3,0.4]
    assert abs(js_divergence(p,q)-js_divergence(q,p)) < 1e-9
