from src.api.graph_sessions import alpha_curve
import asyncio


def test_alpha_curve_monotonic():
    # alpha_curve is an async router handler; await it
    res = asyncio.get_event_loop().run_until_complete(alpha_curve(step=0.2))
    assert 'curve' in res
    curve = res['curve']
    assert isinstance(curve, list) and len(curve) >= 5
    # ensure alpha values are within configured min/max
    base = res.get('base_alpha')
    mn = res.get('min_alpha')
    mx = res.get('max_alpha')
    for pt in curve:
        a = pt.get('alpha')
        assert a >= mn and a <= mx
    # ensure alpha does not increase as volatility increases (monotonic non-increasing)
    alphas = [pt.get('alpha') for pt in curve]
    for i in range(1, len(alphas)):
        assert alphas[i] <= alphas[i-1] + 1e-6
