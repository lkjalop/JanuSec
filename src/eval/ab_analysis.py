import math
from typing import Dict, Tuple
try:
    from scipy import stats  # type: ignore
except Exception:
    stats = None  # type: ignore


def uplift_and_pvalue(control_tp: int, control_total: int, treat_tp: int, treat_total: int) -> Dict[str, float]:
    """Return uplift (difference in proportions), two-sided p-value.

    Prefers SciPy chi-square; falls back to Wald z-test when SciPy unavailable.
    """
    pc = control_tp / control_total if control_total else 0.0
    pt = treat_tp / treat_total if treat_total else 0.0
    uplift = pt - pc
    p = 1.0
    if stats is not None:
        try:
            table = [[treat_tp, max(0, treat_total - treat_tp)], [control_tp, max(0, control_total - control_tp)]]
            chi2, p, dof, ex = stats.chi2_contingency(table)
        except Exception:
            p = 1.0
    else:
        # Wald z-test approximation
        pooled = (control_tp + treat_tp) / float((control_total + treat_total) or 1)
        var = pooled * (1 - pooled)
        se = math.sqrt(var * (1.0 / (control_total or 1) + 1.0 / (treat_total or 1)))
        z = (pt - pc) / se if se and math.isfinite(se) and se > 0 else 0.0
        p = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))
    return {'control_prop': pc, 'treat_prop': pt, 'uplift': uplift, 'p_value': float(p)}


def beta_interval(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Return Bayesian credible interval using Beta posterior (uniform prior).

    Falls back to normal approximation when SciPy unavailable.
    """
    if n <= 0:
        return 0.0, 1.0
    if stats is not None:
        a = 1 + k
        b = 1 + n - k
        lo = stats.beta.ppf(alpha/2, a, b)
        hi = stats.beta.ppf(1 - alpha/2, a, b)
        return float(lo), float(hi)
    # Normal approximation
    p = k / n
    z = 1.96 if abs(alpha - 0.05) < 1e-9 else 1.96
    se = math.sqrt((p * (1 - p)) / n)
    lo = max(0.0, p - z * se)
    hi = min(1.0, p + z * se)
    return float(lo), float(hi)


def sample_size_for_uplift(baseline_prop: float, min_detectable_uplift: float, alpha: float = 0.05, power: float = 0.8) -> int:
    """Approximate sample size per group for detecting uplift on proportions using normal approx."""
    p1 = baseline_prop
    p2 = baseline_prop + min_detectable_uplift
    if stats is not None:
        z_alpha = abs(stats.norm.ppf(alpha/2))
        z_beta = abs(stats.norm.ppf(1 - power))
    else:
        # Defaults close to alpha=0.05, power=0.8
        z_alpha = 1.96
        z_beta = 0.84
    sd = math.sqrt(p1*(1-p1) + p2*(1-p2))
    if min_detectable_uplift == 0:
        return 0
    n = ((z_alpha + z_beta) * sd / min_detectable_uplift) ** 2
    return int(math.ceil(n))
