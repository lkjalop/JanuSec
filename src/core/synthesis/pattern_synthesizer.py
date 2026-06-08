"""Cross-engine pattern synthesis — Stage 5l of the assessment ingest pipeline.

Combines signals from three independent engines to produce a unified per-principal
anomaly multiplier:

    ChronoGraph  → time-series z-scores (hourly bucket ring, 30d)
    IdentityGraph → directed hop adjacency + HVT reachability
    MLSignalAggregator → peak isolation-forest / ensemble anomaly score

The combined_signal drives a confidence_boost (max +0.15) applied to breach
cluster confidence after narration.  The non-linear interaction term amplifies
the boost when BOTH temporal anomaly AND graph risk are elevated simultaneously —
a single-engine spike is normal; both spiking together is the attack pattern.

Called from assessment_worker.py Stage 5l after Stages 5g (IdentityGraph),
5i (ChronoGraph accumulation), and 5j (ChronoGraph z-score elevation) complete.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.chrono.sketch_store import ChronoSketchStore
    from src.core.graph.identity_hopgraph import IdentityHopGraph

logger = logging.getLogger(__name__)

# Security-relevant metrics to check for z-score anomaly per principal.
# Subset of src.core.chrono.metric_names.M — kept local to avoid circular imports.
_SECURITY_METRICS = [
    "endpoint:lolbin_count",
    "endpoint:wmi_exec_count",
    "endpoint:encoded_ps_count",
    "iam:rc4_count",
    "iam:pre_auth_fail_count",
    "cloud:foreign_asn_count",
    "cloud:consent_grant_count",
    "bytes_out",
    "cloud_bytes_out",
    "recon_events",
    "off_hours_recon_events",
    "ml:iso_anom_count",
    "ml:ensemble_peak",
]

# z-score threshold above which a metric is considered anomalous
_ZSCORE_ANOMALY_THRESHOLD = 1.5

# Minimum combined_signal to emit the identity:cross_engine_anomaly tag
_SYNTHESIS_TAG_THRESHOLD = 0.30


def synthesize_cluster_signals(
    cluster: dict,
    chrono: "ChronoSketchStore",
    identity_graph: "IdentityHopGraph",
    ml_signals: dict,
) -> dict:
    """Compute a unified anomaly signal for all principals in *cluster*.

    Args:
        cluster: correlation cluster dict (must have shared_accounts or shared_users).
        chrono: ChronoSketchStore singleton (CHRONO).
        identity_graph: IdentityHopGraph singleton (GLOBAL_IDENTITY_GRAPH).
        ml_signals: dict from MLSignalAggregator.summary() — expected keys:
            peak_iso, peak_ensemble, anomaly_count, event_count.

    Returns:
        {
            'principals_checked': list[str],
            'best_chrono_z': float,     # max z-score across all principals × metrics
            'best_graph_risk': float,   # max lateral-movement risk score (0–1)
            'best_ml_peak': float,      # peak ML anomaly score from aggregator
            'combined_signal': float,   # fused score (0–1)
            'confidence_boost': float,  # max +0.15 additive to cluster.confidence
            'triggered': bool,          # True if combined_signal > threshold
            'anomalous_metrics': list[str],
        }
    """
    principals = list(dict.fromkeys(
        (cluster.get('shared_accounts') or []) +
        (cluster.get('shared_users') or [])
    ))[:5]

    best_chrono_z = 0.0
    best_graph_risk = 0.0
    anomalous_metrics: list[str] = []

    for principal in principals:
        # ── ChronoGraph: max z-score across security metrics ─────────────────
        # ChronoSketchStore.z_score() takes window_seconds (not window_hours)
        # and returns a dict with key 'z' (not 'z_score').
        for metric in _SECURITY_METRICS:
            try:
                z_result = chrono.z_score('user', principal, metric, window_seconds=72 * 3600)
                z = float((z_result or {}).get('z') or 0.0)
                if z >= _ZSCORE_ANOMALY_THRESHOLD:
                    anomalous_metrics.append(f"{principal}:{metric}={z:.1f}σ")
                best_chrono_z = max(best_chrono_z, z)
            except Exception:
                pass

        # ── IdentityGraph: hop adjacency + HVT reachability ──────────────────
        try:
            # Try prefixed node key first (standard form), then bare name
            adj = (
                identity_graph._adj.get(f'user:{principal}')
                or identity_graph._adj.get(principal)
                or []
            )
            hvt_reachable = sum(
                1 for (dst, _etype, _ts, _weight) in adj
                if dst in identity_graph._high_value
            )
            # hop_score: 0.0 for no edges, scaling to 1.0 at 10+ edges or any HVT reach
            hop_score = min(1.0, (len(adj) / 10.0) + (hvt_reachable * 0.4))
            best_graph_risk = max(best_graph_risk, hop_score)
        except Exception:
            pass

    # ── MLSignalAggregator: peak anomaly across all sources ──────────────────
    best_ml_peak = float(
        ml_signals.get('peak_iso')
        or ml_signals.get('peak_ensemble')
        or 0.0
    )

    # ── Non-linear fusion ────────────────────────────────────────────────────
    # Normalise chrono_z to [0, 1] (3σ = full score)
    chrono_norm = min(1.0, best_chrono_z / 3.0)

    # Weighted base: temporal 40%, graph 30%, ML 30%
    base = 0.4 * chrono_norm + 0.3 * best_graph_risk + 0.3 * best_ml_peak

    # Interaction: amplify when BOTH chrono AND graph are elevated (co-occurrence
    # of temporal anomaly + lateral movement = high-confidence attack signal)
    interaction = chrono_norm * best_graph_risk * 0.4

    combined = min(1.0, base + interaction)
    confidence_boost = round(combined * 0.15, 3)  # cap +0.15

    return {
        'principals_checked': principals,
        'best_chrono_z': round(best_chrono_z, 3),
        'best_graph_risk': round(best_graph_risk, 3),
        'best_ml_peak': round(best_ml_peak, 3),
        'combined_signal': round(combined, 3),
        'confidence_boost': confidence_boost,
        'triggered': combined > _SYNTHESIS_TAG_THRESHOLD,
        'anomalous_metrics': anomalous_metrics[:10],
    }
