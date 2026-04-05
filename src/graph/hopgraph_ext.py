from __future__ import annotations
import time, math
from typing import Dict, Any, List
from src.graph.hopgraph import HopGraph  # type: ignore

try:
    from src.core.correlation.factor_registry import FACTOR_REGISTRY  # type: ignore
except Exception:  # pragma: no cover
    FACTOR_REGISTRY = None  # type: ignore
try:
    from src.core.correlation.temporal_sequencer import GLOBAL_TEMPORAL_SEQUENCER  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_TEMPORAL_SEQUENCER = None  # type: ignore
try:
    from src.core.correlation.cooccurrence import GLOBAL_COOCCURRENCE  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_COOCCURRENCE = None  # type: ignore
try:
    from src.core.correlation.suppression import GLOBAL_SUPPRESSION_ENGINE  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_SUPPRESSION_ENGINE = None  # type: ignore

class ExtendedHopGraph(HopGraph):
    def add_node_factor(self, node: str, factor: str, decision_id: str | None = None):  # type: ignore[override]
        super().add_node_factor(node, factor, decision_id)
        try:
            nf = self.nodes.get(node, {}).get('factors', [])
            if nf and GLOBAL_COOCCURRENCE is not None:
                GLOBAL_COOCCURRENCE.record(nf)
        except Exception:
            pass

    def ingest_event(self, event: Dict[str, Any], source: str = 'event'):  # type: ignore[override]
        super().ingest_event(event, source)
        try:
            proc = event.get('process') or event.get('process_name')
            pid = event.get('pid')
            if proc:
                proc_key = proc.lower() + (f":{pid}" if pid else "")
                node_id = f"process:{proc_key}"
                factors = self.get_node_factors(node_id)
                if factors and GLOBAL_SUPPRESSION_ENGINE is not None:
                    adj = GLOBAL_SUPPRESSION_ENGINE.evaluate({}, factors)
                    if adj:
                        for f, delta in adj.items():
                            if delta <= -500:
                                try:
                                    lst = self.nodes[node_id].get('factors', [])
                                    if f in lst:
                                        lst.remove(f)
                                except Exception:
                                    pass
                            else:
                                if FACTOR_REGISTRY is not None and f in FACTOR_REGISTRY.weights:
                                    FACTOR_REGISTRY.weights[f] = max(0.01, FACTOR_REGISTRY.weights[f] + delta)
        except Exception:
            pass

    def explain_chain(self, start: str, max_depth: int = 4, beam_width: int = 5, top_k: int = 3):  # type: ignore[override]
        result = super().explain_chain(start, max_depth=max_depth, beam_width=beam_width, top_k=top_k)
        try:
            chains = result.get('chains', [])
            if not chains:
                return result
            last_chain = chains[-1]
            # collect factors for temporal recording
            encountered: List[str] = []
            for hop in last_chain.get('hops', []):
                src = hop.get('src'); dst = hop.get('dst')
                for nid in (src, dst):
                    if nid and nid in self.nodes:
                        for f in self.nodes[nid].get('factors', []):
                            if f not in encountered:
                                encountered.append(f)
            if encountered and GLOBAL_COOCCURRENCE is not None and len(encountered) > 1:
                pair_scores = []
                for i in range(len(encountered)):
                    for j in range(i+1, len(encountered)):
                        pair_scores.append(GLOBAL_COOCCURRENCE.score_pair(encountered[i], encountered[j]))
                if pair_scores:
                    last_chain['cooccurrence_boost'] = sum(pair_scores) / len(pair_scores)
                last_chain['factors'] = encountered
            if encountered and GLOBAL_TEMPORAL_SEQUENCER is not None:
                GLOBAL_TEMPORAL_SEQUENCER.record(start, encountered)
                last_chain['temporal_matches'] = GLOBAL_TEMPORAL_SEQUENCER.detect()
            # Scoring hook: adjust chain score using co-occurrence + temporal signals (capped)
            try:
                base_score = float(last_chain.get('score') or 0.0)
                boost = float(last_chain.get('cooccurrence_boost') or 0.0)
                t_matches = last_chain.get('temporal_matches') or []
                t_boost = 0.0
                if t_matches:
                    # aggregate pattern span efficiency: shorter span -> higher boost
                    for m in t_matches[:5]:
                        span = float(m.get('span_seconds') or 0.0)
                        # inverse log scaling (avoid division by zero)
                        eff = 1.0 / math.log(max(2.0, span+1.0), 2)
                        t_boost += eff
                    t_boost = t_boost / max(1.0, len(t_matches))
                # normalization: sqrt dampen
                combined = boost + t_boost
                if combined > 0:
                    adj = math.sqrt(combined)
                    new_score = base_score + adj
                    # Cap growth to 50% of (1 - base_score) to avoid runaway inflation
                    ceiling = base_score + (1.0 - min(1.0, base_score)) * 0.5
                    last_chain['score_adjusted'] = min(ceiling, new_score)
                else:
                    last_chain['score_adjusted'] = base_score
            except Exception:
                pass
            # Hop confidence fields derived from factor severity blend of src/dst
            try:
                from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model  # type: ignore
                for ch in chains:
                    for hop in ch.get('hops', []):
                        src = hop.get('src'); dst = hop.get('dst')
                        sf = self.get_node_factors(src) if src else []
                        df = self.get_node_factors(dst) if dst else []
                        sev_src = aggregate_threat_model(sf).get('severity',0.0) if sf else 0.0
                        sev_dst = aggregate_threat_model(df).get('severity',0.0) if df else 0.0
                        hop_conf = round(min(1.0, (sev_src + sev_dst)/2.0),3)
                        hop['hop_confidence'] = hop_conf
            except Exception:
                pass
        except Exception:
            pass
        return result

GLOBAL_EXT_HOPGRAPH = ExtendedHopGraph()

__all__ = ["ExtendedHopGraph", "GLOBAL_EXT_HOPGRAPH"]
