from __future__ import annotations

from typing import Any, Dict, List

from .taxonomy_loader import ControlTaxonomyLoader
from .knowledge_graph import KnowledgeGraph


DOMAIN_MAP = {
    "A.5": "Information Security Policies",
    "A.6": "Organization of Information Security",
    "A.8": "Asset Management",
    "A.9": "Access Control",
}


class LogicGateEngine:
    def __init__(self) -> None:
        self.graph = KnowledgeGraph()
        self._controls_cache: List[Dict[str, Any]] | None = None
        self._loader = ControlTaxonomyLoader()

    async def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        state = await self.context_gate(state)
        state = await self.evidence_scoring_gate(state)
        state = await self.confidence_gate(state)
        state = await self.gap_analysis_gate(state)
        return state

    async def context_gate(self, state: Dict[str, Any]) -> Dict[str, Any]:
        state.setdefault('context', {})
        state['context'].setdefault('framework', state.get('framework', 'ISO 27001:2022'))
        return state

    async def evidence_scoring_gate(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Score evidence chunks against control keywords (simple heuristic)."""
        chunks: List[Dict[str, Any]] = state.get('chunks', [])
        if self._controls_cache is None:
            self._controls_cache = self._loader.load()
        # Filter by requested framework if present
        try:
            fw = str(state.get('context', {}).get('framework') or '').upper()
        except Exception:
            fw = ''
        controls_iter = self._controls_cache
        if fw:
            controls_iter = [c for c in self._controls_cache or [] if str(c.get('framework','')).upper() == fw]
        control_scores: Dict[str, Dict[str, Any]] = {}
        for ctrl in controls_iter:
            cid = ctrl['control_id']
            kw = [str(k).lower() for k in ctrl.get('keywords', [])]
            per_chunk_scores: List[tuple[str, float]] = []
            for c in chunks:
                txt = str(c.get('text','')).lower()
                s = 0
                for k in kw:
                    if k and k in txt:
                        s += 1
                norm = s / max(len(kw), 1)
                per_chunk_scores.append((c['id'], norm))
            top = sorted(per_chunk_scores, key=lambda x: x[1], reverse=True)[:3]
            agg = sum(v for _, v in top) / (len(top) or 1)
            control_scores[cid] = {
                'control_id': cid,
                'title': ctrl.get('title'),
                'raw_score': agg,
                'chunk_scores': per_chunk_scores,
            }
        state['control_raw'] = control_scores
        return state

    async def confidence_gate(self, state: Dict[str, Any]) -> Dict[str, Any]:
        enriched: List[Dict[str, Any]] = []
        for cid, meta in state.get('control_raw', {}).items():
            score = float(meta.get('raw_score') or 0.0)
            if score < 0.4:
                risk = 'High'
            elif score < 0.7:
                risk = 'Medium'
            else:
                risk = 'Low'
            dom_key = '.'.join(cid.split('.')[:2])
            domain_name = DOMAIN_MAP.get(dom_key, 'General')
            supporting = [sc for sc in meta.get('chunk_scores', []) if (sc[1] or 0) > 0]
            enriched.append({
                'control_id': cid,
                'title': meta.get('title'),
                'score': round(score, 4),
                'risk_tier': risk,
                'domain': domain_name,
                'supporting_chunk_ids': [c[0] for c in supporting[:10]],
                'supporting_count': len(supporting),
            })
        state['control_results'] = enriched
        return state

    async def gap_analysis_gate(self, state: Dict[str, Any]) -> Dict[str, Any]:
        gaps: List[Dict[str, Any]] = []
        for ctrl in state.get('control_results', []):
            if ctrl['risk_tier'] in ('High', 'Medium'):
                gaps.append({
                    'control_id': ctrl['control_id'],
                    'risk_tier': ctrl['risk_tier'],
                    'gap': 'Evidence coverage insufficient for assurance',
                    'recommended_action': 'Enhance policy/procedure and add records',
                })
        state['gaps'] = gaps
        tier_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for c in state.get('control_results', []):
            tier_counts[c['risk_tier']] = tier_counts.get(c['risk_tier'], 0) + 1
        state['risk_matrix'] = tier_counts
        scores = [c['score'] for c in state.get('control_results', [])]
        state['overall_score'] = round(sum(scores)/len(scores)*100, 2) if scores else 0.0
        # Build simple knowledge graph
        for ctrl in state.get('control_results', []):
            self.graph.add_node('CONTROL', id=ctrl['control_id'], title=ctrl['title'], score=ctrl['score'], risk_tier=ctrl['risk_tier'])
        chunk_index = {c['id']: c for c in state.get('chunks', [])}
        for ctrl in state.get('control_results', []):
            for chunk_id in ctrl['supporting_chunk_ids']:
                if chunk_id in chunk_index:
                    evid_id = self.graph.add_node('EVIDENCE', id=chunk_id, source_file=chunk_index[chunk_id]['source_file'], chunk_index=chunk_index[chunk_id]['chunk_index'])
                    self.graph.add_edge(evid_id, ctrl['control_id'], 'EVIDENCE_SUPPORTS_CONTROL', weight=1.0)
        return state
