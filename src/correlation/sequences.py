from __future__ import annotations
import os, time, threading, hashlib
from typing import List, Dict, Tuple, Any, Optional
from .annotations import emit_edge
from src.core.factors.observe_flags import adjust_delta

class SequenceRule:
    __slots__ = ('name','sequence','window','output','delta','min_support','entities')
    def __init__(self, name: str, sequence: List[str], window: float, output: str, delta: float, min_support: int = 1, entities: List[str] = None):
        self.name = name
        self.sequence = sequence
        self.window = window
        self.output = output
        self.delta = delta
        self.min_support = min_support
        self.entities = entities or ['host','incident_id']

class SequenceCorrelator:
    """Ordered sequence correlation across events per entity.

    Maintains per-entity chronological factor occurrences; checks if rule sequences appear in order within window.
    Emits one correlation factor per rule match (cooldown gated) and annotates edges.
    """
    def __init__(self):
        self.enabled = os.getenv('SEQ_ENABLED','1') not in ('0','false','False')
        self.max_events_per_entity = int(os.getenv('SEQ_MAX_EVENTS_PER_ENTITY','200') or 200)
        self.cooldown = int(os.getenv('SEQ_RULE_COOLDOWN_SECONDS','600') or 600)
        self.rules: List[SequenceRule] = self._load_rules()
        self._events: Dict[str, List[Tuple[float,List[str]]]] = {}
        self._last_emit: Dict[Tuple[str,str], float] = {}
        self._lock = threading.RLock()

    def _load_rules(self) -> List[SequenceRule]:
        rules: List[SequenceRule] = []
        # Simple env toggle test rule
        if os.getenv('SEQ_TEST_RULE','0') in ('1','true','True'):
            rules.append(SequenceRule('test_seq', ['factor:a','factor:b'], window=900, output='corr:seq_test', delta=0.02))
        # Placeholder: could later load from YAML path set in SEQ_RULES_FILE
        return rules

    def _entity_key(self, event: dict, entities: List[str]) -> Optional[str]:
        for k in entities:
            v = event.get(k)
            if v:
                return f"{k}:{v}"
        return None

    def ingest(self, event: dict, factors: List[str]) -> Tuple[List[str], float]:
        if not self.enabled or not self.rules or not factors:
            return [], 0.0
        now = float(event.get('ts') or time.time())
        emitted: List[str] = []
        delta_total = 0.0
        with self._lock:
            for rule in self.rules:
                ek = self._entity_key(event, rule.entities)
                if not ek:
                    continue
                ev_list = self._events.setdefault(ek, [])
                # Append current event factors
                ev_list.append((now, list(factors)))
                # Prune outside max retention length
                if len(ev_list) > self.max_events_per_entity:
                    ev_list[:] = ev_list[-self.max_events_per_entity:]
                # Walk backwards collecting sequence
                needed = list(rule.sequence)
                idx = len(needed)-1
                matched_times = []
                for ts, facs in reversed(ev_list):
                    if needed[idx] in facs:
                        matched_times.append(ts)
                        idx -= 1
                        if idx < 0:
                            break
                if idx >= 0:
                    continue  # incomplete
                first_t = matched_times[-1]
                if (now - first_t) > rule.window:
                    continue
                key = (rule.name, ek)
                last_emit = self._last_emit.get(key)
                if last_emit and (now - last_emit) < self.cooldown:
                    continue
                self._last_emit[key] = now
                if rule.output not in emitted and rule.output not in factors:
                    emitted.append(rule.output)
                    d = adjust_delta(rule.output, rule.delta)
                    delta_total += d
                    emit_edge({
                        'edge_type': 'sequence',
                        'rule_id': rule.name,
                        'ts': now,
                        'entities': [ek],
                        'input_factors': list(rule.sequence),
                        'output_factor': rule.output,
                        'delta': d,
                        'meta': {
                            'window': rule.window,
                            'match_span': now - first_t,
                            'length': len(rule.sequence)
                        }
                    })
        return emitted, delta_total

GLOBAL_SEQUENCE_CORRELATOR = SequenceCorrelator()

def record_sequence_correlation(event: dict, factors: List[str]) -> Tuple[List[str], float]:
    try:
        return GLOBAL_SEQUENCE_CORRELATOR.ingest(event, factors)
    except Exception:
        return [], 0.0

__all__ = ['SequenceCorrelator','GLOBAL_SEQUENCE_CORRELATOR','record_sequence_correlation']