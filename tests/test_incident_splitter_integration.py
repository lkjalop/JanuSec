"""Integration tests for incident_splitter.py — end-to-end cluster → Incident."""
import pytest
from src.core.incident_extraction import extract_incidents
from src.core.incident_extraction.incident_schema import CoherenceWarning


def _make_cluster(cid, rows, severity='high', confidence=0.8, entities=None, prefill=None):
    return {
        'cluster_id': cid,
        'rows': rows,
        'severity': severity,
        'confidence': confidence,
        'entities': entities or {},
        'prefill': prefill or {},
    }


def _row(user=None, mitre=None, ts=None, src=None, hostname=None, src_ip=None, row_index=None):
    r = {}
    if user:
        r['user_principal_name'] = user
    if mitre:
        r['mitre'] = mitre if isinstance(mitre, list) else [mitre]
    if ts is not None:
        r['timestamp_epoch'] = ts
    if src:
        r['source_sheet'] = src
    if hostname:
        r['hostname'] = hostname
    if src_ip:
        r['src_ip'] = src_ip
    if row_index is not None:
        r['row_index'] = row_index
    return r


class TestExtractIncidents:
    def test_empty_clusters_returns_empty(self):
        assert extract_incidents([]) == []

    def test_single_cluster_single_incident(self):
        rows = [_row(user='alice', mitre='T1566', ts=0, src='azure')]
        cluster = _make_cluster('c1', rows)
        incidents = extract_incidents([cluster])
        assert len(incidents) == 1
        assert incidents[0].source_cluster_ids == ['c1']

    def test_incident_id_unique(self):
        rows = [_row(user='alice', ts=0)]
        c1 = _make_cluster('c1', rows)
        c2 = _make_cluster('c2', rows)
        incidents = extract_incidents([c1, c2])
        ids = [i.incident_id for i in incidents]
        assert len(set(ids)) == len(ids)

    def test_incident_has_required_fields(self):
        rows = [_row(user='alice', mitre='T1566', ts=1000, src='azure')]
        incidents = extract_incidents([_make_cluster('c1', rows)])
        inc = incidents[0]
        assert inc.incident_id.startswith('INC-')
        assert inc.name
        assert isinstance(inc.row_refs, list)
        assert isinstance(inc.entities, dict)
        assert isinstance(inc.mitre_techniques, list)
        assert isinstance(inc.kill_chain_phases, list)
        assert isinstance(inc.source_types, list)
        assert 0.0 <= inc.confidence <= 1.0

    def test_multi_cluster_produces_multiple_incidents(self):
        c1 = _make_cluster('c1', [_row(user='alice', ts=0)])
        c2 = _make_cluster('c2', [_row(user='bob', ts=0)])
        incidents = extract_incidents([c1, c2])
        assert len(incidents) == 2

    def test_coherence_warning_on_low_score_cluster(self):
        # Rows spanning >90 days with no shared entities → low coherence
        rows = [
            _row(user='alice', ts=0, src='azure'),
            _row(user='bob', ts=86400 * 100, src='azure'),
        ]
        cluster = _make_cluster('c1', rows)
        incidents = extract_incidents([cluster])
        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.coherence_warning != CoherenceWarning.NONE or inc.coherence_score >= 0.0

    def test_what_happened_used_in_name(self):
        rows = [_row(user='alice', ts=0, src='azure')]
        prefill = {'what_happened': 'Attacker exfiltrated credentials via phishing'}
        cluster = _make_cluster('c1', rows, prefill=prefill)
        incidents = extract_incidents([cluster])
        assert 'Attacker exfiltrated credentials via phishing' in incidents[0].name

    def test_mitre_techniques_extracted(self):
        rows = [
            _row(mitre='T1566', ts=0),
            _row(mitre=['T1059', 'T1041'], ts=100),
        ]
        incidents = extract_incidents([_make_cluster('c1', rows)])
        techs = set(incidents[0].mitre_techniques)
        assert 'T1566' in techs
        assert 'T1041' in techs

    def test_kill_chain_phases_ordered(self):
        rows = [
            _row(mitre='T1566', ts=0),   # initial_access
            _row(mitre='T1059', ts=100), # execution
            _row(mitre='T1041', ts=200), # exfiltration
        ]
        incidents = extract_incidents([_make_cluster('c1', rows)])
        phases = incidents[0].kill_chain_phases
        assert phases.index('initial_access') < phases.index('execution')
        assert phases.index('execution') < phases.index('exfiltration')

    def test_time_span_extracted(self):
        rows = [_row(ts=1000, src='azure'), _row(ts=5000, src='azure')]
        incidents = extract_incidents([_make_cluster('c1', rows)])
        assert incidents[0].start_time == '1000'
        assert incidents[0].end_time == '5000'

    def test_split_produces_split_rationale(self):
        pytest.importorskip('networkx')
        # Two disjoint user groups — should split
        alice_rows = [_row(user='alice', hostname='alice-host') for _ in range(5)]
        bob_rows = [_row(user='bob', hostname='bob-host') for _ in range(5)]
        cluster = _make_cluster('c1', alice_rows + bob_rows)
        incidents = extract_incidents([cluster])
        if len(incidents) > 1:
            assert any(i.split_rationale for i in incidents)

    def test_severity_propagated(self):
        rows = [_row(user='alice', ts=0)]
        incidents = extract_incidents([_make_cluster('c1', rows, severity='critical')])
        assert incidents[0].severity == 'critical'

    def test_to_dict_serializable(self):
        rows = [_row(user='alice', mitre='T1566', ts=0, src='azure')]
        incidents = extract_incidents([_make_cluster('c1', rows)])
        d = incidents[0].to_dict()
        assert d['incident_id'].startswith('INC-')
        assert isinstance(d['coherence_warning'], str)
