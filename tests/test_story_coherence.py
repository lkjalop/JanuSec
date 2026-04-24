"""Tests for story_coherence.py."""
import pytest
from src.core.incident_extraction.story_coherence import (
    COHERENCE_THRESHOLD,
    compute_story_coherence,
    _score_kill_chain_coherence,
    _score_temporal_contiguity,
    _score_source_corroboration,
    _score_mitre_affinity,
)


def _row(user=None, mitre=None, ts=None, src=None, hostname=None):
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
    return r


class TestTemporalContiguity:
    def test_single_row_returns_1(self):
        assert _score_temporal_contiguity([_row(ts=1000)]) == 1.0

    def test_same_day_returns_1(self):
        rows = [_row(ts=0), _row(ts=3600)]
        assert _score_temporal_contiguity(rows) == 1.0

    def test_within_30_days_returns_09(self):
        rows = [_row(ts=0), _row(ts=86400 * 10)]
        assert _score_temporal_contiguity(rows) == 0.9

    def test_within_90_days_returns_06(self):
        rows = [_row(ts=0), _row(ts=86400 * 45)]
        assert _score_temporal_contiguity(rows) == 0.6

    def test_over_90_days_returns_02(self):
        rows = [_row(ts=0), _row(ts=86400 * 100)]
        assert _score_temporal_contiguity(rows) == 0.2

    def test_no_timestamps_returns_1(self):
        rows = [{'user_principal_name': 'alice'}]
        assert _score_temporal_contiguity(rows) == 1.0


class TestKillChainCoherence:
    def test_no_mitre_returns_03(self):
        assert _score_kill_chain_coherence([_row()]) == 0.3

    def test_forward_progression_high_score(self):
        rows = [
            _row(mitre='T1566'),   # initial_access
            _row(mitre='T1059'),   # execution
            _row(mitre='T1547'),   # persistence
            _row(mitre='T1041'),   # exfiltration
        ]
        score = _score_kill_chain_coherence(rows)
        assert score >= 0.7

    def test_single_technique_returns_05(self):
        rows = [_row(mitre='T1566')]
        assert _score_kill_chain_coherence(rows) == 0.5


class TestSourceCorroboration:
    def test_three_sources_returns_1(self):
        rows = [_row(src='azure'), _row(src='okta'), _row(src='endpoint')]
        assert _score_source_corroboration(rows) == 1.0

    def test_two_sources_returns_07(self):
        rows = [_row(src='azure'), _row(src='okta')]
        assert _score_source_corroboration(rows) == 0.7

    def test_single_source_returns_04(self):
        rows = [_row(src='azure'), _row(src='azure')]
        assert _score_source_corroboration(rows) == 0.4


class TestMitreAffinity:
    def test_one_technique_family_returns_1(self):
        rows = [_row(mitre='T1566'), _row(mitre='T1566.001')]
        assert _score_mitre_affinity(rows) == 1.0

    def test_many_families_returns_03(self):
        rows = [_row(mitre=f'T1{100+i}') for i in range(10)]
        assert _score_mitre_affinity(rows) == 0.3

    def test_no_techniques_returns_05(self):
        assert _score_mitre_affinity([_row()]) == 0.5


class TestComputeStoryCoherence:
    def test_high_coherence_keeps_single(self):
        entities = {
            'user_principal_name': ['alice@corp.com'],
            'hostname': ['ws1'],
        }
        rows = [
            _row(user='alice@corp.com', mitre='T1566', ts=0, src='azure', hostname='ws1'),
            _row(user='alice@corp.com', mitre='T1059', ts=3600, src='okta', hostname='ws1'),
            _row(user='alice@corp.com', mitre='T1041', ts=7200, src='endpoint', hostname='ws1'),
        ]
        result = compute_story_coherence(rows, entities)
        assert result.keep_as_single_incident
        assert result.score >= 0.5

    def test_returns_all_components(self):
        rows = [_row(user='bob', ts=0, src='siem')]
        entities = {'user_principal_name': ['bob']}
        result = compute_story_coherence(rows, entities)
        expected_keys = {'shared_entities', 'temporal_contiguity', 'kill_chain_coherence',
                         'mitre_technique_affinity', 'source_corroboration'}
        assert set(result.component_scores.keys()) == expected_keys

    def test_empty_rows_score_low(self):
        result = compute_story_coherence([], {})
        assert not result.keep_as_single_incident
        assert result.score < COHERENCE_THRESHOLD
