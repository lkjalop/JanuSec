"""Three-file cross-source pipeline integration test.

Validates the full analysis stack against the three synthetic fixture files:
  - janusec_net_c2_bgp.v1.1.csv       — Network C2/BGP telemetry
  - janusec_okta_m365_events.v1.1.json — Okta/M365 identity events
  - janusec_ep_endpoint.v1.1.xlsx      — Windows/Linux endpoint KAPE artefacts

These files contain two distinct BEC campaigns (PHANTOM-MERIDIAN and
HARBOURSIDE), NPM supply-chain compromise, and significant noise/benign
events — making them the acid test for correlation accuracy, verdict
calibration, and HopGraph data completeness.

Run with:
    pytest tests/test_full_pipeline_integration.py -v --timeout=120
"""
import asyncio
import csv
import io
import json
import os
import sys

import pytest

# ── File paths ─────────────────────────────────────────────────────────────────

_DUMP_DIR = os.path.join(os.path.dirname(__file__), '..', 'dump', 'test files')

FIXTURE_CSV  = os.path.join(_DUMP_DIR, 'janusec_net_c2_bgp.v1.1.csv')
FIXTURE_JSON = os.path.join(_DUMP_DIR, 'janusec_okta_m365_events.v1.1.json')
FIXTURE_XLSX = os.path.join(_DUMP_DIR, 'janusec_ep_endpoint.v1.1.xlsx')

ALL_FIXTURES = [FIXTURE_CSV, FIXTURE_JSON, FIXTURE_XLSX]

# ── File parsers → normalised row dicts ───────────────────────────────────────

def _parse_csv_fixture(path: str) -> list[dict]:
    rows = []
    with open(path, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for i, raw in enumerate(reader):
            row = dict(raw)
            row['row_index']    = i + 1
            row['source_sheet'] = 'Network'
            row['accounts']     = [row.get('username') or '']
            row['ips']          = list(filter(None, [row.get('src_ip'), row.get('dst_ip')]))
            row['hosts']        = []
            row['resources']    = []
            row['mitre']        = [row['mitre_technique']] if row.get('mitre_technique') else []
            row['session_id']   = None
            row['timestamp_epoch'] = _parse_ts(row.get('timestamp_utc') or row.get('timestamp') or '')
            rows.append(row)
    return rows


def _parse_json_fixture(path: str) -> list[dict]:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)

    events = data.get('events') or (data if isinstance(data, list) else [])
    rows = []
    for i, ev in enumerate(events):
        row = dict(ev)
        row['row_index']    = 10000 + i  # offset to avoid collision with CSV
        row['source_sheet'] = ev.get('source_platform', 'Okta')
        row['accounts']     = list(filter(None, [ev.get('user_principal_name')]))
        row['src_ip']       = ev.get('source_ip') or ev.get('src_ip')
        row['ips']          = list(filter(None, [row['src_ip']]))
        row['hosts']        = []
        row['resources']    = list(filter(None, [ev.get('target_app_or_resource')]))
        row['mitre']        = [ev['mitre_technique']] if ev.get('mitre_technique') else []
        row['session_id']   = ev.get('session_id')
        row['timestamp_epoch'] = _parse_ts(ev.get('timestamp_utc') or '')
        # Pass through incident_id so over-clustering tests can use it
        row['incident_tag'] = ev.get('incident_id') or ev.get('review_state') or ''
        rows.append(row)
    return rows


def _parse_xlsx_fixture(path: str) -> list[dict]:
    try:
        import openpyxl
    except ImportError:
        return []

    rows = []
    offset = 20000  # avoid row_index collision
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        headers = None
        for r_idx, raw_row in enumerate(ws.iter_rows(values_only=True)):
            if headers is None:
                headers = [str(h or '') for h in raw_row]
                continue
            ev = dict(zip(headers, raw_row))
            row = dict(ev)
            row['row_index']    = offset + r_idx
            row['source_sheet'] = sheet_name
            row['accounts']     = list(filter(None, [ev.get('username')]))
            row['src_ip']       = ev.get('internal_ip') or ev.get('src_ip')
            row['ips']          = list(filter(None, [row['src_ip']]))
            row['hosts']        = list(filter(None, [ev.get('hostname')]))
            row['resources']    = list(filter(None, [ev.get('registry_key'), ev.get('file_path')]))
            row['mitre']        = [ev['mitre_technique']] if ev.get('mitre_technique') else []
            row['session_id']   = None
            row['timestamp_epoch'] = _parse_ts(str(ev.get('date_utc') or ''))
            rows.append(row)
        offset += 1000
    wb.close()
    return rows


def _parse_ts(s: str) -> float:
    if not s:
        return 0.0
    try:
        from datetime import datetime, timezone
        s = s.replace('Z', '+00:00')
        dt = datetime.fromisoformat(s)
        return dt.timestamp()
    except Exception:
        return 0.0


# ── Module-scope assessment fixture ───────────────────────────────────────────

@pytest.fixture(scope='module')
def all_rows() -> list[dict]:
    missing = [f for f in ALL_FIXTURES if not os.path.exists(f)]
    if missing:
        pytest.skip(f'Fixture files missing: {missing}')
    net_rows  = _parse_csv_fixture(FIXTURE_CSV)
    okta_rows = _parse_json_fixture(FIXTURE_JSON)
    ep_rows   = _parse_xlsx_fixture(FIXTURE_XLSX)
    combined  = net_rows + okta_rows + ep_rows
    assert combined, 'No rows parsed from any fixture file'
    return combined


@pytest.fixture(scope='module')
def assessment(all_rows) -> dict:
    """Run the correlation layer synchronously and return the assessment dict.

    We bypass the HTTP layer and call _build_correlation_clusters directly so
    the test works without a running server.  This tests the correlation engine
    (the part that matters for BEC non-merge), verdict backfill, and top_links
    completeness.  The full HTTP-level test is the Playwright E2E spec.
    """
    from src.api.deep_analyze_endpoints import _build_correlation_clusters
    from src.core.verdict_engine.verdict_rules import backfill_cluster_verdicts

    clusters, adjacency = _build_correlation_clusters(all_rows)
    # Rows not in any cluster are "isolated"
    clustered_indices = set()
    for c in clusters:
        clustered_indices |= set(c.get('row_refs') or [])
    isolated_rows = [r for r in all_rows if r['row_index'] not in clustered_indices]
    result = {
        'assessment_id': 'integration_test',
        'correlation_clusters': clusters,
        'normalized_rows': all_rows,
        'isolated_rows': isolated_rows,
        'isolated_count': len(isolated_rows),
    }
    backfill_cluster_verdicts(result)
    return result


# ── Smoke tests ────────────────────────────────────────────────────────────────

class TestPipelineSmoke:

    def test_fixtures_exist(self):
        for f in ALL_FIXTURES:
            assert os.path.exists(f), f'Fixture missing: {f}'

    def test_csv_parses(self):
        rows = _parse_csv_fixture(FIXTURE_CSV)
        assert len(rows) > 10, 'CSV fixture produced too few rows'
        assert all('src_ip' in r for r in rows[:5])

    def test_json_parses(self):
        rows = _parse_json_fixture(FIXTURE_JSON)
        assert len(rows) > 10, 'JSON fixture produced too few rows'
        assert all('accounts' in r for r in rows[:5])

    def test_xlsx_parses(self):
        try:
            import openpyxl
        except ImportError:
            pytest.skip('openpyxl not installed')
        rows = _parse_xlsx_fixture(FIXTURE_XLSX)
        assert len(rows) > 5, 'XLSX fixture produced too few rows'
        assert all('hosts' in r for r in rows[:5])

    def test_row_indices_unique(self, all_rows):
        indices = [r['row_index'] for r in all_rows]
        assert len(indices) == len(set(indices)), (
            'Duplicate row_index values across files — correlation will produce wrong results'
        )


# ── Correlation accuracy ───────────────────────────────────────────────────────

class TestCorrelationAccuracy:

    def test_produces_at_least_one_cluster(self, assessment):
        clusters = assessment.get('correlation_clusters', [])
        assert len(clusters) >= 1, 'Pipeline produced zero clusters'

    def test_phantom_harbourside_bec_do_not_merge(self, assessment):
        """PHANTOM-MERIDIAN (45.153.x.x) and HARBOURSIDE (194.87.x.x) must stay separate.

        Both campaigns target the same victim accounts, but from different
        attacker IP infrastructure. A single shared cluster would be a
        correlation engine regression.
        """
        # Tag rows by incident_tag from the JSON fixture
        phantom_rows = {
            r['row_index'] for r in assessment['normalized_rows']
            if 'PHANTOM' in str(r.get('incident_tag', '')).upper()
            or '45.153.' in str(r.get('src_ip') or '')
        }
        harbourside_rows = {
            r['row_index'] for r in assessment['normalized_rows']
            if 'HARBOURSIDE' in str(r.get('incident_tag', '')).upper()
            or '194.87.' in str(r.get('src_ip') or '')
        }

        if not phantom_rows or not harbourside_rows:
            pytest.skip('Could not identify PHANTOM/HARBOURSIDE rows — check fixture content')

        for cluster in assessment['correlation_clusters']:
            cr = set(cluster.get('row_refs') or [])
            phantom_in = cr & phantom_rows
            harbourside_in = cr & harbourside_rows
            assert not (phantom_in and harbourside_in), (
                f"Cluster {cluster.get('cluster_id')} merged PHANTOM "
                f"({len(phantom_in)} rows) and HARBOURSIDE ({len(harbourside_in)} rows). "
                f"Different attacker IPs must never produce a single cluster."
            )

    def test_at_least_one_cross_source_cluster(self, assessment):
        """At least one cluster must contain rows from 2+ source_sheet types.

        This validates cross-source correlation: e.g. a Network row and an
        Okta row from the same attacker IP clustering together.
        """
        for cluster in assessment['correlation_clusters']:
            refs = set(cluster.get('row_refs') or [])
            row_map = {r['row_index']: r for r in assessment['normalized_rows']}
            sources = {row_map[i]['source_sheet'] for i in refs if i in row_map}
            if len(sources) >= 2:
                return
        pytest.fail(
            'No cross-source cluster found. Cross-source correlation (network+okta, '
            'okta+endpoint) may be broken.'
        )

    def test_npm_supply_chain_detected(self, assessment):
        """NPM/supply-chain rows must appear in at least one cluster."""
        npm_rows = {
            r['row_index'] for r in assessment['normalized_rows']
            if 'NPM' in str(r.get('incident_tag', '')).upper()
            or 'npm' in str(r.get('analyst_notes', '')).lower()
            or 'webdataparser' in str(r.get('analyst_notes', '')).lower()
        }
        if not npm_rows:
            pytest.skip('NPM rows not identifiable in fixtures — check fixture content')

        clustered = set()
        for cluster in assessment['correlation_clusters']:
            clustered |= set(cluster.get('row_refs') or [])

        npm_clustered = npm_rows & clustered
        assert npm_clustered, (
            f'NPM supply-chain rows ({npm_rows}) were not placed in any cluster. '
            'They may be isolated — check attacker IP / host pivot logic.'
        )

    def test_isolated_rows_not_in_clusters(self, assessment):
        """No row should appear in both clusters AND isolated list."""
        clustered = set()
        for c in assessment['correlation_clusters']:
            clustered |= set(c.get('row_refs') or [])

        # isolated may be a list of row dicts OR a list of int row_indices
        _iso_raw = assessment.get('isolated_rows') or []
        isolated = set()
        for item in _iso_raw:
            if isinstance(item, dict):
                isolated.add(item.get('row_index'))
            elif isinstance(item, int):
                isolated.add(item)
        overlap = clustered & isolated
        assert not overlap, (
            f'Rows appear in both clusters and isolated list: {overlap}. '
            'This is a data integrity bug in _build_correlation_clusters.'
        )


# ── Verdict accuracy ───────────────────────────────────────────────────────────

class TestVerdictAccuracy:

    def test_verdicts_not_all_uncertain(self, assessment):
        verdicts = [c.get('verdict') for c in assessment['correlation_clusters']]
        non_uncertain = [v for v in verdicts if v and v not in ('UNCERTAIN', None, '')]
        assert len(non_uncertain) > 0, (
            f'All cluster verdicts are UNCERTAIN or missing. '
            f'backfill_cluster_verdicts may not be wired. Got: {verdicts}'
        )

    def test_gate_urgency_varies_across_clusters(self, assessment):
        """After _apply_hvr_gating, gate_urgency must not be uniform.

        If every cluster has the same urgency it means HVR Fix 1.1 is not applied.
        """
        urgencies = {c.get('gate_urgency') for c in assessment['correlation_clusters']}
        # Need at least 2 distinct urgency values, or some None (not gated) vs set
        non_none = {u for u in urgencies if u is not None}
        if len(non_none) == 1 and not any(
            c.get('gate_urgency') is None for c in assessment['correlation_clusters']
        ):
            pytest.fail(
                f'All clusters have identical gate_urgency: {urgencies}. '
                'Fix 1.1 (_apply_hvr_gating) may not be applied to cluster-build output.'
            )

    def test_high_severity_cluster_gets_non_trivial_verdict(self, assessment):
        """A critical/high severity cluster should reach at least SUSPICIOUS_ACTIVITY."""
        high_clusters = [
            c for c in assessment['correlation_clusters']
            if c.get('severity') in ('critical', 'high')
        ]
        if not high_clusters:
            pytest.skip('No critical/high severity cluster in this run')

        acceptable = {'VALIDATED_BREACH', 'CONFIRMED_INTRUSION', 'LIKELY_COMPROMISE',
                      'SUSPICIOUS_ACTIVITY'}
        for c in high_clusters:
            v = c.get('verdict') or ''
            assert v in acceptable or not v, (
                f"High-severity cluster {c.get('cluster_id')} has unexpected verdict: {v}"
            )


# ── HopGraph data completeness ─────────────────────────────────────────────────

class TestHopGraphData:

    def test_at_least_one_cluster_has_top_links(self, assessment):
        """Without top_links, HopGraph renders empty or falls back to row-field edges only."""
        with_links = [c for c in assessment['correlation_clusters'] if c.get('top_links')]
        assert with_links, (
            'No cluster has top_links populated. HopGraph will render with no pivot edges. '
            'Check _build_correlation_clusters top_links computation.'
        )

    def test_top_links_have_required_fields(self, assessment):
        """Every top_link must carry src, dst, pivot, conf, summary."""
        for cluster in assessment['correlation_clusters']:
            for lk in (cluster.get('top_links') or []):
                for field in ('src', 'dst', 'pivot', 'conf', 'summary'):
                    assert field in lk, (
                        f"top_link in cluster {cluster.get('cluster_id')} "
                        f"missing field '{field}': {lk}"
                    )

    def test_attacker_ip_pivot_present_in_some_cluster(self, assessment):
        """At least one top_link should be tagged pivot='attacker_ip'."""
        all_links = []
        for c in assessment['correlation_clusters']:
            all_links.extend(c.get('top_links') or [])
        has_atk_ip = any(lk.get('pivot') == 'attacker_ip' for lk in all_links)
        assert has_atk_ip, (
            'No top_link with pivot=attacker_ip found across all clusters. '
            'The attacker-IP correlation signal is either not firing or not being '
            'stored in top_links.'
        )

    def test_source_sheets_populated_on_multi_source_clusters(self, assessment):
        """Cross-source clusters must list their source_sheets."""
        for cluster in assessment['correlation_clusters']:
            refs = set(cluster.get('row_refs') or [])
            row_map = {r['row_index']: r for r in assessment['normalized_rows']}
            sources = {row_map[i].get('source_sheet') for i in refs if i in row_map}
            if len(sources) >= 2:
                stored = cluster.get('source_sheets')
                assert stored, (
                    f"Cross-source cluster {cluster.get('cluster_id')} has rows from "
                    f"{sources} but source_sheets field is empty."
                )


# ── Row count sanity ───────────────────────────────────────────────────────────

class TestDataCompleteness:

    def test_all_three_sources_present_in_rows(self, all_rows):
        source_sheets = {r.get('source_sheet') for r in all_rows}
        has_network  = any('net' in s.lower() or 'network' in s.lower() for s in source_sheets if s)
        has_identity = any(any(k in s.lower() for k in ('okta', 'azure', 'm365', 'entra'))
                           for s in source_sheets if s)
        has_endpoint = any(any(k in s.lower() for k in ('endpoint', 'win', 'linux', 'kape'))
                           for s in source_sheets if s)
        assert has_network,  f'No network rows found. source_sheets: {source_sheets}'
        assert has_identity, f'No identity rows found. source_sheets: {source_sheets}'
        assert has_endpoint, f'No endpoint rows found. source_sheets: {source_sheets}'

    def test_minimum_row_count(self, all_rows):
        assert len(all_rows) >= 50, (
            f'Combined row count {len(all_rows)} is suspiciously low. '
            'One or more fixture files may have failed to parse.'
        )

    def test_timestamps_parseable(self, all_rows):
        with_ts = [r for r in all_rows if r.get('timestamp_epoch', 0) > 0]
        pct = len(with_ts) / max(len(all_rows), 1)
        assert pct >= 0.5, (
            f'Only {pct:.0%} of rows have a parseable timestamp. '
            'Swimlane temporal ordering will be unreliable.'
        )
