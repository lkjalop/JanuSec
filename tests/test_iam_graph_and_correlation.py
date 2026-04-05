from src.domains.iam.graph_store import PermissionGraphStore
from src.domains.iam.correlation import correlate_events_time_window
from src.domains.iam.enforcement import EnforcementController
import time


def test_graph_store_upsert_and_query(tmp_path):
    p = tmp_path / 'pg.json'
    store = PermissionGraphStore(persist_path=str(p))
    store.upsert_principal('user:alice', [('iam:CreateAccessKey', 9), ('s3:PutObject', 1)])
    assert store.get_principal('user:alice')
    path = store.find_shortest_path_to_level('user:alice', 8)
    assert path is not None


def test_correlate_time_window():
    now = time.time()
    iam = [{'eventName': 'CreateAccessKey', 'eventTime': now, 'userIdentity': {'userName': 'bob'}}]
    other = [{'type': 'package_install', 'eventTime': now + 10, 'package': 'evilpkg'}]
    corr = correlate_events_time_window(iam, other, window_seconds=30)
    assert len(corr) == 1


def test_enforcement_feedback():
    e = EnforcementController()
    e.set_toggle('iam.create_key', 'auto')
    assert e.get_toggle('iam.create_key') == 'auto'
    e.record_feedback('iam.create_key', 'disable_key', 'operator1', 'useful')
    fb = e.recent_feedback('iam.create_key')
    assert fb and fb[-1]['feedback'] == 'useful'
