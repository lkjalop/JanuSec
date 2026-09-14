import os
import json
import time
from src.integrations.polling_state import PollingStateStore


def test_save_and_load_tmp(tmp_path, monkeypatch):
    d = tmp_path / "polling_state"
    monkeypatch.setenv('POLLING_STATE_DIR', str(d))
    store = PollingStateStore()
    tid = 'tenant-x'
    prov = 'msgraph'
    state = {'delta_link': 'abc', 'last_polled': int(time.time())}
    store.save_state(tid, prov, state)
    out = store.load_state(tid, prov)
    assert out.get('delta_link') == 'abc'


def test_recover_corrupt_file(tmp_path, monkeypatch):
    d = tmp_path / "polling_state"
    monkeypatch.setenv('POLLING_STATE_DIR', str(d))
    store = PollingStateStore()
    tid = 'tenant-corrupt'
    prov = 'gmail'
    path = os.path.join(str(d), f"{tid}_{prov}.json")
    os.makedirs(str(d), exist_ok=True)
    # write corrupt json
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('{ this is not valid json')
    # load_state should not raise and should return empty dict
    out = store.load_state(tid, prov)
    assert out == {}
    # and file should have been removed or replaced; subsequent save should create a valid file
    store.save_state(tid, prov, {'history_id': '123'})
    out2 = store.load_state(tid, prov)
    assert out2.get('history_id') == '123'
