import os
import tempfile
from src.core.correlation.rules.weekX.high_signal_bursts import lateral_burst, rapid_scan, exfil_spike
from src.core.correlation.rules.rule_thresholds import set_threshold, reset_to_env_defaults


def test_lateral_burst_fires_and_not_fires():
    # ensure threshold known
    set_threshold('lateral_conn_count', 5, persist=False)
    evt = {'src_ip': '10.0.0.5', 'conn_count': 6}
    assert lateral_burst(evt) is True
    evt2 = {'src_ip': '10.0.0.5', 'conn_count': 4}
    assert lateral_burst(evt2) is False
    reset_to_env_defaults(persist=False)


def test_rapid_scan_threshold():
    set_threshold('rapid_scan_rate', 20.0, persist=False)
    evt = {'src_ip': '10.1.1.2', 'scan_rate': 25.0}
    assert rapid_scan(evt) is True
    evt2 = {'src_ip': '10.1.1.2', 'scan_rate': 10.0}
    assert rapid_scan(evt2) is False
    reset_to_env_defaults(persist=False)


def test_exfil_spike_threshold():
    set_threshold('exfil_bytes', 1000, persist=False)
    evt = {'src_ip': '10.1.1.3', 'http_bytes_out': 2000}
    assert exfil_spike(evt) is True
    evt2 = {'src_ip': '10.1.1.3', 'http_bytes_out': 500}
    assert exfil_spike(evt2) is False
    reset_to_env_defaults(persist=False)
