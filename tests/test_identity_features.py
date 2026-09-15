from __future__ import annotations

from src.features.identity_features import extract_features


def test_extract_features_flags():
    ev = {
        'action': 'assume_role',
        'event_type': 'login',
        'src_host': 'A',
        'dest_host': 'B',
        'groups': ['users'],
    }
    f = extract_features(ev)
    assert f['lateral_flag'] is True
    assert f['priv_escalation_flag'] is True
    assert isinstance(f['hour'], int) and 0 <= f['hour'] <= 23

