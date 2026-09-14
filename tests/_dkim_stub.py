"""Minimal dkim stub used for unit tests when dkimpy is not installed.

The real tests monkeypatch `dkim.verify` to simulate pass/fail.
"""
def verify(msg_bytes):
    raise NotImplementedError("dkim.verify not implemented in test stub; tests should monkeypatch this")
