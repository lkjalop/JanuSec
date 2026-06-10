"""Tests for reversible IOC tokenization (sovereignty-preserving LLM routing)."""
from __future__ import annotations

from src.security.ioc_redaction import IocRedactor, redact


class TestRedaction:
    def test_ipv4_tokenized_and_consistent(self):
        r = IocRedactor()
        out = r.redact("10.0.0.5 talked to 10.0.0.9 and back to 10.0.0.5")
        assert "10.0.0.5" not in out and "10.0.0.9" not in out
        # same IP -> same token (correlation preserved)
        assert out.count("IP_001") == 2
        assert "IP_002" in out

    def test_users_hosts_arns(self):
        r = IocRedactor()
        txt = ("martin.chen@acme.com from WS-MARTIN-01 assumed "
               "arn:aws:iam::123:user/sophie.reid")
        out = r.redact(txt)
        assert "martin.chen@acme.com" not in out
        assert "ws-martin-01" not in out.lower()
        assert "sophie.reid" not in out
        assert "USER_001" in out and "HOST_001" in out and "ARN_001" in out

    def test_mitre_ids_preserved(self):
        r = IocRedactor()
        out = r.redact("Kerberoasting T1558.003 and WMI T1047 on host SRV-DB-01")
        assert "T1558.003" in out and "T1047" in out
        assert "srv-db-01" not in out.lower()  # the host IS tokenized

    def test_public_cloud_fqdn_not_redacted(self):
        r = IocRedactor()
        out = r.redact("call to s3.amazonaws.com and login.microsoftonline.com")
        assert "amazonaws.com" in out
        assert "microsoftonline.com" in out


class TestRoundTrip:
    def test_restore_is_exact_inverse(self):
        r = IocRedactor()
        original = ("At 02:14 martin.chen@acme.com (10.42.4.91) used WMI (T1047) on "
                    "ws-martin-01 to reach 10.42.1.10 and SVR-DB-01 via "
                    "arn:aws:sts::1:assumed-role/AdminRole/sess.")
        red = r.redact(original)
        restored = r.restore(red)
        assert restored == original

    def test_llm_response_restoration(self):
        # Simulate: redact prompt entities, LLM reasons over tokens, we restore its output.
        r = IocRedactor()
        r.redact("user martin.chen@acme.com from 10.42.4.91 on ws-martin-01")
        llm_output = "USER_001 (IP_001) compromised HOST_001 — isolate HOST_001 immediately."
        restored = r.restore(llm_output)
        assert "martin.chen@acme.com" in restored
        assert "10.42.4.91" in restored
        assert restored.count("ws-martin-01") == 2  # both HOST_001 references restored

    def test_token_collision_safety(self):
        # 10+ IPs: ensure IP_010 restores correctly and isn't clobbered by IP_001 prefix.
        r = IocRedactor()
        ips = [f"10.0.0.{i}" for i in range(1, 13)]
        red = r.redact(" ".join(ips))
        restored = r.restore(red)
        for ip in ips:
            assert ip in restored

    def test_empty_and_none_safe(self):
        r = IocRedactor()
        assert r.redact("") == ""
        assert r.restore("") == ""

    def test_convenience_helper(self):
        red, r = redact("login from 10.1.2.3")
        assert "10.1.2.3" not in red
        assert r.restore(red) == "login from 10.1.2.3"
