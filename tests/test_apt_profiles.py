"""Tests for APT attribution profiles."""
from src.core.enrichment.apt_profiles import attribute_apt, APT_PROFILES


def test_apt29_attribution_from_oauth_and_entra():
    """APT29 / Midnight Blizzard hallmark: OAuth device code + Entra privesc + cloud_identity."""
    res = attribute_apt(
        phase_tags={"oauth_device_code", "entra_privesc", "secret_access"},
        pivot_keys={"cloud_identity:alice", "iam_op:resetpassword"},
        cloud_providers={"azure"},
    )
    assert res is not None
    assert res["actor"] in ("apt29", "midnight_blizzard")
    assert res["confidence"] >= 0.55
    assert any("phase:" in m for m in res["matched_indicators"])


def test_apt41_cloud_imds_theft():
    """APT41: cloud IMDS credential theft + IAM privesc + rclone exfil on AWS/GCP."""
    res = attribute_apt(
        phase_tags={"cloud_imds_theft", "cloud_iam_privesc", "data_exfiltration_rclone"},
        pivot_keys={"cloud_identity:bob", "attacker_zone:aws"},
        cloud_providers={"aws"},
    )
    assert res is not None
    assert res["actor"] == "apt41"
    assert res["origin"] == "CN"


def test_lockbit_ransomware_chain():
    """LockBit hallmark: shadow copy deletion + ransomware staging + lateral lolbin."""
    res = attribute_apt(
        phase_tags={"shadow_copy_deletion", "ransomware_staging", "wmi_dcom_lateral", "credential_theft"},
        pivot_keys={"host:fileserver01", "sig:lockbit_encryptor"},
    )
    assert res is not None
    assert res["actor"] in ("lockbit", "blackcat")
    assert res["confidence"] >= 0.65


def test_scattered_spider_session_hijack():
    """Scattered Spider / Octo Tempest: session theft + MFA fatigue + privesc."""
    res = attribute_apt(
        phase_tags={"session_theft", "oauth_device_code", "credential_theft", "ransomware_staging"},
        pivot_keys={"cloud_identity:helpdesk_victim", "iam_op:resetmfa"},
        cloud_providers={"okta", "azure"},
    )
    assert res is not None
    assert res["actor"] in ("scattered_spider", "lapsus")


def test_no_attribution_with_single_indicator():
    """Single phase tag MUST NOT trigger attribution."""
    res = attribute_apt(
        phase_tags={"credential_theft"},
        pivot_keys={"host:wkstn01"},
    )
    assert res is None


def test_no_attribution_with_empty_input():
    """Empty input never attributes."""
    assert attribute_apt() is None
    assert attribute_apt(phase_tags=set(), pivot_keys=set()) is None


def test_volt_typhoon_living_off_the_land():
    """Volt Typhoon: lolbin-heavy, dcsync, wmi/dcom, no exfil — pre-positioning."""
    res = attribute_apt(
        phase_tags={"lolbin_execution", "credential_theft", "dcsync", "wmi_dcom_lateral"},
        pivot_keys={"host:dc01", "sig:ntds_dump"},
    )
    assert res is not None
    # Could be volt_typhoon, fin7, or apt40 — all have these indicators
    assert res["actor"] in ("volt_typhoon", "fin7", "apt40", "lockbit")
    # If volt_typhoon wins, origin should be CN
    if res["actor"] == "volt_typhoon":
        assert res["origin"] == "CN"


def test_confidence_capped():
    """Confidence is never >= 1.0."""
    # Throw every possible indicator at every profile
    all_phase = set()
    for p in APT_PROFILES.values():
        all_phase.update(p.get("phase_indicators", []))
    res = attribute_apt(
        phase_tags=all_phase,
        pivot_keys={"cloud_identity:x", "attacker_zone:y", "iam_op:z", "host:h", "sig:s"},
        cloud_providers={"aws", "azure", "gcp", "okta", "m365", "github", "kubernetes"},
    )
    assert res is not None
    assert res["confidence"] <= 0.95


def test_all_profiles_have_required_fields():
    """Every APT profile must declare aliases, origin, indicators, description."""
    for actor, profile in APT_PROFILES.items():
        assert "aliases" in profile, f"{actor} missing aliases"
        assert "origin" in profile, f"{actor} missing origin"
        assert "phase_indicators" in profile and len(profile["phase_indicators"]) >= 2, \
            f"{actor} needs ≥2 phase_indicators"
        assert "description" in profile and len(profile["description"]) >= 40, \
            f"{actor} description too short"
        assert profile.get("min_indicators", 0) >= 2, f"{actor} min_indicators must be ≥2"


def test_lazarus_dprk_attribution():
    """Lazarus: DNS tunneling + credential theft + rclone — DPRK financial heist."""
    res = attribute_apt(
        phase_tags={"credential_theft", "secret_access", "data_exfiltration_rclone", "dns_tunnel"},
        pivot_keys={"attacker_zone:north_korea_proxy"},
    )
    assert res is not None
    # Lazarus or similar (apt41 also matches some of these)
    assert res["actor"] in ("lazarus", "apt41")
