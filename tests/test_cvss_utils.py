from src.core.scoring.cvss_utils import adjust_cvss, map_cvss_to_exploitability


def test_adjust_cvss_basic():
    assert adjust_cvss(9.0) == 9.0
    assert adjust_cvss(9.0, temporal_factor=0.8) == 7.2
    assert adjust_cvss(9.0, temporal_factor=0.8, env_modifier=0.9) == 6.48


def test_map_cvss_to_exploitability():
    assert map_cvss_to_exploitability(0) == 0
    assert map_cvss_to_exploitability(5.0) == 5.0
    assert map_cvss_to_exploitability(10.0) == 10.0
