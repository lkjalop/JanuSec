from src.core.graph.email_hopgraph import normalize_display_name, detect_homograph, cluster_by_campaign


def test_detect_homograph_ascii():
    assert detect_homograph('example.com') is False


def test_detect_homograph_idn():
    # Cyrillic 'а' (U+0430) looks like 'a'
    dom = 'exаmple.com'  # contains cyrillic a
    assert detect_homograph(dom) is True


def test_cluster_by_campaign_basic():
    emails = [
        {'from': 'phish@example.com', 'subject': 'Pay invoice'},
        {'from': 'noreply@example.com', 'subject': 'Pay invoice now'},
        {'from': 'alerts@other.com', 'subject': 'Notice'},
    ]
    groups = cluster_by_campaign(emails)
    # expect at least two groups
    assert any(len(g) >= 2 for g in groups)
