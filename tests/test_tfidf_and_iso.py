from src.ml.tfidf_profile import TfidfProfile, GLOBAL_TFIDF
from src.ml.isolation_model import IsolationWrapper, GLOBAL_ISO_MODEL

def test_tfidf_basic():
    p = TfidfProfile()
    p.add_document(['a','b','c'])
    p.add_document(['a','d'])
    s = p.get_rarity_score(['c'])
    assert 0.0 <= s <= 1.0
    s2 = p.get_rarity_score(['a'])
    assert s2 <= s or s2 == s


def test_iso_wrapper_neutral():
    # Without sklearn available, wrapper returns 0.0
    assert GLOBAL_ISO_MODEL.score([0.1, 0.2]) == 0.0
