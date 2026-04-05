from src.core.entity_resolution import (
    canonicalize_user, canonicalize_host, canonicalize_domain,
    canonicalize_ip, canonicalize_hash, canonical_entity_id,
)

def test_user_canonicalization_variants():
    assert canonicalize_user('Alice') == 'alice'
    assert canonicalize_user('EXAMPLE\\Alice') == 'alice'
    assert canonicalize_user('alice@example.com') == 'alice'


def test_host_domain_canonicalization():
    assert canonicalize_host('Host01.') == 'host01'
    assert canonicalize_domain('Example..COM') == 'example.com'


def test_ip_and_hash_canonicalization():
    assert canonicalize_ip('[2001:0db8::1]') == '2001:0db8::1'
    assert canonicalize_hash('AA:BB:CC') == 'aabbcc'


def test_canonical_entity_id():
    assert canonical_entity_id('identity', 'Alice@EXAMPLE') == 'identity:alice'
    assert canonical_entity_id('endpoint', 'Host01') == 'endpoint:host01'
