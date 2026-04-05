from src.core.ingest.hash_merge import merge_hashes


def test_merge_hashes_sidecar_overrides():
    parser = {'md5': 'aaaabbbbccccddddeeeeffff11112222', 'sha1': '1111222233334444555566667777888889990000'}
    sidecar = {'sha256': 'deadbeef' * 8, 'md5': '777788889999aaaabbbbccccddddeeee'}
    merged = merge_hashes(parser, sidecar)
    # sidecar sha256 present
    assert 'sha256' in merged
    # md5 overridden by sidecar
    assert merged['md5'] == sidecar['md5']
    # sha1 preserved from parser
    assert merged['sha1'] == parser['sha1']


def test_merge_with_none_inputs():
    assert merge_hashes(None, None) == {}
    assert merge_hashes({'md5': 'a'}, None) == {'md5': 'a'}
    assert merge_hashes(None, {'sha1': 'b'}) == {'sha1': 'b'}
