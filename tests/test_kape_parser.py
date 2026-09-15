from src.core.ingest.kape_parser import normalize_kape_stream, _load_sidecar_hashes_for_path
import os


def _load_fixture_lines(name: str):
    base = os.path.join(os.path.dirname(__file__), 'fixtures', 'kape')
    path = os.path.join(base, name)
    with open(path, 'r', encoding='utf-8') as fh:
        return [l.rstrip('\n') for l in fh]


def test_kape_prefetch_amcache_shimcache_and_run():
    lines = []
    lines += _load_fixture_lines('amcache_sample.txt')
    lines += _load_fixture_lines('shimcache_sample.txt')
    lines += ['Run: MyApp = C:\\Tools\\myapp.exe /quiet']
    out = normalize_kape_stream(lines)
    types = {o.get('type') for o in out}
    assert any(t for t in types if t and ('amcache' in t or 'prefetch' in t or 'shimcache' in t))
    assert any(o.get('type') == 'kape.registry.run' for o in out)


def test_userassist_mru_mft_and_sidecar_merge():
    lines = []
    lines += _load_fixture_lines('userassist_sample.txt')
    lines += _load_fixture_lines('mru_sample.txt')
    lines += _load_fixture_lines('mft_sample.txt')

    # simulate loading a sidecar next to a KAPE bundle (path is tests/fixtures/kape/sidecar_hashes.json)
    base = os.path.join(os.path.dirname(__file__), 'fixtures', 'kape', 'sidecar_hashes')
    # sidecar loader expects basepath (without .json); our implementation loads basepath + '.json'
    sidecar_map = _load_sidecar_hashes_for_path(base)
    assert isinstance(sidecar_map, dict)

    out = normalize_kape_stream(lines)
    types = {o.get('type') for o in out}
    assert 'kape.userassist' in types
    assert 'kape.mru' in types
    mfts = [o for o in out if o.get('type') == 'kape.mft']
    assert len(mfts) >= 1
    assert isinstance(mfts[0].get('timestamp'), float)
    # Check that at least one parsed MFT or artifact corresponds to an entry present in sidecar_map
    found = False
    for e in out:
        fp = e.get('file_path') or (e.get('evidence') or {}).get('raw')
        if not fp:
            continue
        bn = os.path.basename(fp).lower()
        if bn in (k.lower() for k in sidecar_map.keys()):
            found = True
            break
    assert found
