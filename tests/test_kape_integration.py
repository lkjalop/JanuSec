import os
import json
from src.core.ingest.kape_parser import normalize_kape_stream, _load_sidecar_hashes_for_path
from src.core.ingest.hash_merge import merge_hashes


def test_kape_integration_merge(tmp_path, monkeypatch):
    # Create a fake upload dir
    upload_dir = tmp_path / 'data' / 'uploads' / 'kape' / 'bundle-1'
    upload_dir.mkdir(parents=True)

    # write sample artifact files
    (upload_dir / 'mft.txt').write_text('C:\\Temp\\evil.exe\t133176576000000000 entry')
    (upload_dir / 'userassist.txt').write_text('{GUID}\\Count\\MyApp.exe -> Count=7; LastRun=2024-01-02T13:14:15')

    # sidecar next to bundle
    sidecar = {
        'evil.exe': {'sha256': 'aa' * 32},
        'myapp.exe': {'md5': 'bb' * 16}
    }
    sidecar_path = upload_dir / 'sidecar_hashes.json'
    sidecar_path.write_text(json.dumps(sidecar))

    # load lines and sidecar via parser helpers (simulate worker behavior)
    lines = []
    for p in ['mft.txt', 'userassist.txt']:
        lines += (upload_dir / p).read_text().splitlines()

    sidecar_map = _load_sidecar_hashes_for_path(str(sidecar_path.with_suffix('')))
    assert 'evil.exe' in sidecar_map

    parsed = list(normalize_kape_stream(lines))
    # simulate merge: for each parsed event, if basename matches sidecar entry, apply sidecar hashes
    merged_events = []
    for e in parsed:
        fp = e.get('file_path')
        if not fp:
            merged_events.append(e)
            continue
        bn = os.path.basename(fp).lower()
        side = sidecar_map.get(bn)
        ph = e.get('hashes')
        e['hashes'] = merge_hashes(ph or {}, side or {})
        merged_events.append(e)

    # verify merged events have sidecar hashes when matching
    found_evil = [e for e in merged_events if os.path.basename(e.get('file_path', '')).lower() == 'evil.exe']
    assert found_evil and 'sha256' in found_evil[0]['hashes']
