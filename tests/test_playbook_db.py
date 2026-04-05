import os
import json
import time
from pathlib import Path

from src.analysis import playbook_db as pdb


def _write_db(content: dict):
    p = Path(os.getcwd()) / 'data' / 'playbooks'
    p.mkdir(parents=True, exist_ok=True)
    fp = p / 'mitre_playbooks.json'
    with open(fp, 'w', encoding='utf-8') as fh:
        json.dump(content, fh)


def test_reload_forces_new_content(tmp_path, monkeypatch):
    # Backup any existing DB
    db_dir = Path(os.getcwd()) / 'data' / 'playbooks'
    db_dir.mkdir(parents=True, exist_ok=True)
    db_file = db_dir / 'mitre_playbooks.json'

    orig = None
    if db_file.exists():
        orig = db_file.read_text(encoding='utf-8')

    try:
        # write initial
        _write_db({'T0001': {'desc': 'original'}})
        # clear internal cache and load
        pdb.reload()
        r1 = pdb.get_playbook_for_mitre('T0001')
        assert r1.get('desc') == 'original'

        # overwrite on disk
        _write_db({'T0001': {'desc': 'updated'}, 'T0002': {'desc': 'new'}})

        # without reload (cache active) should still return original
        r2 = pdb.get_playbook_for_mitre('T0001')
        assert r2.get('desc') == 'original'

        # force reload
        pdb.reload()
        r3 = pdb.get_playbook_for_mitre('T0001')
        assert r3.get('desc') == 'updated'
        r4 = pdb.get_playbook_for_mitre('T0002')
        assert r4.get('desc') == 'new'

    finally:
        # restore
        if orig is not None:
            db_file.write_text(orig, encoding='utf-8')