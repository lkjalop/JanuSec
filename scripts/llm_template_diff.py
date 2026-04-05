import json
import os
from pathlib import Path

from src.reporting.prompt_templates import PERSONA_TEMPLATES, PERSONA_TEMPLATES_META

PERSIST_PATH = Path(os.getenv('LLM_TEMPLATE_META_PATH', 'data/llm_templates_meta.json'))


def load_persisted():
    if not PERSIST_PATH.exists():
        return None
    try:
        return json.loads(PERSIST_PATH.read_text())
    except Exception:
        return None


def diff_and_exit():
    prev = load_persisted()
    if not prev:
        print('No persisted meta found; consider creating one with current meta')
        return 0
    changed = False
    if prev.get('version') != PERSONA_TEMPLATES_META.get('version'):
        print(f"Version changed: {prev.get('version')} -> {PERSONA_TEMPLATES_META.get('version')}")
        changed = True
    # shallow compare keys
    prev_keys = set(prev.get('templates', {}).keys())
    cur_keys = set(PERSONA_TEMPLATES.keys())
    added = cur_keys - prev_keys
    removed = prev_keys - cur_keys
    if added:
        print('Added templates:', ','.join(sorted(added)))
        changed = True
    if removed:
        print('Removed templates:', ','.join(sorted(removed)))
        changed = True
    if not changed:
        print('No changes detected')
    return 1 if changed else 0


if __name__ == '__main__':
    raise SystemExit(diff_and_exit())
