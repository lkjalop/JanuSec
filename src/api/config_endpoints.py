from __future__ import annotations

import os
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/config", tags=["config"])


@router.get('/assessment_defaults')
async def get_assessment_defaults() -> dict:
    """Return the assessment defaults YAML as JSON.

    This endpoint is intentionally small and file-backed to avoid introducing
    new dependencies or persistence layers. It reads `config/assessment_defaults.yml`
    relative to the repository root and returns the parsed YAML.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    cfg_path = os.path.join(repo_root, 'config', 'assessment_defaults.yml')
    if not os.path.exists(cfg_path):
        raise HTTPException(status_code=404, detail='assessment_defaults not found')
    try:
        # Try parsing via PyYAML if available.
        try:
            import yaml  # type: ignore
            with open(cfg_path, 'r', encoding='utf-8') as fh:
                data = yaml.safe_load(fh)
            return data or {}
        except Exception:
            # Fall back to returning raw YAML as a single-field payload if
            # PyYAML not available; attempt a tiny, best-effort YAML->dict
            # parser for simple mapping use-cases to avoid forcing the raw
            # YAML payload on the client. This is intentionally limited and
            # should not be treated as a full YAML implementation.
            def _simple_yaml_parse(text: str) -> dict:
                out = {}
                stack = [out]
                indent_stack = [0]
                for line in text.splitlines():
                    if not line.strip() or line.strip().startswith('#'):
                        continue
                    # count leading spaces
                    indent = len(line) - len(line.lstrip(' '))
                    # basic key: value
                    if ':' in line:
                        key, val = line.split(':', 1)
                        key = key.strip()
                        val = val.strip()
                        # promote or demote stack according to indent
                        while indent_stack and indent < indent_stack[-1]:
                            stack.pop(); indent_stack.pop()
                        if val == '':
                            # start a nested mapping
                            node = {}
                            stack[-1][key] = node
                            stack.append(node)
                            indent_stack.append(indent + 2)
                        else:
                            # attempt to coerce boolean/number
                            if val.lower() in ('true', 'false'):
                                v = val.lower() == 'true'
                            else:
                                try:
                                    if '.' in val:
                                        v = float(val)
                                    else:
                                        v = int(val)
                                except Exception:
                                    v = val
                            stack[-1][key] = v
                return out

            with open(cfg_path, 'r', encoding='utf-8') as fh:
                raw = fh.read()
            parsed = _simple_yaml_parse(raw)
            if parsed:
                return parsed
            return {'raw': raw}
    except Exception as exc:  # pragma: no cover - simple file read
        raise HTTPException(status_code=500, detail=f'failed to load config: {exc}')
