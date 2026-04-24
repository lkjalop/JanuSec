#!/usr/bin/env python3
import os
import sys
import json
import pprint

import os
import sys
import json
import pprint
import csv


def load_json_flex(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        pass
    with open(path, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]
    if not lines:
        raise ValueError('empty file')
    if len(lines) == 1:
        return json.loads(lines[0])
    objs = []
    for ln in lines:
        try:
            objs.append(json.loads(ln))
        except Exception:
            continue
    if objs:
        return objs
    raise ValueError('Could not parse JSON lines')


def load_data(path):
    lower = path.lower()
    if lower.endswith('.json'):
        return load_json_flex(path)
    if lower.endswith('.csv'):
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return [r for r in reader]
    if lower.endswith('.xlsx') or lower.endswith('.xls'):
        # Prefer pandas if available
        try:
            import pandas as pd

            df = pd.read_excel(path)
            return df.fillna('').to_dict(orient='records')
        except Exception as e:
            raise RuntimeError('Excel support requires pandas: %s' % e)
    # Fallback: try json then csv
    try:
        return load_json_flex(path)
    except Exception:
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = [r for r in reader]
            if rows:
                return rows
    raise ValueError('Could not parse file as json/csv/xlsx')


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'dump/janusec_okta_m365_events.json'
    p = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
    if not os.path.exists(p):
        print('file not found:', p)
        sys.exit(2)
    try:
        data = load_data(p)
    except Exception as e:
        print('Failed to load data:', e)
        sys.exit(3)
    # pick a representative row
    if isinstance(data, list) and data:
        row = data[0]
    elif isinstance(data, dict):
        row = data
    else:
        print('Unrecognized data shape:', type(data))
        sys.exit(4)
    try:
        from src.analysis.auto_llm import LLMAssessmentClient
    except Exception as e:
        print('Could not import LLMAssessmentClient:', e)
        sys.exit(5)
    client = LLMAssessmentClient()
    ctx = {'model': os.environ.get('LLM_MODEL', 'qwen2.5:14b'), 'tier': 'tier1'}
    print('Invoking summarize_row with context:', ctx)
    try:
        res = client.summarize_row(row, ctx)
    except Exception as e:
        print('Error during summarize_row:', e)
        raise
    pprint.pprint(res)


if __name__ == '__main__':
    main()
