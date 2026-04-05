"""Small CLI to run a rule against an in-memory fake graph for quick verification.

Usage:
  python scripts/run_rule.py rules/examples/corr_office_macro_ps.yaml
"""
import sys
from src.core.rules.runner import load_and_run

class FakeHG:
    def __init__(self):
        self.adj = {
            'office_macro': [('host:win1','exec',{'ts':123}), ('file:ps1','created',{'ts':124})]
        }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: run_rule.py <rule.yaml>')
        sys.exit(2)
    path = sys.argv[1]
    hg = FakeHG()
    actions = load_and_run(path, hg)
    for a in actions:
        print('ACTION:', a)
