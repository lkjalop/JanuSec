#!/usr/bin/env python3
"""Count all registered correlation rules."""
import sys
sys.path.insert(0, 'src')

from src.core.correlation.rules.registry import CORRELATION_RULES

# Import all rule modules to trigger registration
from src.core.correlation.rules.week1 import office_macro_chain, powershell_encoded, amsi_bypass, office_spawn_ps, scheduled_task_lolbin
from src.core.correlation.rules.week2 import lsass_openprocess, registry_run_keys, new_service_nonstandard_path
from src.core.correlation.rules.weekX import expanded_batch, graph_week1
from src.core.correlation.rules.batch_more import additional_30

rules = CORRELATION_RULES.list()
print(f'Total registered rules: {len(rules)}')
print(f'\nBreakdown by module:')
print(f'  Week 1 rules: ~5')
print(f'  Week 2 rules: ~3')
print(f'  Expanded batch: ~40')
print(f'  Additional 30: ~30')
print(f'  Graph rules: varies')
print(f'\nAll rule names:')
for r in sorted([rule.name for rule in rules]):
    print(f'  - {r}')
