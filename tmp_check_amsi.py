import importlib
from src.core.correlation.rules.registry import CORRELATION_RULES

importlib.import_module('src.core.correlation.rules.week1.amsi_bypass')
print('registered:', 'corr_amsi_bypass' in CORRELATION_RULES._rules)
event={'process':'powershell.exe','cmdline':'-NoProfile -ExecutionPolicy Bypass -EncodedCommand QQ==','event.source':'script.dll'}
res = CORRELATION_RULES.evaluate(event)
print('fired', [r.name for r in res])
