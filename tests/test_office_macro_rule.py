import importlib
import sys
from types import SimpleNamespace

from src.core.correlation.rules.week1.office_macro_chain import office_macro_spawn_powershell, exec_office_macro_chain


def test_office_macro_rule_basic_fallback():
    # Construct an event matching the boolean rule signature
    evt = {
        'event.source': 'document.docm',
        'source': 'document.docm',
        'process': 'powershell.exe',
        'command_line': 'powershell.exe -EncodedCommand AAAAA',
    }
    # The boolean rule should return True for encoded powershell spawned from a docm
    assert office_macro_spawn_powershell(evt) is True


def test_exec_office_macro_chain():
    evt = {'parent_process': 'winword.exe', 'child_process': 'powershell.exe'}
    assert exec_office_macro_chain(evt) is True
