from src.core.correlation.rules.registry import CORRELATION_RULES


def test_office_macro_direct_powershell():
    event = {
        'event.source': 'file:invoice.docm|vbaProject.bin',
        'process': 'powershell.exe',
        'cmdline': 'powershell -EncodedCommand QQBz'  # truncated encoded command
    }
    fired = CORRELATION_RULES.evaluate(event)
    names = [r.name for r in fired]
    assert 'corr_office_macro_ps' in names


def test_office_macro_child_powershell():
    event = {
        'event.source': 'file:invoice.docm',
        'process': 'winword.exe',
        'children': [
            {'process': 'powershell.exe', 'cmdline': 'powershell -EncodedCommand QQBz'},
        ]
    }
    fired = CORRELATION_RULES.evaluate(event)
    names = [r.name for r in fired]
    assert 'corr_office_macro_ps' in names


def test_office_macro_false_positive():
    event = {
        'event.source': 'file:readme.txt',
        'process': 'notepad.exe',
        'cmdline': ''
    }
    fired = CORRELATION_RULES.evaluate(event)
    names = [r.name for r in fired]
    assert 'corr_office_macro_ps' not in names
