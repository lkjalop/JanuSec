import json
from pathlib import Path
from src.core.correlation.rules.registry import CORRELATION_RULES


DATA = Path(__file__).parent / 'data'


def load(path):
    return json.loads((DATA / path).read_text())


def test_linux_suspicious_curl_exec():
    evt = load('linux_suspicious_curl_exec.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_suspicious_curl_exec' in fired


def test_linux_cron_network_tool():
    evt = load('linux_cron_network_tool.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_cron_network_tool' in fired


def test_linux_bash_temp_exec():
    evt = load('linux_bash_temp_exec.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_bash_temp_exec' in fired


def test_linux_downloads_exec_sh():
    evt = load('linux_downloads_exec_sh.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_downloads_exec_sh' in fired


def test_linux_chmod_exec_downloads():
    evt = load('linux_chmod_exec_downloads.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_chmod_exec_downloads' in fired


def test_linux_systemctl_user_unusual():
    evt = load('linux_systemctl_user_unusual.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_systemctl_user_unusual' in fired


def test_linux_sudo_misuse():
    evt = load('linux_sudo_misuse.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_sudo_misuse_pattern' in fired


def test_linux_python_exec_downloads():
    evt = load('linux_python_exec_downloads.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'linux_python_exec_downloads' in fired
