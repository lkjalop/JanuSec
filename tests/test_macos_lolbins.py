import json
from pathlib import Path
from src.core.correlation.rules.registry import CORRELATION_RULES


DATA = Path(__file__).parent / 'data'


def load(path):
    return json.loads((DATA / path).read_text())


def test_macos_osascript_network_payload():
    evt = load('macos_osascript_network_payload.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'macos_osascript_network_payload' in fired


def test_macos_open_from_downloads():
    evt = load('macos_open_from_downloads.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'macos_open_from_downloads' in fired


def test_macos_launchctl_unusual():
    evt = load('macos_launchctl_unusual.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'macos_launchctl_unusual' in fired


def test_macos_persistence_writes_userdirs():
    evt = load('macos_persistence_writes_userdirs.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'macos_persistence_writes_userdirs' in fired


def test_macos_curl_wget_exec_downloads():
    evt = load('macos_curl_wget_exec_downloads.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'macos_curl_wget_exec_downloads' in fired


def test_macos_disk_image_mount_exec():
    evt = load('macos_disk_image_mount_exec.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'macos_disk_image_mount_exec' in fired


def test_macos_python_exec_from_downloads():
    evt = load('macos_python_exec_from_downloads.json')
    fired = [r.name for r in CORRELATION_RULES.evaluate(evt)]
    assert 'macos_python_exec_from_downloads' in fired
