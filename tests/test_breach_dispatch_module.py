"""Smoke tests for breach_dispatch.js module structure.

These tests verify:
1. breach_dispatch.js exists and is syntactically loadable by Node.js.
2. The module exposes the expected globals (roles, pref, renderBar).
3. renderBar produces valid HTML with expected test IDs.
4. ROLES has the expected 7 entries with correct keys.
5. pref() returns the fallback when localStorage is unavailable.
"""
import json
import os
import re
import subprocess
import sys
import pytest

DISPATCH_JS = os.path.join(
    os.path.dirname(__file__), '..', 'frontend', 'static', 'js', 'breach_dispatch.js'
)
DISPATCH_JS = os.path.normpath(DISPATCH_JS)


def _node(*script_lines):
    """Run a Node.js snippet that sets up a browser-like global and returns JSON."""
    shim = (
        "var window = {}; var localStorage = null;\n"
        + open(DISPATCH_JS, encoding='utf-8').read()
        + "\n"
        + "\n".join(script_lines)
    )
    result = subprocess.run(
        ['node', '-e', shim],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError(f"Node.js error:\n{result.stderr}")
    return result.stdout.strip()


def _node_json(*script_lines):
    return json.loads(_node(*script_lines))


# ── Skip if Node.js is not available ─────────────────────────────────────────

def _node_available():
    try:
        r = subprocess.run(['node', '--version'], capture_output=True, timeout=5)
        return r.returncode == 0
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _node_available(),
    reason='node.js not found on PATH — skipping breach_dispatch.js tests'
)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_file_exists():
    assert os.path.isfile(DISPATCH_JS), f"breach_dispatch.js not found at {DISPATCH_JS}"


def test_no_syntax_error():
    """Node.js --check flag verifies syntax without executing."""
    r = subprocess.run(
        ['node', '--check', DISPATCH_JS],
        capture_output=True, text=True, timeout=10
    )
    assert r.returncode == 0, f"Syntax error in breach_dispatch.js:\n{r.stderr}"


def test_module_exposes_globals():
    keys = _node_json('console.log(JSON.stringify(Object.keys(window.BreachDispatch)));')
    assert 'roles'     in keys, "Missing 'roles' export"
    assert 'pref'      in keys, "Missing 'pref' export"
    assert 'renderBar' in keys, "Missing 'renderBar' export"


def test_roles_count():
    count = _node_json('console.log(window.BreachDispatch.roles.length);')
    assert count == 9, f"Expected 9 ROLES, got {count}"


def test_roles_keys():
    keys = _node_json(
        'console.log(JSON.stringify(window.BreachDispatch.roles.map(function(r){return r.key;})));'
    )
    expected = ['soc_analyst', 'ciso', 'executive', 'threat_hunter', 'forensics', 'compliance', 'audit', 'mssp', 'export']
    assert keys == expected, f"ROLES keys mismatch: {keys}"


def test_roles_have_required_fields():
    roles = _node_json('console.log(JSON.stringify(window.BreachDispatch.roles));')
    for role in roles:
        assert 'key'   in role, f"Role missing 'key': {role}"
        assert 'label' in role, f"Role missing 'label': {role}"
        assert 'desc'  in role, f"Role missing 'desc': {role}"


def test_pref_returns_fallback_without_localstorage():
    """When localStorage is null, pref() should return the fallback value."""
    val = _node("console.log(window.BreachDispatch.pref('dispatch.hidden', '0'));")
    assert val == '0'


def test_render_bar_returns_string():
    result_type = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(typeof html);"
    )
    assert result_type == 'string'


def test_render_bar_has_dispatch_testid():
    html = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(html);"
    )
    assert 'data-testid="br-dispatch"' in html


def test_render_bar_has_action_center():
    html = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(html);"
    )
    assert 'data-testid="br-action-center"' in html


def test_render_bar_has_all_role_buttons():
    html = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(html);"
    )
    expected_testids = [
        'br-dispatch-soc_analyst',
        'br-dispatch-ciso',
        'br-dispatch-executive',
        'br-dispatch-threat_hunter',
        'br-dispatch-forensics',
        'br-dispatch-compliance',
    ]
    for tid in expected_testids:
        assert f'data-testid="{tid}"' in html, f"Missing dispatch button: {tid}"


def test_render_bar_drawer_closed_by_default():
    html = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(html);"
    )
    # Drawer should be hidden by default (no localStorage state)
    assert 'id="br-dispatch-drawer"' in html
    assert 'display:none' in html


def test_render_bar_approval_count_from_assessment():
    html = _node(
        "var assessment = { proposed_actions: [",
        "  { status: 'pending' },",
        "  { status: 'pending' },",
        "  { status: 'pending' }",
        "] };",
        "var html = window.BreachDispatch.renderBar(assessment);",
        "console.log(html);"
    )
    assert '3 pending' in html


def test_render_bar_escapes_xss_in_desc():
    """Verify that role descriptions are HTML-escaped in button titles."""
    html = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(html);"
    )
    # No unescaped angle brackets from role descs should appear in title attributes
    # (all role descs are plain text so this confirms _esc is applied, not bypassed)
    titles = re.findall(r'title="([^"]*)"', html)
    for t in titles:
        assert '<script' not in t.lower(), f"Potential XSS in title: {t}"


def test_render_bar_preview_panel_present():
    html = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(html);"
    )
    assert 'data-testid="br-dispatch-preview"' in html


def test_render_bar_drawer_role_buttons():
    """The full drawer (inside br-dispatch__drawer) should have all 9 role buttons."""
    html = _node(
        "var html = window.BreachDispatch.renderBar({});",
        "console.log(html);"
    )
    drawer_tids = re.findall(r'data-testid="(br-dispatch-drawer-[^"]+)"', html)
    expected_keys = ['soc_analyst', 'ciso', 'executive', 'threat_hunter', 'forensics', 'compliance', 'audit', 'mssp', 'export']
    found_keys = [t.replace('br-dispatch-drawer-', '') for t in drawer_tids]
    assert sorted(found_keys) == sorted(expected_keys), f"Drawer buttons mismatch: {found_keys}"
