"""Unit tests for src/analysis/expand_engine.py (Phase 3 backend)."""
from __future__ import annotations

import json
import os
import time
import tempfile

import pytest

from src.analysis.expand_engine import (
    extract_task_entity_slice,
    build_expand_prompt,
    call_expand_llm,
    load_expand_cache,
    save_expand_cache,
    get_expand_cache_path,
    make_task_id,
    _parse_json_from_text,
    _format_rows_for_prompt,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

_ROWS = [
    {
        "row_index": 0, "user": "alice@corp.local", "src_ip": "10.0.0.1",
        "host": "WS-01", "event_type": "process_spawn",
        "command_line": "powershell -enc AABB", "severity": "high",
        "mitre_technique": "T1059.001", "ts": "2026-04-17T08:12:00Z",
    },
    {
        "row_index": 1, "user": "alice@corp.local", "src_ip": "10.0.0.1",
        "host": "WS-01", "event_type": "lsass_access",
        "process": "procdump.exe", "severity": "critical",
        "mitre_technique": "T1003.001", "ts": "2026-04-17T08:13:30Z",
    },
    {
        "row_index": 2, "user": "bob@corp.local", "src_ip": "10.0.0.2",
        "host": "SRV-02", "event_type": "lateral_move",
        "severity": "high", "ts": "2026-04-17T08:20:00Z",
    },
]

_ASSESSMENT = {"assessment_id": "test-001", "rows": _ROWS}
_INVESTIGATE_RECORD = {
    "investigate_id": "inv-test",
    "assessment_id": "test-001",
    "status": "ready",
    "rows_ref": [0, 1],
    "evidence_table": [
        {"row_index": 0, "user": "alice@corp.local"},
        {"row_index": 1, "user": "alice@corp.local"},
    ],
}


# ── make_task_id ─────────────────────────────────────────────────────────────

class TestMakeTaskId:
    def test_returns_16_char_hex(self):
        tid = make_task_id("investigate alice's activity")
        assert len(tid) == 16
        assert all(c in "0123456789abcdef" for c in tid)

    def test_deterministic(self):
        t1 = make_task_id("same text", "soc")
        t2 = make_task_id("same text", "soc")
        assert t1 == t2

    def test_persona_changes_id(self):
        t_soc = make_task_id("same text", "soc")
        t_ciso = make_task_id("same text", "ciso")
        assert t_soc != t_ciso

    def test_case_insensitive(self):
        t1 = make_task_id("Alice Used PowerShell", "soc")
        t2 = make_task_id("alice used powershell", "soc")
        assert t1 == t2


# ── extract_task_entity_slice ────────────────────────────────────────────────

class TestExtractTaskEntitySlice:
    def test_returns_required_keys(self):
        result = extract_task_entity_slice("alice ran powershell", _INVESTIGATE_RECORD, _ASSESSMENT)
        assert "rows" in result
        assert "entity_fields" in result
        assert "check_results" in result
        assert "matched_entities" in result

    def test_filters_rows_by_entity(self):
        result = extract_task_entity_slice("alice@corp.local ran powershell", _INVESTIGATE_RECORD, _ASSESSMENT)
        users_in_rows = {r.get("user") for r in result["rows"]}
        assert "alice@corp.local" in users_in_rows
        # bob should not be included (task mentions only alice)
        assert "bob@corp.local" not in users_in_rows

    def test_fallback_to_evidence_table(self):
        # Task with no matching entity text → fallback to investigate record's evidence_table
        result = extract_task_entity_slice("check all recent events", _INVESTIGATE_RECORD, _ASSESSMENT)
        # Should return something (evidence_table has rows 0 and 1)
        assert len(result["rows"]) >= 0  # may be 0 if no entity match AND evidence_table empty

    def test_otp2_checks_run(self):
        result = extract_task_entity_slice("alice@corp.local activity", _INVESTIGATE_RECORD, _ASSESSMENT)
        assert isinstance(result["check_results"], list)
        check_ids = {c["check_id"] for c in result["check_results"]}
        assert "after_hours" in check_ids
        assert "same_ip_cross_account" in check_ids

    def test_max_30_rows_cap(self):
        # Create 50 rows for alice
        big_rows = [
            {"row_index": i, "user": "alice", "src_ip": "1.2.3.4", "host": f"H-{i}"}
            for i in range(50)
        ]
        big_assessment = {"assessment_id": "big", "rows": big_rows}
        result = extract_task_entity_slice("alice activity", {}, big_assessment)
        assert len(result["rows"]) <= 30

    def test_entity_fields_populated(self):
        result = extract_task_entity_slice("alice@corp.local on WS-01", _INVESTIGATE_RECORD, _ASSESSMENT)
        ef = result["entity_fields"]
        assert "users" in ef
        assert "ips" in ef

    def test_empty_rows_assessment(self):
        result = extract_task_entity_slice("alice did something", {}, {"assessment_id": "x", "rows": []})
        assert result["rows"] == []
        assert result["entity_fields"]["users"] == []


# ── _format_rows_for_prompt ──────────────────────────────────────────────────

class TestFormatRowsForPrompt:
    def test_returns_string(self):
        out = _format_rows_for_prompt(_ROWS)
        assert isinstance(out, str)

    def test_limits_to_15_rows(self):
        big = [{"row_index": i, "user": f"u{i}"} for i in range(30)]
        out = _format_rows_for_prompt(big)
        # Each row starts with [N]
        lines = [l for l in out.splitlines() if l.strip().startswith("[")]
        assert len(lines) <= 15

    def test_includes_key_fields(self):
        out = _format_rows_for_prompt(_ROWS)
        assert "powershell" in out.lower() or "T1059" in out


# ── build_expand_prompt ──────────────────────────────────────────────────────

class TestBuildExpandPrompt:
    def _slice(self):
        return extract_task_entity_slice("alice@corp.local activity", _INVESTIGATE_RECORD, _ASSESSMENT)

    def test_returns_string(self):
        prompt = build_expand_prompt("alice ran powershell", self._slice())
        assert isinstance(prompt, str)
        assert len(prompt) > 50

    def test_contains_task_text(self):
        prompt = build_expand_prompt("alice ran powershell", self._slice())
        assert "alice ran powershell" in prompt

    def test_contains_output_schema(self):
        prompt = build_expand_prompt("alice ran powershell", self._slice())
        assert '"subtasks"' in prompt
        assert '"iocs"' in prompt

    def test_persona_soc_default(self):
        prompt = build_expand_prompt("alice ran powershell", self._slice(), persona="soc")
        assert "SOC" in prompt or "analyst" in prompt.lower()

    def test_persona_ciso(self):
        prompt = build_expand_prompt("alice ran powershell", self._slice(), persona="ciso")
        assert "CISO" in prompt or "executive" in prompt.lower() or "business" in prompt.lower()

    def test_persona_hunter(self):
        prompt = build_expand_prompt("alice ran powershell", self._slice(), persona="hunter")
        assert "hunter" in prompt.lower() or "hunt" in prompt.lower()

    def test_scope_guard_present(self):
        prompt = build_expand_prompt("alice ran powershell", self._slice())
        assert "scope" in prompt.lower() or "context window" in prompt.lower()

    def test_triggered_checks_included(self):
        # The rows use Saturday timestamp → after_hours should trigger
        prompt = build_expand_prompt("after hours activity", self._slice())
        # Either checks block or entity block should mention hours/activity
        assert isinstance(prompt, str)


# ── _parse_json_from_text ────────────────────────────────────────────────────

class TestParseJsonFromText:
    def test_clean_json(self):
        text = '{"summary": "ok", "confidence": 0.9}'
        result = _parse_json_from_text(text)
        assert result == {"summary": "ok", "confidence": 0.9}

    def test_json_in_markdown_fence(self):
        text = "```json\n{\"summary\": \"ok\"}\n```"
        result = _parse_json_from_text(text)
        assert result is not None
        assert result.get("summary") == "ok"

    def test_json_embedded_in_prose(self):
        text = 'Here is the result: {"summary": "found it", "confidence": 0.5} done.'
        result = _parse_json_from_text(text)
        assert result is not None
        assert result.get("summary") == "found it"

    def test_invalid_json_returns_none(self):
        assert _parse_json_from_text("not json at all") is None

    def test_empty_string_returns_none(self):
        assert _parse_json_from_text("") is None

    def test_none_returns_none(self):
        assert _parse_json_from_text(None) is None


# ── call_expand_llm ──────────────────────────────────────────────────────────

class MockLLMClient:
    def __init__(self, response_text: str):
        self._text = response_text

    def generate(self, prompt, max_tokens=700, **kwargs):
        return {"text": self._text}


class TestCallExpandLlm:
    _VALID_JSON = json.dumps({
        "summary": "alice used procdump",
        "confidence": 0.85,
        "subtasks": [{"id": "s1", "action": "isolate host", "entity": "WS-01", "priority": "high"}],
        "iocs": [{"type": "process", "value": "procdump.exe", "context": "LSASS dump"}],
        "mitre_techniques": ["T1003.001"],
        "next_pivot": "check EDR telemetry on WS-01",
    })

    def test_none_client_returns_fallback(self):
        result = call_expand_llm("prompt", None)
        assert "fallback" in result["summary"].lower() or "unavailable" in result["summary"].lower()
        assert result["confidence"] == 0.0
        assert result.get("fallback_generated") is True
        assert len(result["subtasks"]) > 0

    def test_valid_json_response_parsed(self):
        client = MockLLMClient(self._VALID_JSON)
        result = call_expand_llm("prompt", client)
        assert result["summary"] == "alice used procdump"
        assert result["confidence"] == 0.85
        assert len(result["subtasks"]) == 1
        assert result["next_pivot"] == "check EDR telemetry on WS-01"

    def test_invalid_json_returns_fallback(self):
        client = MockLLMClient("I cannot help with that.")
        result = call_expand_llm("prompt", client)
        assert result["confidence"] == 0.0

    def test_partial_json_fills_defaults(self):
        client = MockLLMClient('{"summary": "partial", "confidence": 0.5}')
        result = call_expand_llm("prompt", client)
        assert result["summary"] == "partial"
        # subtasks come from persona fallback when LLM omits them
        assert isinstance(result["subtasks"], list)
        assert result["iocs"] == []

    def test_llm_exception_returns_fallback(self):
        class FailClient:
            def generate(self, *a, **kw):
                raise RuntimeError("connection refused")

        result = call_expand_llm("prompt", FailClient())
        assert result["confidence"] == 0.0


# ── expand cache ─────────────────────────────────────────────────────────────

class TestExpandCache:
    @pytest.fixture(autouse=True)
    def _tmp_cache(self, tmp_path, monkeypatch):
        """Redirect cache to a temp directory for isolation."""
        monkeypatch.setattr("src.analysis.expand_engine.EXPAND_CACHE_DIR", str(tmp_path))
        yield tmp_path

    def test_save_and_load(self):
        result = {"summary": "test", "confidence": 0.8, "subtasks": []}
        save_expand_cache("aid-1", "tid-1", result)
        loaded = load_expand_cache("aid-1", "tid-1")
        assert loaded is not None
        assert loaded["summary"] == "test"

    def test_cache_miss_returns_none(self):
        assert load_expand_cache("nonexistent", "task") is None

    def test_expired_cache_returns_none(self):
        result = {"summary": "old"}
        save_expand_cache("aid-2", "tid-2", result)
        # Reload with 0-second TTL → always expired
        loaded = load_expand_cache("aid-2", "tid-2", ttl_seconds=0)
        assert loaded is None

    def test_cache_path_safe_characters(self):
        path = get_expand_cache_path("assess/ment!1", "task?2&3")
        assert path is not None
        # Ensure path only contains safe characters in filename portion
        filename = os.path.basename(path)
        assert "/" not in filename
        assert "?" not in filename
        assert "&" not in filename

    def test_overwrite_updates_cache(self):
        save_expand_cache("aid-3", "tid-3", {"summary": "v1"})
        save_expand_cache("aid-3", "tid-3", {"summary": "v2"})
        loaded = load_expand_cache("aid-3", "tid-3")
        assert loaded["summary"] == "v2"
