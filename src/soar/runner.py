from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List

import httpx
from src.soar.connectors import get_registry, ConnectorError
from src.soar.connector_audit import record_audit

DEFAULT_TIMEOUT = 5


class StepResult:
    def __init__(self, name: str, ok: bool, detail: str | None = None, data: Any | None = None):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.data = data

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "data": self.data}


class PlaybookRunner:
    """Very small sequential playbook runner for demo.

    Playbook example:
    {
      "name": "ioc-auto-block",
      "dry_run": true,
      "steps": [
        {"type":"enrich","params": {"source":"ti"}},
        {"type":"open_case","params": {"title": "IOC auto-block"}},
        {"type":"block_ip","params": {"ip":"1.2.3.4"}},
        {"type":"notify","params": {"channel":"slack","msg":"blocked 1.2.3.4"}}
      ]
    }
    """

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    async def _step_enrich(self, params: Dict[str, Any]) -> StepResult:
        # Demo enrichment: sleep and return fake enrichment
        await asyncio.sleep(0.01)
        return StepResult("enrich", True, data={"intel_score": 95})

    async def _step_open_case(self, params: Dict[str, Any]) -> StepResult:
        # For demo we just record timestamped case id
        await asyncio.sleep(0.01)
        case_id = f"case-{int(time.time()*1000)}"
        return StepResult("open_case", True, data={"case_id": case_id})

    async def _step_block_ip(self, params: Dict[str, Any]) -> StepResult:
        ip = params.get("ip")
        if not ip:
            return StepResult("block_ip", False, detail="missing ip")
        if self.dry_run:
            return StepResult("block_ip", True, detail="dry-run: not actually blocked", data={"ip": ip})
        # Use connectors if available
        try:
            reg = get_registry()
            connector_name = params.get('connector') or 'firewall.block_ip'
            conn = reg.get(connector_name)
            if conn:
                # attach playbook context to params for auditing; playbook context
                # is provided via params under '_playbook' or outer runner state
                pb_name = params.get('_playbook_name') or params.get('playbook')
                if not pb_name:
                    # no playbook provided in params; leave as-is
                    pass
                else:
                    params.setdefault('playbook', pb_name)
                res = await conn(params)
                try:
                    # record a lightweight audit entry for non-idp connectors
                    record_audit({'connector': connector_name, 'params': {'ip': ip}, 'playbook': params.get('playbook'), 'tenant': params.get('tenant')})
                except Exception:
                    pass
                return StepResult("block_ip", True, data=res)
            # fallback to a noop stub
            await asyncio.sleep(0.01)
            return StepResult("block_ip", True, data={"ip": ip})
        except ConnectorError as e:
            return StepResult("block_ip", False, detail=str(e))
        except Exception as e:
            return StepResult("block_ip", False, detail=str(e))

    async def _step_notify(self, params: Dict[str, Any]) -> StepResult:
        # send a simple HTTP POST to webhook if configured
        url = params.get("webhook_url")
        msg = params.get("msg") or params.get("message")
        if self.dry_run:
            return StepResult("notify", True, detail="dry-run: not sent", data={"url": url, "msg": msg})
        if not url:
            return StepResult("notify", False, detail="no webhook_url")
        try:
            # allow using a connector for notify if specified
            reg = get_registry()
            connector_name = params.get('connector')
            if connector_name:
                conn = reg.get(connector_name)
                if conn:
                    res = await conn({'url': url, 'msg': msg, **params})
                    return StepResult("notify", True, data=res)
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as c:
                resp = await c.post(url, json={"text": msg})
                return StepResult("notify", resp.status_code < 300, detail=str(resp.status_code), data=resp.text[:200])
        except Exception as e:
            return StepResult("notify", False, detail=str(e))

    async def _step_revoke_sessions(self, params: Dict[str, Any]) -> StepResult:
        user = params.get("user") or params.get("username")
        if not user:
            return StepResult("revoke_sessions", False, detail="missing user")
        if self.dry_run:
            await asyncio.sleep(0.01)
            return StepResult("revoke_sessions", True, detail="sessions revoked (dry-run)", data={"user": user})
        try:
            reg = get_registry()
            connector_name = params.get('connector') or 'idp.revoke_sessions'
            conn = reg.get(connector_name)
            if not conn:
                return StepResult("revoke_sessions", False, detail=f"no connector {connector_name}")
            res = await conn(params)
            return StepResult("revoke_sessions", True, data=res)
        except ConnectorError as e:
            return StepResult("revoke_sessions", False, detail=str(e))
        except Exception as e:
            return StepResult("revoke_sessions", False, detail=str(e))

    async def _step_quarantine_file(self, params: Dict[str, Any]) -> StepResult:
        file_hash = params.get("file_hash")
        endpoints = params.get("endpoints") or []
        if not file_hash:
            return StepResult("quarantine_file", False, detail="missing file_hash")
        if self.dry_run:
            await asyncio.sleep(0.01)
            return StepResult("quarantine_file", True, detail="quarantined (dry-run)", data={"file_hash": file_hash, "endpoints": endpoints})
        try:
            reg = get_registry()
            connector_name = params.get('connector') or 'file.quarantine'
            conn = reg.get(connector_name)
            if not conn:
                return StepResult("quarantine_file", False, detail=f"no connector {connector_name}")
            res = await conn(params)
            return StepResult("quarantine_file", True, data=res)
        except ConnectorError as e:
            return StepResult("quarantine_file", False, detail=str(e))
        except Exception as e:
            return StepResult("quarantine_file", False, detail=str(e))

    async def _step_policy_rollback(self, params: Dict[str, Any]) -> StepResult:
        policy_id = params.get("policy_id") or "shadow-admin-rollback"
        if self.dry_run:
            await asyncio.sleep(0.01)
            return StepResult("policy_rollback", True, detail="policy rollback scheduled (dry-run)", data={"policy_id": policy_id})
        # For demo we still return success; real implementation would call a connector
        try:
            reg = get_registry()
            connector_name = params.get('connector')
            if connector_name:
                conn = reg.get(connector_name)
                if conn:
                    res = await conn(params)
                    return StepResult("policy_rollback", True, data=res)
        except ConnectorError as e:
            return StepResult("policy_rollback", False, detail=str(e))
        except Exception:
            pass
        return StepResult("policy_rollback", True, detail="policy rollback scheduled (dry-run)", data={"policy_id": policy_id})

    async def _step_disable_mailbox_rule(self, params: Dict[str, Any]) -> StepResult:
        user = params.get("user") or params.get("mailbox")
        rule = params.get("rule_name") or "suspicious-forward"
        if not user:
            return StepResult("disable_mailbox_rule", False, detail="missing user")
        if self.dry_run:
            await asyncio.sleep(0.01)
            return StepResult("disable_mailbox_rule", True, detail="rule disabled (dry-run)", data={"user": user, "rule": rule})
        try:
            reg = get_registry()
            connector_name = params.get('connector') or 'mailbox.disable_rule'
            conn = reg.get(connector_name)
            if not conn:
                return StepResult("disable_mailbox_rule", False, detail=f"no connector {connector_name}")
            res = await conn(params)
            return StepResult("disable_mailbox_rule", True, data=res)
        except ConnectorError as e:
            return StepResult("disable_mailbox_rule", False, detail=str(e))
        except Exception as e:
            return StepResult("disable_mailbox_rule", False, detail=str(e))

    async def _step_reset_credentials(self, params: Dict[str, Any]) -> StepResult:
        user = params.get("user") or params.get("username")
        if not user:
            return StepResult("reset_credentials", False, detail="missing user")
        if self.dry_run:
            await asyncio.sleep(0.01)
            return StepResult("reset_credentials", True, detail="credentials reset initiated (dry-run)", data={"user": user})
        # Reset credentials could be an IdP connector call
        try:
            reg = get_registry()
            connector_name = params.get('connector') or 'idp.revoke_sessions'
            conn = reg.get(connector_name)
            if not conn:
                return StepResult("reset_credentials", False, detail=f"no connector {connector_name}")
            res = await conn(params)
            return StepResult("reset_credentials", True, data=res)
        except ConnectorError as e:
            return StepResult("reset_credentials", False, detail=str(e))
        except Exception as e:
            return StepResult("reset_credentials", False, detail=str(e))

    async def run(self, playbook: Dict[str, Any]) -> Dict[str, Any]:
        dry = bool(playbook.get("dry_run", self.dry_run))
        self.dry_run = dry
        steps: List[Dict[str, Any]] = playbook.get("steps", [])
        results: List[Dict[str, Any]] = []
        for s in steps:
            t = s.get("type")
            params = s.get("params", {}) or {}
            # provide playbook context to steps for auditing/connector use
            try:
                params.setdefault('_playbook_name', playbook.get('name') if isinstance(playbook, dict) else None)
            except Exception:
                pass
            if t == "enrich":
                res = await self._step_enrich(params)
            elif t == "open_case":
                res = await self._step_open_case(params)
            elif t == "block_ip":
                res = await self._step_block_ip(params)
            elif t == "notify":
                res = await self._step_notify(params)
            elif t == "revoke_sessions":
                res = await self._step_revoke_sessions(params)
            elif t == "quarantine_file":
                res = await self._step_quarantine_file(params)
            elif t == "policy_rollback":
                res = await self._step_policy_rollback(params)
            elif t == "disable_mailbox_rule":
                res = await self._step_disable_mailbox_rule(params)
            elif t == "reset_credentials":
                res = await self._step_reset_credentials(params)
            else:
                res = StepResult(t or "unknown", False, detail="unsupported step type")
            results.append(res.to_dict())
            # stop on failure
            if not res.ok:
                break
        return {"playbook": playbook.get("name"), "dry_run": self.dry_run, "results": results}


def run_playbook_sync(playbook: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    runner = PlaybookRunner(dry_run=dry_run)
    return asyncio.get_event_loop().run_until_complete(runner.run(playbook))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: runner.py <playbook.json>")
        raise SystemExit(2)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        pb = json.load(f)
    out = run_playbook_sync(pb)
    print(json.dumps(out, indent=2))
