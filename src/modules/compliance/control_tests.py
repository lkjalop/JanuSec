from __future__ import annotations

from typing import Any, Dict, List
import os
import time
import json

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


def _read_jsonl(path: str) -> List[dict]:
    items: List[dict] = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        items.append(obj)
                except Exception:
                    continue
    except FileNotFoundError:
        return []
    except Exception:
        return []
    return items


class ControlTestRunner:
    """Execute automated tests for compliance controls (best-effort).

    Tests use lightweight, local signals to avoid heavy external dependencies.
    """

    async def test_A_9_2_user_access_management(self, tenant_id: str) -> Dict[str, Any]:
        """A.9.2: User access management

        Signals:
        - artifacts/compliance/iam.jsonl lines containing user dicts with fields:
          username, mfa_enabled (bool), last_login_days_ago (int)
        """
        path = os.getenv('IAM_AUDIT_LOG', 'artifacts/compliance/iam.jsonl')
        users = [u for u in _read_jsonl(path) if not tenant_id or (u.get('tenant_id') in (None, tenant_id))]
        total = len(users)
        mfa_enabled = sum(1 for u in users if bool(u.get('mfa_enabled')))
        inactive_90d = sum(1 for u in users if int(u.get('last_login_days_ago', 0)) > 90)
        if total == 0:
            status = 'not_implemented'
        else:
            status = 'pass' if (mfa_enabled == total and inactive_90d == 0) else 'fail'
        return {
            'control_id': 'A.9.2',
            'test_name': 'User Access Management',
            'status': status,
            'timestamp': time.time(),
            'details': {
                'total_users': total,
                'mfa_enabled': mfa_enabled,
                'mfa_required': total,
                'inactive_90d': inactive_90d,
                'source': path,
            },
        }

    async def test_A_12_4_logging_monitoring(self, tenant_id: str) -> Dict[str, Any]:
        """A.12.4: Logging and monitoring

        Signals:
        - /metrics HTTP probe (or PROMETHEUS_URL)
        - artifacts/compliance/audit_trail.jsonl recent entries
        """
        # Probe metrics
        prom_ok = False
        urls = [
            os.getenv('PROMETHEUS_URL'),
            os.getenv('METRICS_URL'),
            'http://127.0.0.1:8000/metrics',
            'http://127.0.0.1:8080/metrics',
        ]
        urls = [u for u in urls if u]
        if httpx and urls:
            for u in urls:
                try:
                    async with httpx.AsyncClient(timeout=3) as client:
                        r = await client.get(u)
                    if r.status_code == 200 and ('# HELP' in r.text or 'janusec_' in r.text or 'http_requests_total' in r.text):
                        prom_ok = True
                        break
                except Exception:
                    continue
        # Audit logs within 90d
        audit_path = os.getenv('COMPLIANCE_AUDIT_LOG', 'artifacts/compliance/audit_trail.jsonl')
        items = _read_jsonl(audit_path)
        now = time.time()
        ninety_days = 90 * 86400
        recent = [e for e in items if (not tenant_id or e.get('tenant_id') in (None, tenant_id)) and (float(e.get('ts', 0)) >= (now - ninety_days))]
        passed = prom_ok and (len(recent) > 0)
        status = 'pass' if passed else ('fail' if prom_ok or items else 'not_implemented')
        return {
            'control_id': 'A.12.4',
            'test_name': 'Logging and Monitoring',
            'status': status,
            'timestamp': now,
            'details': {
                'prometheus_responding': prom_ok,
                'audit_logs_90d': len(recent),
                'audit_log_path': audit_path,
            }
        }

    async def test_A_13_1_network_security(self, tenant_id: str) -> Dict[str, Any]:
        """A.13.1: Network security

        Signals:
        - artifacts/compliance/posture.jsonl with type containing 'cloud:sg_open_0_0_0_0'
        """
        path = os.getenv('POSTURE_LOG_PATH', 'artifacts/compliance/posture.jsonl')
        items = _read_jsonl(path)
        exposures = 0
        for it in items:
            try:
                t = str(it.get('type') or '').lower()
                if 'cloud:sg_open_0_0_0_0' in t:
                    if not tenant_id or it.get('tenant_id') in (None, tenant_id):
                        exposures += 1
            except Exception:
                continue
        status = 'pass' if exposures == 0 and items else ('fail' if items else 'not_implemented')
        return {
            'control_id': 'A.13.1',
            'test_name': 'Network Security',
            'status': status,
            'timestamp': time.time(),
            'details': {
                'open_world_sg_rules': exposures,
                'posture_records': len(items),
                'posture_path': path,
            }
        }

    async def test_A_14_2_secure_development(self, tenant_id: str) -> Dict[str, Any]:
        """A.14.2: Secure development

        Signals:
        - Presence of security tooling config (bandit.yaml/ruff.toml)
        - SBOM/vulnerability mapping module present
        """
        cwd = os.getcwd()
        bandit = os.path.exists(os.path.join(cwd, 'bandit.yaml'))
        ruff = os.path.exists(os.path.join(cwd, 'ruff.toml'))
        sbom_module = os.path.exists(os.path.join(cwd, 'src', 'modules', 'sbom_vuln_mapper.py'))
        status = 'pass' if (bandit or ruff) and sbom_module else 'fail'
        return {
            'control_id': 'A.14.2',
            'test_name': 'Secure Development',
            'status': status,
            'timestamp': time.time(),
            'details': {
                'bandit_config_present': bandit,
                'ruff_config_present': ruff,
                'sbom_mapper_present': sbom_module,
            }
        }

    async def test_A_16_1_incident_response(self, tenant_id: str) -> Dict[str, Any]:
        """A.16.1: Incident response

        Signals:
        - docs/runbooks/incident_response.md exists
        - Escalation/playbooks modules present
        """
        cwd = os.getcwd()
        ir_doc = os.path.exists(os.path.join(cwd, 'docs', 'runbooks', 'incident_response.md'))
        has_queue = os.path.exists(os.path.join(cwd, 'src', 'core', 'escalation', 'queue.py'))
        has_playbooks = os.path.exists(os.path.join(cwd, 'src', 'core', 'playbooks', 'executor.py'))
        status = 'pass' if ir_doc and (has_queue or has_playbooks) else 'fail'
        return {
            'control_id': 'A.16.1',
            'test_name': 'Incident Response',
            'status': status,
            'timestamp': time.time(),
            'details': {
                'ir_runbook_present': ir_doc,
                'escalation_engine_present': has_queue,
                'playbooks_present': has_playbooks,
            }
        }

    async def run_test(self, control_id: str, tenant_id: str) -> Dict[str, Any]:
        """Route to specific test by control ID."""
        test_map = {
            'A.9.2': self.test_A_9_2_user_access_management,
            'A.12.4': self.test_A_12_4_logging_monitoring,
            'A.13.1': self.test_A_13_1_network_security,
            'A.14.2': self.test_A_14_2_secure_development,
            'A.16.1': self.test_A_16_1_incident_response,
        }
        fn = test_map.get(control_id)
        if not fn:
            return {
                'control_id': control_id,
                'status': 'not_implemented',
                'message': f'No automated test for {control_id}',
            }
        return await fn(tenant_id)

