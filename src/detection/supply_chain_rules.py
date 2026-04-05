"""Supply chain detection rules.

Implements high-signal developer-targeted phishing detection and multi-stage
attack chain correlation spanning Email → Identity → DevOps/Cloud → Endpoint.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from src.schemas.email import NormalizedEmailEvent


class RuleMatch:
    def __init__(
        self,
        rule_id: str,
        severity: str,
        confidence: float,
        description: str,
        evidence: List[str],
        recommended_actions: List[str],
        decision_gate: Optional[Dict[str, Any]] = None,
        supply_chain_context: Optional[Dict[str, Any]] = None,
        attack_chain: Optional[Dict[str, Any]] = None,
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.confidence = confidence
        self.description = description
        self.evidence = evidence
        self.recommended_actions = recommended_actions
        self.decision_gate = decision_gate
        self.supply_chain_context = supply_chain_context
        self.attack_chain = attack_chain


class DeveloperTargetedPhishing:
    """Detect phishing that targets developers and supply-chain pathways."""
    rule_id = "EMAIL-SC-001"

    # Content indicators
    DEVELOPER_KEYWORDS = [
        # Package managers
        "npm", "pypi", "pip", "yarn", "nuget", "rubygems", "cargo", "maven",
        "package", "dependency", "module", "library",
        # Code platforms
        "github", "gitlab", "bitbucket", "azure devops", "codecommit",
        "repository", "repo", "commit", "pull request", "merge",
        # CI/CD
        "jenkins", "travis", "circleci", "github actions", "gitlab ci",
        "pipeline", "build", "deploy", "ci/cd", "workflow",
        # Credentials / tokens / OAuth
        "api key", "access token", "secret", "credential", "ssh key",
        "personal access token", "pat", "deploy key",
        "oauth", "authorize", "permission", "grant access", "connect app",
    ]

    # High-risk link destinations
    SUPPLY_CHAIN_DOMAINS = {
        "npmjs.com", "npmjs.org", "registry.npmjs.org",
        "pypi.org", "pypi.python.org", "files.pythonhosted.org",
        "github.com", "gitlab.com", "bitbucket.org",
        "rubygems.org", "nuget.org", "crates.io",
    }

    # Role heuristics
    DEVELOPER_ROLES = {
        "dev", "developer", "engineer", "swe", "sde",
        "devops", "sre", "platform", "infrastructure",
        "security", "secops", "appsec", "devsecops",
        "backend", "frontend", "fullstack", "data", "ml", "ai",
    }

    # Lookalike patterns (best-effort)
    LOOKALIKE_PATTERNS = [
        "g1thub", "githuub", "git-hub", "git--hub",
        "g1tlab", "git-lab",
        "npm-js", "nprnjs",
    ]

    def _is_developer_target(self, event: NormalizedEmailEvent) -> bool:
        recipient = (event.recipient or "").lower()
        if any(r in recipient for r in self.DEVELOPER_ROLES):
            return True
        if event.targets_developer:
            return True
        roles = [str(x).lower() for x in (event.affected_user_roles or [])]
        return any(r in " ".join(roles) for r in self.DEVELOPER_ROLES)

    def _mentions_supply_chain(self, content: str) -> List[str]:
        return [kw for kw in self.DEVELOPER_KEYWORDS if kw in content]

    def _links_to_supply_chain(self, event: NormalizedEmailEvent) -> List[str]:
        hits: List[str] = []
        for u in event.urls or []:
            url = (u.get("url") or "").lower()
            dom = (u.get("domain") or "").lower()
            for d in self.SUPPLY_CHAIN_DOMAINS:
                if d in url or d in dom:
                    hits.append(d)
        return list(dict.fromkeys(hits))

    def _sender_lookalike(self, sender_domain: Optional[str]) -> bool:
        sd = (sender_domain or "").lower()
        if sd in {"github.com", "gitlab.com", "npmjs.com"}:
            return False
        return any(p in sd for p in self.LOOKALIKE_PATTERNS)

    def evaluate(self, event: NormalizedEmailEvent) -> Optional[RuleMatch]:
        content = ((event.subject or "") + " " + (event.body_preview or "")).lower()
        is_dev = self._is_developer_target(event)
        keywords = self._mentions_supply_chain(content)
        domains = self._links_to_supply_chain(event)
        oauth = bool(event.oauth_consent_attempted)
        auth_fail = (str(event.spf_result or '').lower() == 'fail') or (str(event.dmarc_result or '').lower() == 'fail')
        lookalike = self._sender_lookalike(event.sender_domain)

        if not (is_dev and (keywords or domains or oauth)):
            return None

        signals = []
        if keywords:
            signals.append(f"keywords={', '.join(keywords[:5])}")
        if domains:
            signals.append(f"domains={', '.join(domains[:5])}")
        if oauth:
            signals.append("oauth_consent_attempted")
        if auth_fail:
            signals.append(f"auth_fail spf={event.spf_result} dmarc={event.dmarc_result}")
        if lookalike:
            signals.append(f"lookalike_sender_domain={event.sender_domain}")

        # Confidence and severity
        base_conf = 0.55 + 0.06 * len(signals)
        if oauth:
            base_conf += 0.12
        conf = min(base_conf, 0.97)
        severity = "HIGH"
        if oauth or (lookalike and auth_fail):
            severity = "CRITICAL"

        recommended = [
            "Quarantine message immediately",
            "Notify user: DO NOT click or authorize",
            "Revoke OAuth tokens (if any)",
            "Audit repository access for user",
            "Scan developer endpoints for malware",
        ]
        decision_gate = {
            "question": f"Block sender domain {(event.sender_domain or '').lower()} and alert developer?",
            "urgency": "immediate",
            "auto_action_timeout_minutes": 10,
        }
        sc_context = {
            "risk_type": "credential_theft_for_supply_chain",
            "potential_impact": "package_poisoning",
            "urgency": "prevent_before_credential_use",
            "risk_score": float(event.calculate_supply_chain_risk() or 0.0),
        }

        evidence = signals + [
            f"recipient={event.recipient}",
            f"sender={event.sender}",
            f"subject={event.subject}",
        ]

        return RuleMatch(
            self.rule_id,
            severity,
            conf,
            "Developer-targeted phishing (supply chain risk)",
            evidence,
            recommended,
            decision_gate=decision_gate,
            supply_chain_context=sc_context,
        )


class SupplyChainAttackChain:
    """Correlate email with downstream identity/devops/endpoint activity."""
    rule_id = "EMAIL-SC-002"

    @staticmethod
    def _in_window(start: datetime, event_time: Any, hours: int) -> bool:
        if not event_time:
            return False
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace("Z", ""))
            except Exception:
                return False
        return start <= event_time <= (start + timedelta(hours=hours))

    async def evaluate_chain(
        self,
        email_event: NormalizedEmailEvent,
        identity_events: List[Dict],
        devops_events: List[Dict],
        endpoint_events: List[Dict],
        time_window_hours: int = 24,
    ) -> Optional[RuleMatch]:
        stages: List[Dict[str, Any]] = []
        chain_start = email_event.timestamp or datetime.utcnow()

        stages.append({
            "stage": 1,
            "name": "Developer Phishing Email",
            "timestamp": chain_start,
            "evidence": f"Email to {email_event.recipient}: {email_event.subject}",
            "confidence": 0.7,
        })

        # Identity
        for ie in sorted(identity_events or [], key=lambda e: e.get("timestamp") or chain_start):
            if not self._in_window(chain_start, ie.get("timestamp"), time_window_hours):
                continue
            et = (ie.get("event_type") or "").lower()
            if et == "oauth_grant":
                scopes = ie.get("scopes", [])
                stages.append({
                    "stage": 2,
                    "name": "OAuth Token Granted",
                    "timestamp": ie.get("timestamp") or chain_start,
                    "evidence": f"App={ie.get('app_name')} Scopes={scopes}",
                    "confidence": 0.85,
                })
            elif et == "login" and (ie.get("risk_level") in {"high", "medium"}):
                stages.append({
                    "stage": 2,
                    "name": "Suspicious Login",
                    "timestamp": ie.get("timestamp") or chain_start,
                    "evidence": f"IP={ie.get('source_ip')} GEO={ie.get('geo')}",
                    "confidence": 0.75,
                })
            elif et in {"npm_login", "pypi_login"}:
                stages.append({
                    "stage": 2,
                    "name": "Package Registry Login",
                    "timestamp": ie.get("timestamp") or chain_start,
                    "evidence": f"Registry={et.replace('_login','')}",
                    "confidence": 0.9,
                })

        # DevOps/Cloud
        for de in sorted(devops_events or [], key=lambda e: e.get("timestamp") or chain_start):
            if not self._in_window(chain_start, de.get("timestamp"), time_window_hours):
                continue
            et = (de.get("event_type") or "").lower()
            if et in {"repo_clone", "repo_push"}:
                stages.append({
                    "stage": 3,
                    "name": "Repository Access",
                    "timestamp": de.get("timestamp") or chain_start,
                    "evidence": f"Repo={de.get('repo_name')} Action={et}",
                    "confidence": 0.8,
                })
            elif et in {"npm_publish", "pypi_publish"}:
                stages.append({
                    "stage": 3,
                    "name": "Package Published",
                    "timestamp": de.get("timestamp") or chain_start,
                    "evidence": f"Package={de.get('package_name')} Version={de.get('version')}",
                    "confidence": 0.95,
                })
            elif et == "pipeline_modified":
                stages.append({
                    "stage": 3,
                    "name": "CI/CD Pipeline Modified",
                    "timestamp": de.get("timestamp") or chain_start,
                    "evidence": f"Pipeline={de.get('pipeline_name')}",
                    "confidence": 0.85,
                })
            elif et == "secret_accessed":
                stages.append({
                    "stage": 3,
                    "name": "CI/CD Secret Accessed",
                    "timestamp": de.get("timestamp") or chain_start,
                    "evidence": f"Secret={de.get('secret_name')}",
                    "confidence": 0.9,
                })

        # Endpoint
        for ep in sorted(endpoint_events or [], key=lambda e: e.get("timestamp") or chain_start):
            if not self._in_window(chain_start, ep.get("timestamp"), time_window_hours):
                continue
            et = (ep.get("event_type") or "").lower()
            if et == "package_install":
                stages.append({
                    "stage": 4,
                    "name": "Malicious Package Installed",
                    "timestamp": ep.get("timestamp") or chain_start,
                    "evidence": f"Package={ep.get('package_name')} Host={ep.get('hostname')}",
                    "confidence": 0.9,
                })
            elif et == "process_create":
                p = (ep.get("process_path") or "").lower()
                if ("node_modules" in p) or ("site-packages" in p):
                    stages.append({
                        "stage": 4,
                        "name": "Code Execution from Package",
                        "timestamp": ep.get("timestamp") or chain_start,
                        "evidence": f"Process={ep.get('process_name')} Path={p}",
                        "confidence": 0.85,
                    })

        if len(stages) < 2:
            return None

        avg_conf = sum(s.get("confidence", 0.7) for s in stages) / len(stages)
        severity = "HIGH" if len(stages) < 4 else "CRITICAL"

        attack_chain = {
            "chain_type": "supply_chain",
            "stages": stages,
            "timeline": [
                {
                    "stage": s["stage"],
                    "timestamp": (
                        s["timestamp"].isoformat() if hasattr(s["timestamp"], "isoformat") else str(s["timestamp"])
                    ),
                }
                for s in stages
            ],
        }

        recommended = [
            "CRITICAL: Potential supply chain compromise",
            f"Revoke all OAuth tokens for {(email_event.recipient or '')}",
            "Audit recent package publishes",
            "Check for modified CI/CD pipelines",
            "Scan developer endpoints for malware",
            "Review repository commit history",
        ]

        decision_gate = {
            "question": "Initiate supply chain incident response?",
            "urgency": "immediate",
            "options": ["Full IR", "Targeted Investigation", "Monitor"],
        }

        return RuleMatch(
            self.rule_id,
            severity,
            min(avg_conf, 0.99),
            f"Supply chain attack chain: {len(stages)} stages detected",
            [f"Stage {s['stage']}: {s['name']} - {s['evidence']}" for s in stages],
            recommended,
            decision_gate=decision_gate,
            attack_chain=attack_chain,
        )


__all__ = ["DeveloperTargetedPhishing", "SupplyChainAttackChain", "RuleMatch"]
