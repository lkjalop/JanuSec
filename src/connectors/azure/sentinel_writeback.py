"""
Sentinel Write-Back (P1-A)
Updates Microsoft Sentinel incidents with Janusec pipeline verdicts via the
Azure Sentinel REST API.  Also adds a comment with the persona-summary text.

This enables bi-directional integration: Janusec enriches Sentinel incidents
in-place so analysts working in Sentinel see the correlation outcomes without
having to switch consoles.

Env vars:
    SENTINEL_WORKSPACE_ID       — Sentinel workspace GUID (required)
    SENTINEL_RESOURCE_GROUP     — Azure resource group name (required)
    SENTINEL_SUBSCRIPTION_ID    — Azure subscription GUID (required)
    SENTINEL_TENANT_ID          — Azure AD tenant for MSI/SPN auth (required)
    SENTINEL_CLIENT_ID          — Service principal client ID (or use MSI)
    SENTINEL_CLIENT_SECRET      — Service principal secret (or use MSI)
    SENTINEL_API_VERSION        — API version (default 2024-01-01-preview)
    SENTINEL_WRITEBACK_ENABLED  — Set 0 to disable (default 1)
    SENTINEL_BASE_URL           — override for testing
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

_ENABLED = os.getenv('SENTINEL_WRITEBACK_ENABLED', '1') not in ('0', 'false', 'no')
_WORKSPACE_ID = os.getenv('SENTINEL_WORKSPACE_ID', '')
_RESOURCE_GROUP = os.getenv('SENTINEL_RESOURCE_GROUP', '')
_SUBSCRIPTION_ID = os.getenv('SENTINEL_SUBSCRIPTION_ID', '')
_TENANT_ID = os.getenv('SENTINEL_TENANT_ID', '')
_CLIENT_ID = os.getenv('SENTINEL_CLIENT_ID', '')
_CLIENT_SECRET = os.getenv('SENTINEL_CLIENT_SECRET', '')
_API_VERSION = os.getenv('SENTINEL_API_VERSION', '2024-01-01-preview')
_BASE_URL = os.getenv('SENTINEL_BASE_URL', 'https://management.azure.com')

# Verdict → Sentinel incident classification mapping
_VERDICT_TO_CLASSIFICATION: dict[str, str] = {
    'MALICIOUS': 'TruePositive',
    'HIGH': 'TruePositive',
    'CRITICAL': 'TruePositive',
    'SUSPICIOUS': 'BenignPositive',
    'BENIGN': 'FalsePositive',
    'CLEAN': 'FalsePositive',
    'FALSE_POSITIVE': 'FalsePositive',
    'FP': 'FalsePositive',
    'UNDETERMINED': 'Undetermined',
}

_VERDICT_TO_CLASSIFICATION_REASON: dict[str, str] = {
    'MALICIOUS': 'ConfirmedActivity',
    'HIGH': 'ConfirmedActivity',
    'CRITICAL': 'ConfirmedActivity',
    'SUSPICIOUS': 'SuspiciousActivity',
    'BENIGN': 'InaccurateData',
    'CLEAN': 'InaccurateData',
    'FALSE_POSITIVE': 'InaccurateData',
    'FP': 'InaccurateData',
    'UNDETERMINED': 'Undetermined',
}


def _build_base_url(workspace_id: str = _WORKSPACE_ID) -> str:
    sub = _SUBSCRIPTION_ID
    rg = _RESOURCE_GROUP
    ws = workspace_id or _WORKSPACE_ID
    return (
        f'{_BASE_URL}/subscriptions/{sub}/resourceGroups/{rg}'
        f'/providers/Microsoft.OperationalInsights/workspaces/{ws}'
        f'/providers/Microsoft.SecurityInsights'
    )


def _get_token() -> str:
    """Obtain an Azure bearer token via MSAL (SPN) or MSI fallback."""
    try:
        import msal  # type: ignore
        authority = f'https://login.microsoftonline.com/{_TENANT_ID}'
        app = msal.ConfidentialClientApplication(
            _CLIENT_ID,
            authority=authority,
            client_credential=_CLIENT_SECRET,
        )
        result = app.acquire_token_for_client(
            scopes=['https://management.azure.com/.default']
        )
        return result.get('access_token', '')
    except ImportError:
        pass
    # MSI fallback (works in Azure VMs / container apps)
    try:
        import urllib.request as _req
        import json as _json
        url = (
            'http://169.254.169.254/metadata/identity/oauth2/token'
            '?api-version=2018-02-01&resource=https://management.azure.com/'
        )
        request = _req.Request(url, headers={'Metadata': 'true'})
        with _req.urlopen(request, timeout=5) as resp:  # noqa: S310
            data = _json.loads(resp.read())
            return data.get('access_token', '')
    except Exception as exc:
        logger.warning('sentinel_writeback: MSI token fetch failed: %s', exc)
        return ''


class SentinelWriteback:
    """Updates Sentinel incidents with Janusec pipeline outcomes."""

    def __init__(
        self,
        workspace_id: str = _WORKSPACE_ID,
        enabled: bool = _ENABLED,
    ) -> None:
        self.workspace_id = workspace_id
        self.enabled = enabled
        self._token: str = ''
        self._token_expiry: float = 0.0

    def _ensure_token(self) -> str:
        if time.time() < self._token_expiry - 60:
            return self._token
        token = _get_token()
        if token:
            self._token = token
            self._token_expiry = time.time() + 3500  # tokens valid ~1h
        return self._token

    def _headers(self) -> dict[str, str]:
        return {
            'Authorization': f'Bearer {self._ensure_token()}',
            'Content-Type': 'application/json',
        }

    def _incidents_url(self, incident_id: str) -> str:
        return (
            f'{_build_base_url(self.workspace_id)}'
            f'/incidents/{incident_id}?api-version={_API_VERSION}'
        )

    def _comments_url(self, incident_id: str, comment_id: str) -> str:
        return (
            f'{_build_base_url(self.workspace_id)}'
            f'/incidents/{incident_id}/comments/{comment_id}?api-version={_API_VERSION}'
        )

    def update_incident(
        self,
        incident_id: str,
        verdict: str,
        confidence: float = 0.0,
        mitre_tags: list[str] | None = None,
        persona_summary: str = '',
    ) -> dict[str, Any]:
        """PATCH a Sentinel incident with verdict-derived classification.

        Args:
            incident_id:     Sentinel incident GUID or name.
            verdict:         Janusec verdict string (e.g. 'MALICIOUS').
            confidence:      Confidence score 0.0–1.0.
            mitre_tags:      List of MITRE ATT&CK technique IDs.
            persona_summary: Short persona narrative to embed in labels.

        Returns:
            API response dict, or {'error': ...} on failure.
        """
        if not self.enabled:
            return {'skipped': 'writeback_disabled'}
        if not self.workspace_id or not _SUBSCRIPTION_ID:
            return {'skipped': 'sentinel_not_configured'}

        verdict_upper = verdict.upper()
        classification = _VERDICT_TO_CLASSIFICATION.get(verdict_upper, 'Undetermined')
        classification_reason = _VERDICT_TO_CLASSIFICATION_REASON.get(verdict_upper, 'Undetermined')
        status = 'Active' if classification in ('TruePositive', 'BenignPositive') else 'Closed'

        labels = [{'labelName': 'janusec', 'labelType': 'User'}]
        if mitre_tags:
            for tag in mitre_tags[:5]:  # Sentinel label limit
                labels.append({'labelName': tag, 'labelType': 'User'})

        body: dict[str, Any] = {
            'properties': {
                'status': status,
                'classification': classification,
                'classificationReason': classification_reason,
                'classificationComment': (
                    f'Janusec verdict={verdict_upper} confidence={confidence:.2f}'
                ),
                'labels': labels,
            }
        }

        try:
            import json
            import urllib.request as _req

            url = self._incidents_url(incident_id)
            data = json.dumps(body).encode('utf-8')
            request = _req.Request(
                url,
                data=data,
                headers=self._headers(),
                method='PATCH',
            )
            with _req.urlopen(request, timeout=15) as resp:  # noqa: S310
                result = json.loads(resp.read())
                logger.info(
                    'sentinel_writeback: updated incident %s classification=%s',
                    incident_id, classification,
                )
                return result
        except Exception as exc:
            logger.error(
                'sentinel_writeback: update_incident failed for %s: %s', incident_id, exc
            )
            return {'error': str(exc)}

    def add_comment(
        self,
        incident_id: str,
        text: str,
        comment_id: str | None = None,
    ) -> dict[str, Any]:
        """PUT a comment on a Sentinel incident.

        Args:
            incident_id: Sentinel incident GUID or name.
            text:        Comment body (Markdown supported by Sentinel).
            comment_id:  Optional stable comment GUID; auto-generated if omitted.

        Returns:
            API response dict, or {'error': ...} on failure.
        """
        if not self.enabled:
            return {'skipped': 'writeback_disabled'}
        if not self.workspace_id or not _SUBSCRIPTION_ID:
            return {'skipped': 'sentinel_not_configured'}

        import json
        import uuid
        import urllib.request as _req

        if not comment_id:
            comment_id = str(uuid.uuid4())

        body: dict[str, Any] = {'properties': {'message': text[:30000]}}  # Sentinel limit
        try:
            url = self._comments_url(incident_id, comment_id)
            data = json.dumps(body).encode('utf-8')
            request = _req.Request(
                url,
                data=data,
                headers=self._headers(),
                method='PUT',
            )
            with _req.urlopen(request, timeout=15) as resp:  # noqa: S310
                result = json.loads(resp.read())
                logger.info('sentinel_writeback: added comment to incident %s', incident_id)
                return result
        except Exception as exc:
            logger.error(
                'sentinel_writeback: add_comment failed for %s: %s', incident_id, exc
            )
            return {'error': str(exc)}

    def push_pipeline_result(
        self,
        incident_id: str,
        verdict: str,
        confidence: float = 0.0,
        mitre_tags: list[str] | None = None,
        persona_summary: str = '',
    ) -> dict[str, Any]:
        """Convenience: update classification then attach the persona summary as a comment."""
        update_result = self.update_incident(
            incident_id, verdict, confidence, mitre_tags, persona_summary
        )
        comment_result: dict[str, Any] = {}
        if persona_summary:
            comment_text = (
                f'## Janusec Pipeline Summary\n\n'
                f'**Verdict:** {verdict}  \n'
                f'**Confidence:** {confidence:.0%}  \n\n'
                f'{persona_summary}'
            )
            comment_result = self.add_comment(incident_id, comment_text)

        return {
            'update': update_result,
            'comment': comment_result,
        }


# Module-level singleton
_writeback = SentinelWriteback()


def get_writeback() -> SentinelWriteback:
    """Return the module-level singleton."""
    return _writeback
