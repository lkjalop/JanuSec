"""Secrets manager abstraction for CrowdStrike credentials.

Supports multiple backends via environment selection. For demo/local use the
ENV backend which reads from env vars. Optional AWS Secrets Manager and Vault
backends are supported if packages are installed and relevant env vars set.
"""
from __future__ import annotations
import os
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class SecretsManager:
    def __init__(self, backend: Optional[str] = None):
        self.backend = backend or os.getenv('CS_SECRETS_BACKEND', 'env')

    def get_crowdstrike_credentials(self) -> Dict[str, Optional[str]]:
        if self.backend == 'aws':
            return self._get_from_aws()
        if self.backend == 'vault':
            return self._get_from_vault()
        # default: env
        return {'client_id': os.getenv('CROWDSTRIKE_CLIENT_ID'), 'client_secret': os.getenv('CROWDSTRIKE_CLIENT_SECRET')}

    def _get_from_aws(self) -> Dict[str, Optional[str]]:
        try:
            import boto3
            name = os.getenv('CROWDSTRIKE_AWS_SECRET_NAME')
            if not name:
                logger.debug('AWS secret name not configured')
                return {'client_id': None, 'client_secret': None}
            client = boto3.client('secretsmanager')
            resp = client.get_secret_value(SecretId=name)
            import json
            data = json.loads(resp.get('SecretString','{}'))
            return {'client_id': data.get('client_id'), 'client_secret': data.get('client_secret')}
        except Exception:
            logger.exception('Failed to load CS creds from AWS')
            return {'client_id': None, 'client_secret': None}

    def _get_from_vault(self) -> Dict[str, Optional[str]]:
        try:
            import hvac
            url = os.getenv('VAULT_ADDR')
            token = os.getenv('VAULT_TOKEN')
            path = os.getenv('CROWDSTRIKE_VAULT_PATH')
            if not url or not token or not path:
                logger.debug('Vault config missing')
                return {'client_id': None, 'client_secret': None}
            cli = hvac.Client(url=url, token=token)
            resp = cli.secrets.kv.v2.read_secret_version(path=path)
            data = resp.get('data', {}).get('data', {})
            return {'client_id': data.get('client_id'), 'client_secret': data.get('client_secret')}
        except Exception:
            logger.exception('Failed to load CS creds from Vault')
            return {'client_id': None, 'client_secret': None}


_DEFAULT = SecretsManager()

def get_crowdstrike_credentials() -> Dict[str, Optional[str]]:
    return _DEFAULT.get_crowdstrike_credentials()

__all__ = ['get_crowdstrike_credentials', 'SecretsManager']
