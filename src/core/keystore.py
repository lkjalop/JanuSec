import os
import json
import base64
from typing import Optional, Dict, Any

KEYSTORE_PATH = os.environ.get('APPROVAL_KEYSTORE_PATH', 'data/approval_keystore.json')


def _ensure_dir():
    os.makedirs(os.path.dirname(KEYSTORE_PATH) or 'data', exist_ok=True)


def load_keystore() -> Dict[str, Any]:
    _ensure_dir()
    if not os.path.exists(KEYSTORE_PATH):
        return {}
    try:
        with open(KEYSTORE_PATH, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_keystore(m: Dict[str, Any]):
    _ensure_dir()
    with open(KEYSTORE_PATH, 'w', encoding='utf-8') as fh:
        json.dump(m, fh, indent=2)


def get_key_metadata(key_id: str) -> Optional[Dict[str, Any]]:
    """Return keystore entry metadata for a key_id.

    Entries should be metadata-only and reference wrapped keys where possible.
    Example:
      {"wrap": "kms", "kms_ciphertext": "<base64>"}
      {"wrap": "azure", "vault_secret_name": "name", "vault_url": "https://..."}
      {"wrap": "plain", "plain": "..."}  # not recommended
    """
    m = load_keystore()
    return m.get(key_id)


def add_key_metadata(key_id: str, entry: Dict[str, Any]):
    m = load_keystore()
    m[key_id] = entry
    save_keystore(m)


def resolve_key_plaintext(key_id: str) -> Optional[str]:
    """Resolve key material to plaintext using available loaders.

    Resolution order:
      1. keystore entry with wrap=='plain' -> return plaintext
      2. env override via APPROVAL_AUDIT_HMAC_KEY + APPROVAL_AUDIT_HMAC_KEY_ID
      3. KMS ciphertext entry -> decrypt via boto3 KMS
      4. Azure Key Vault reference -> fetch via azure-keyvault-secrets
    """
    entry = get_key_metadata(key_id)
    # env map shorthand: allow a mapping JSON in APPROVAL_KEYSTORE_MAP for quick overrides
    if not entry:
        env_map = os.getenv('APPROVAL_KEYSTORE_MAP')
        if env_map:
            try:
                mm = json.loads(env_map)
                e = mm.get(key_id)
                if isinstance(e, str):
                    return e
                if isinstance(e, dict) and 'plain' in e:
                    return e.get('plain')
            except Exception:
                pass
        return None

    wrap = entry.get('wrap')
    if wrap == 'plain' and 'plain' in entry:
        return entry.get('plain')

    # explicit env override
    env_key = os.getenv('APPROVAL_AUDIT_HMAC_KEY')
    env_key_id = os.getenv('APPROVAL_AUDIT_HMAC_KEY_ID')
    if env_key and env_key_id == key_id:
        return env_key

    # AWS KMS decrypt
    if wrap == 'kms' or 'kms_ciphertext' in entry:
        ctext = entry.get('kms_ciphertext')
        if not ctext:
            ctext = os.getenv('APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT')
        if ctext:
            try:
                import boto3
                kms = boto3.client('kms')
                ct = base64.b64decode(ctext)
                resp = kms.decrypt(CiphertextBlob=ct)
                pt = resp.get('Plaintext')
                if isinstance(pt, (bytes, bytearray)):
                    return pt.decode('utf-8')
                return pt
            except Exception:
                return None

    # Azure Key Vault
    if wrap == 'azure' or 'vault_secret_name' in entry:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
            vault_url = entry.get('vault_url') or os.getenv('AZURE_KEYVAULT_URL')
            secret_name = entry.get('vault_secret_name') or os.getenv('APPROVAL_AUDIT_HMAC_AZURE_SECRET_NAME')
            if vault_url and secret_name:
                cred = DefaultAzureCredential()
                client = SecretClient(vault_url=vault_url, credential=cred)
                secret = client.get_secret(secret_name)
                return secret.value
        except Exception:
            return None

    return None
