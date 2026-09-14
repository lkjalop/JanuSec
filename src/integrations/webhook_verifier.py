import json
import time
import logging
from pathlib import Path
from typing import Optional

try:
    import jwt
    from jwt import PyJWKClient
except Exception:
    jwt = None
    PyJWKClient = None

if jwt is not None:
    try:
        if hasattr(jwt, 'PyJWK') and not hasattr(jwt.PyJWK, 'from_pem'):
            from cryptography.hazmat.primitives import serialization

            @classmethod
            def _from_pem(cls, pem_bytes: bytes):
                key = serialization.load_pem_public_key(pem_bytes)
                jwk_json = jwt.algorithms.RSAAlgorithm.to_jwk(key)
                return cls.from_dict(json.loads(jwk_json))

            jwt.PyJWK.from_pem = _from_pem  # type: ignore[attr-defined]
        if hasattr(jwt, 'PyJWK') and not hasattr(jwt.PyJWK, 'to_dict'):
            def _to_dict(self):
                data = getattr(self, '_jwk_data', None)
                if isinstance(data, dict):
                    return dict(data)
                key = getattr(self, 'key', None)
                if key is None:
                    raise AttributeError('PyJWK has no serializable key')
                jwk_json = jwt.algorithms.RSAAlgorithm.to_jwk(key)
                return json.loads(jwk_json)

            jwt.PyJWK.to_dict = _to_dict  # type: ignore[attr-defined]
    except Exception:
        pass

logger = logging.getLogger(__name__)


def verify_jwt_with_jwks(token: str, jwks_url: str, audience: Optional[str] = None) -> dict:
    """Verify an incoming JWT using a JWKS URL (RS256 recommended).

    Returns the decoded payload on success, raises Exception on failure.
    """
    if jwt is None or PyJWKClient is None:
        raise RuntimeError('pyjwt not available')
    options = {'verify_aud': bool(audience)}
    signing_key = None
    if str(jwks_url or '').startswith('file:///'):
        try:
            jwks_path = Path(str(jwks_url)[8:])
            jwks_doc = json.loads(jwks_path.read_text(encoding='utf-8'))
            keys = jwks_doc.get('keys') or []
            if not keys:
                raise RuntimeError('The JWKS endpoint did not contain any signing keys')
            header = jwt.get_unverified_header(token) or {}
            desired_kid = header.get('kid')
            selected = None
            if desired_kid:
                for key_doc in keys:
                    if isinstance(key_doc, dict) and key_doc.get('kid') == desired_kid:
                        selected = key_doc
                        break
            if selected is None:
                first = keys[0]
                if not isinstance(first, dict):
                    raise RuntimeError('invalid_jwk_document')
                selected = first
            key_obj = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(selected))

            class _SigningKey:
                def __init__(self, key, algorithm):
                    self.key = key
                    self.algorithm = algorithm

            signing_key = _SigningKey(key_obj, str(header.get('alg') or selected.get('alg') or 'RS256'))
        except Exception as e:
            logger.debug('file JWKS verification bootstrap failed: %s', e)
            raise
    else:
        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
    # allow missing audience if not provided
    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=[signing_key.algorithm],
            audience=audience if audience else None,
            options=options,
        )
        return payload
    except Exception as e:
        logger.debug('JWT verification failed: %s', e)
        raise
