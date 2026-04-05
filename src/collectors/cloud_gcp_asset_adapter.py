from __future__ import annotations
import os, time
from typing import List, Dict, Any
from .base import EventCollector

import logging
try:
    from google.cloud import asset_v1
except Exception:
    class _AssetV1Stub:
        class AssetServiceClient:  # type: ignore
            def __init__(self, *args, **kwargs):
                raise RuntimeError('google-cloud-asset client unavailable')

    asset_v1 = _AssetV1Stub()

try:
    from google.oauth2 import service_account
except Exception:
    class _ServiceAccountStub:
        class Credentials:  # type: ignore
            @staticmethod
            def from_service_account_file(*args, **kwargs):
                raise RuntimeError('google.oauth2 not available')

    service_account = _ServiceAccountStub()

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
except Exception:
    def retry(*args, **kwargs):
        def decorator(f):
            return f
        return decorator

    def stop_after_attempt(n):
        return None

    def wait_exponential(**kwargs):
        return None

    def retry_if_exception_type(exc):
        return (lambda e: True)

    try:
        from src.security.signature_helpers import preserve_signature
        try:
            preserve_signature(retry, retry)
        except Exception:
            import inspect as _inspect
            try:
                retry.__signature__ = _inspect.signature(retry)
            except Exception:
                pass
    except Exception:
        try:
            import inspect as _inspect
            retry.__signature__ = _inspect.signature(retry)
        except Exception:
            pass

import datetime


class GCPAssetCollector(EventCollector):
    source = "gcp_asset"

    def __init__(self):
        self._creds_path = os.getenv("GCP_CREDENTIALS_JSON")
        self._client = None
        if self._creds_path and os.path.exists(self._creds_path) and asset_v1 is not None and service_account is not None:
            try:
                creds = service_account.Credentials.from_service_account_file(self._creds_path)
                self._client = asset_v1.AssetServiceClient(credentials=creds)
            except Exception as e:
                logging.error(f"Failed to initialize GCP Asset client: {e}")
                self._client = None

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if not self._client:
            return []

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
               retry=retry_if_exception_type(Exception))
        def get_gcp_asset_changes():
            # Example: list assets with time window
            project_id = os.getenv('GCP_PROJECT_ID')
            if not project_id:
                logging.error("GCP_PROJECT_ID not set")
                return []
            parent = f"projects/{project_id}"
            # GCP Asset API does not provide direct change logs, but we can list assets and compare
            # For demo, just list assets
            try:
                pager = self._client.list_assets(
                    request={
                        "parent": parent,
                        "read_time": None,
                        "asset_types": [],
                        "content_type": 0,
                        "page_size": 100
                    }
                )
                for asset in pager:
                    events.append(asset._pb if hasattr(asset, '_pb') else dict(asset))
            except Exception as e:
                logging.error(f"GCPAsset list_assets error: {e}")
            return events

        try:
            return get_gcp_asset_changes()
        except Exception as e:
            logging.error(f"GCPAsset fetch_events error: {e}")
            return []


__all__ = ["GCPAssetCollector"]
