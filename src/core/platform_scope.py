from __future__ import annotations

import os
from typing import Any, Dict


AZURE_CLOUD_FUNNEL = "azure_cloud_funnel"

_AZURE_DISABLED_FEATURES = {
    "aws",
    "api",
    "ai",
    "ja4",
    "supply_chain",
    "autonomous_response",
    "scanners",
    "sandbox",
}


def prod_scope() -> str:
    return (os.getenv("PROD_SCOPE") or "").strip().lower()


def is_prod_scope(scope: str) -> bool:
    return prod_scope() == scope.strip().lower()


def is_azure_cloud_funnel() -> bool:
    return is_prod_scope(AZURE_CLOUD_FUNNEL)


def scope_allows_provider(provider: str) -> bool:
    provider = (provider or "").strip().lower()
    if is_azure_cloud_funnel():
        return provider == "azure"
    return True


def scope_feature_enabled(feature: str) -> bool:
    feature = (feature or "").strip().lower()
    if is_azure_cloud_funnel():
        return feature not in _AZURE_DISABLED_FEATURES
    return True


def platform_profile() -> Dict[str, Any]:
    scope = prod_scope() or "default"
    disabled = sorted(list(_AZURE_DISABLED_FEATURES)) if is_azure_cloud_funnel() else []
    return {
        "prod_scope": scope,
        "launch_mode": "azure_only" if is_azure_cloud_funnel() else "default",
        "allowed_providers": ["azure"] if is_azure_cloud_funnel() else ["azure", "aws"],
        "disabled_features": disabled,
        "tier2_enabled": os.getenv("TIER2_ENABLED", "1").lower() in {"1", "true", "yes"},
        "tier2_placeholder_allowed": os.getenv("TIER2_ALLOW_PLACEHOLDER", "0").lower() in {"1", "true", "yes"},
    }
