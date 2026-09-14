from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any, Dict, List, Tuple

from .metrics import PipelineMetrics
from .utils import cfg_get


class AllowlistManager:
    def __init__(self, config: Any, metrics: PipelineMetrics | None = None) -> None:
        pipeline_cfg = cfg_get(config, 'pipeline', {})
        allow_cfg = cfg_get(pipeline_cfg, 'allowlists', {})
        self.metrics = metrics
        self.enabled = os.getenv('PIPELINE_ALLOWLIST_ENABLED', '1').lower() not in {'0', 'false', 'no'}

        default_vendors = {
            'microsoft corporation',
            'microsoft',
            'windows defender',
            'windows security'
        }
        default_binaries = {
            'mpam-d.exe',
            'mpam-fe.exe',
            'mpam-fe_bd.exe',
            'snippingtool.exe'
        }
        env_vendors = self._split_env_list(os.getenv('PIPELINE_VENDOR_ALLOWLIST', ''))
        env_binaries = self._split_env_list(os.getenv('PIPELINE_BINARY_ALLOWLIST', ''))

        self.vendor_allowlist = set(default_vendors)
        self.vendor_allowlist.update(v.lower() for v in env_vendors)
        for value in cfg_get(allow_cfg, 'vendors', []):
            try:
                self.vendor_allowlist.add(str(value).lower())
            except Exception:
                continue

        self.binary_allowlist = set(default_binaries)
        self.binary_allowlist.update(b.lower() for b in env_binaries)
        for value in cfg_get(allow_cfg, 'binaries', []):
            try:
                self.binary_allowlist.add(str(value).lower())
            except Exception:
                continue

        self.factor_suppress = set()
        for value in cfg_get(allow_cfg, 'suppress_factors', ['endpoint:signed_mismatch']):
            try:
                self.factor_suppress.add(str(value))
            except Exception:
                continue

        cap_value = cfg_get(allow_cfg, 'vendor_max_confidence', 0.35)
        try:
            self.confidence_cap = float(cap_value)
        except Exception:
            self.confidence_cap = 0.35

    @staticmethod
    def _split_env_list(raw: str) -> list[str]:
        return [item.strip() for item in raw.split(',') if item.strip()]

    def apply(self, event: dict[str, Any], factors: list[str], confidence: float) -> tuple[float, list[str]]:
        if not self.enabled or (not self.vendor_allowlist and not self.binary_allowlist):
            return confidence, []

        process = event.get('process') if isinstance(event.get('process'), dict) else {}
        candidate_fields: list[Any] = [
            event.get('vendor'),
            event.get('publisher'),
            event.get('company'),
            event.get('signature_subject'),
            event.get('signature_issuer'),
            event.get('signed_vendor'),
        ]
        if isinstance(process, dict):
            candidate_fields.extend([
                process.get('publisher'),
                process.get('company'),
                process.get('vendor'),
            ])

        vendor_matches = self._match_any(candidate_fields, self.vendor_allowlist)

        name_candidates = [
            (process.get('name') if isinstance(process, dict) else None) or event.get('process_name'),
            event.get('file_name'),
            event.get('image'),
            event.get('path'),
            (process.get('path') if isinstance(process, dict) else None),
        ]
        binary_matches = self._match_any(name_candidates, self.binary_allowlist)

        if not vendor_matches and not binary_matches:
            return confidence, []

        original_len = len(factors)
        if self.factor_suppress:
            factors[:] = [f for f in factors if f not in self.factor_suppress]

        new_factors: list[str] = []
        for vendor in sorted(vendor_matches):
            new_factors.append(f"allowlist_vendor:{vendor.replace(' ', '_')}")
            if self.metrics:
                self.metrics.record_allowlist_hit('vendor')
        for binary in sorted(binary_matches):
            new_factors.append(f"allowlist_binary:{binary.replace(' ', '_')}")
            if self.metrics:
                self.metrics.record_allowlist_hit('binary')

        if self.metrics and len(factors) < original_len:
            self.metrics.record_allowlist_hit('factor_suppression')

        adjusted_confidence = min(confidence, self.confidence_cap)
        return adjusted_confidence, new_factors

    @staticmethod
    def _match_any(values: Iterable[Any], allowlist: Iterable[str]) -> list[str]:
        hits: list[str] = []
        normalized_allow = [item for item in allowlist if item]
        for value in values:
            if not value:
                continue
            lowered = str(value).lower()
            for entry in normalized_allow:
                if entry in lowered:
                    hits.append(entry)
        return hits
