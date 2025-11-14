"""Coverage report service: compute technique coverage, stride distribution, control coverage.
Consumes `threat_dimensions.json` and report artifacts (list of artifact dicts).
"""
from __future__ import annotations
import json, os
from typing import List, Dict, Any

ROOT = os.path.dirname(__file__)
THREAT_PATH = os.path.join(ROOT, 'threat_dimensions.json')

class CoverageService:
    def __init__(self, threat_path: str | None = None):
        self.threat_path = threat_path or THREAT_PATH
        self._load()

    def _load(self):
        try:
            with open(self.threat_path, 'r', encoding='utf-8') as fh:
                self.dim = json.load(fh)
        except Exception:
            self.dim = {}

    def refresh(self):
        self._load()

    def artifact_dimensions(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        # Map artifact factors to aggregated dimensions
        factors = artifact.get('factors', [])
        mitre = set()
        stride = set()
        controls = set()
        for f in factors:
            m = self.dim.get(f, {})
            mitre.update(m.get('mitre', []))
            stride.update(m.get('stride', []))
            controls.update(m.get('controls', []))
        return {'mitre': sorted(mitre), 'stride': sorted(stride), 'controls': sorted(controls)}

    def coverage_report(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        all_mitre = set()
        stride_counts: Dict[str, int] = {}
        control_counts: Dict[str, int] = {}
        for a in artifacts:
            dims = self.artifact_dimensions(a)
            for t in dims['mitre']:
                all_mitre.add(t)
            for s in dims['stride']:
                stride_counts[s] = stride_counts.get(s, 0) + 1
            for c in dims['controls']:
                control_counts[c] = control_counts.get(c, 0) + 1
        total_artifacts = len(artifacts)
        stride_distribution = {k: v/total_artifacts for k, v in stride_counts.items()} if total_artifacts else {}
        control_coverage = {k: v/total_artifacts for k, v in control_counts.items()} if total_artifacts else {}
        return {
            'techniques_covered': sorted(all_mitre),
            'techniques_count': len(all_mitre),
            'stride_distribution': stride_distribution,
            'control_coverage': control_coverage,
            'artifact_count': total_artifacts
        }

# convenience function
_service = CoverageService()
get_coverage_report = _service.coverage_report
refresh_coverage = _service.refresh
