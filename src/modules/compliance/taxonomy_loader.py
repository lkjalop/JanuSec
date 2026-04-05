from __future__ import annotations

from typing import List, Dict, Any, Optional
from pathlib import Path
import json

DEFAULT_SUBSET = [
    {"control_id": "A.5.1.1", "title": "Information Security Policy", "keywords": ["policy", "information security", "isms"], "domain_code": "A.5"},
    {"control_id": "A.6.1.2", "title": "Segregation of Duties", "keywords": ["segregation", "duties", "roles", "responsibilities"], "domain_code": "A.6"},
    {"control_id": "A.8.1.1", "title": "Inventory of Assets", "keywords": ["asset", "inventory", "classification"], "domain_code": "A.8"},
    {"control_id": "A.9.2.1", "title": "User Registration", "keywords": ["user", "registration", "access", "account"], "domain_code": "A.9"},
]


class ControlTaxonomyLoader:
    def __init__(self, search_paths: Optional[List[str]] = None) -> None:
        self.search_paths = [Path(p) for p in (search_paths or ["taxonomy/data"]) if p]

    def _load_all(self) -> List[Dict[str, Any]]:
        controls: List[Dict[str, Any]] = []
        for base in self.search_paths:
            if not base.exists():
                continue
            for f in base.glob('*.json'):
                try:
                    data = json.loads(f.read_text(encoding='utf-8'))
                    if isinstance(data, list):
                        for c in data:
                            if isinstance(c, dict):
                                # Normalize common fields
                                cid = str(c.get('control_id') or '').strip()
                                title = str(c.get('title') or '').strip()
                                if not cid or not title:
                                    continue
                                fw = str(c.get('framework') or '').strip()
                                if fw:
                                    c['framework'] = fw.upper()
                                # backfill domain code if absent
                                if 'domain_code' not in c or not c.get('domain_code'):
                                    c['domain_code'] = '.'.join(cid.split('.')[:2])
                                # ensure keywords list exists
                                if not isinstance(c.get('keywords'), list):
                                    c['keywords'] = []
                                controls.append(c)
                except Exception:
                    continue
        if not controls:
            # Fallback to a tiny built-in subset when no files are present
            controls = DEFAULT_SUBSET.copy()
            for c in controls:
                c.setdefault('framework', 'ISO27001')
        # Optionally expand known frameworks to full index coverage when skeletons are present
        return self._expand_if_needed(controls)

    @staticmethod
    def _expand_if_needed(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add index-complete placeholders for frameworks known to be partial.

        - ISO27001:2022 Annex A — generate 93 control IDs across A.5..A.8
        - SOC2 CC: generate common criteria index spans CC1..CC9 (approximate sub-ids)

        Titles for proprietary standards use neutral placeholders to avoid embedding
        copyrighted text. Keywords/domains are inferred heuristically.
        """
        out = list(items)
        by_fw: Dict[str, Dict[str, Dict[str, Any]] ] = {}
        for c in out:
            fw = str(c.get('framework','')).upper() or 'UNKNOWN'
            by_fw.setdefault(fw, {})[str(c.get('control_id')).upper()] = c

        # ISO27001: ensure 93 controls (A.5.1..A.5.37, A.6.1..A.6.8, A.7.1..A.7.14, A.8.1..A.8.34)
        iso = by_fw.get('ISO27001', {})
        if len(iso) < 80:  # clearly a skeleton
            def _add_iso(sec: str, count: int):
                for i in range(1, count+1):
                    cid = f"{sec}.{i}"
                    if cid.upper() in iso:
                        continue
                    out.append({
                        'framework': 'ISO27001',
                        'control_id': cid,
                        'title': f'Control {cid} (see ISO/IEC 27001:2022 Annex A)',
                        'keywords': ['placeholder','index-only'],
                        'domain_code': sec,
                    })
                    iso[cid.upper()] = out[-1]
            _add_iso('A.5', 37)
            _add_iso('A.6', 8)
            _add_iso('A.7', 14)
            _add_iso('A.8', 34)

        # SOC2: expand CC families with typical sub-criteria ranges
        soc = by_fw.get('SOC2', {})
        if len(soc) < 20:
            spans = {
                'CC1': 5,
                'CC2': 4,
                'CC3': 4,
                'CC4': 2,
                'CC5': 3,
                'CC6': 8,
                'CC7': 4,
                'CC8': 2,
                'CC9': 2,
            }
            for fam, n in spans.items():
                for i in range(1, n+1):
                    cid = f"{fam}.{i}"
                    if cid.upper() in soc:
                        continue
                    out.append({
                        'framework': 'SOC2',
                        'control_id': cid,
                        'title': f'{fam} Sub-criterion {i} (descriptor placeholder)',
                        'keywords': ['placeholder','index-only'],
                        'domain_code': fam,
                    })
                    soc[cid.upper()] = out[-1]

        return out

    def load(self) -> List[Dict[str, Any]]:
        """Load all controls from taxonomy files (all frameworks)."""
        return self._load_all()

    def load_for(self, framework: Optional[str]) -> List[Dict[str, Any]]:
        """Load controls filtered by framework name (case-insensitive)."""
        all_controls = self._load_all()
        if not framework:
            return all_controls
        fw = str(framework).upper()
        out = [c for c in all_controls if str(c.get('framework','')).upper() == fw]
        # If nothing matched, return all as a fallback to avoid breaking flows
        return out or all_controls

    def available_frameworks(self) -> List[str]:
        """Return sorted list of frameworks discovered in taxonomy files."""
        fws = {str(c.get('framework','')).upper() for c in self._load_all() if c.get('framework')}
        if not fws:
            return ['ISO27001']
        return sorted(f for f in fws if f)

__all__ = ["ControlTaxonomyLoader"]
