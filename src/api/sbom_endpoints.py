from __future__ import annotations

from typing import Any
import time
import os
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
try:
    from integrations.vuln_enrichment import ENRICHER  # type: ignore
except Exception:
    ENRICHER = None  # type: ignore
from core.threat_modeling.factor_taxonomy import aggregate_threat_model, controls_for_factors  # type: ignore
try:
    from repositories.sbom_vuln_agg_repo import record_vulnerability as _record_vuln  # type: ignore
except Exception:  # pragma: no cover
    _record_vuln = None  # type: ignore

router = APIRouter(tags=["SBOM"])

_SBOMS: dict[str, dict[str, Any]] = {}
_VULNS: dict[str, list[dict[str, Any]]] = {}
_VEX: dict[str, list[dict[str, Any]]] = {}
_VEX_PATH = Path(os.getenv('SBOM_VEX_PATH', 'data/sbom_vex.jsonl'))
_RECENT_SBOMS: list[str] = []
_EXCEPTIONS: dict[str, list[dict[str, Any]]] = {}
_EXC_PATH = Path(os.getenv('SBOM_EXCEPTIONS_PATH', 'data/sbom_exceptions.jsonl'))

def _ensure_data_dir():
    try:
        _VEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    try:
        _EXC_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

def _persist_vex(sbom_id: str, stmts: list[dict[str, Any]]):
    _ensure_data_dir()
    try:
        with _VEX_PATH.open('a', encoding='utf-8') as f:
            rec = {'sbom_id': sbom_id, 'statements': stmts}
            f.write(json.dumps(rec) + '\n')
    except Exception:
        pass

def _persist_exc(sbom_id: str, items: list[dict[str, Any]]):
    _ensure_data_dir()
    try:
        with _EXC_PATH.open('a', encoding='utf-8') as f:
            rec = {'sbom_id': sbom_id, 'items': items}
            f.write(json.dumps(rec) + '\n')
    except Exception:
        pass

def _load_vex_from_disk():
    if not _VEX_PATH.exists():
        return
    try:
        with _VEX_PATH.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    rec = json.loads(line)
                    sid = rec.get('sbom_id')
                    arr = rec.get('statements') or []
                    if not sid or not isinstance(arr, list):
                        continue
                    _VEX.setdefault(sid, []).extend(arr)
                except Exception:
                    continue
    except Exception:
        pass

def _load_exceptions_from_disk():
    if not _EXC_PATH.exists():
        return
    try:
        with _EXC_PATH.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    rec = json.loads(line)
                    sid = rec.get('sbom_id')
                    arr = rec.get('items') or []
                    if not sid or not isinstance(arr, list):
                        continue
                    _EXCEPTIONS.setdefault(sid, []).extend(arr)
                except Exception:
                    continue
    except Exception:
        pass

def _parse_version_tuple(v: str) -> tuple[int,...]:
    parts = []
    for p in str(v).split('.'):
        try:
            parts.append(int(p))
        except Exception:
            parts.append(0)
    return tuple(parts)

def _cmp_versions(a: str, b: str) -> int:
    ta = _parse_version_tuple(a)
    tb = _parse_version_tuple(b)
    # pad
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    if ta < tb: return -1
    if ta > tb: return 1
    return 0

def _version_in_range(ver: str, expr: str | None) -> bool:
    if not expr:
        return True
    # Support comma-separated constraints like ">=1.2.0,<2.0.0" and single operators
    for chunk in str(expr).split(','):
        c = chunk.strip()
        if not c:
            continue
        op = None
        for o in ('>=','<=','>','<','==','='):
            if c.startswith(o):
                op = o
                target = c[len(o):].strip()
                break
        if op is None:
            # bare version equals
            op = '=='
            target = c
        comp = _cmp_versions(ver, target)
        ok = {
            '>': comp > 0,
            '>=': comp >= 0,
            '<': comp < 0,
            '<=': comp <= 0,
            '==': comp == 0,
            '=': comp == 0,
        }[op]
        if not ok:
            return False
    return True


@router.post('/api/v1/sbom/upload')  # type: ignore[misc]
async def sbom_upload(request: Request) -> dict[str, Any]:
    """Accept SBOM JSON (CycloneDX/SPDX-ish) and run a minimal vulnerability mapping.

    Body: { sbom_id?: string, components: [ {name, version, purl?, cpe?}, ... ] }
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='bad_json')
    sbom_id = (data.get('sbom_id') or f"sbom-{len(_SBOMS)+1}")
    comps = data.get('components') or []
    if not isinstance(comps, list) or not comps:
        raise HTTPException(status_code=400, detail='no_components')
    _SBOMS[sbom_id] = data
    # Track recent uploads (most-recent first, bounded list)
    try:
        if sbom_id in _RECENT_SBOMS:
            _RECENT_SBOMS.remove(sbom_id)  # type: ignore[attr-defined]
    except Exception:
        pass
    _RECENT_SBOMS.insert(0, sbom_id)
    if len(_RECENT_SBOMS) > 25:
        del _RECENT_SBOMS[25:]
    # Minimal mapping demo: flag obviously risky names/versions and pass-through provided CVSS/CVE fields
    vulns: list[dict[str, Any]] = []
    now = time.time()
    for c in comps:
        name = (c or {}).get('name') or ''
        ver = (c or {}).get('version') or ''
        sev = None
        if isinstance(name, str):
            ln = name.lower()
            if 'log4j' in ln:
                sev = 'critical'
            if 'openssl' in ln and str(ver).startswith(('1.0','1.1.0')):
                sev = sev or 'high'
            if 'struts' in ln:
                sev = sev or 'high'
        # Pass-through vulnerability fields if present within component
        if isinstance(c, dict) and any(k in c for k in ('cve','cvss_base_score','cvss_vector')):
            entry = {
                'component': name,
                'version': ver,
                'severity': (c.get('severity') or sev or 'high') if (c.get('cve') or c.get('cvss_base_score')) else (sev or 'medium'),
                'cve': c.get('cve'),
                'cvss_base_score': c.get('cvss_base_score'),
                'cvss_vector': c.get('cvss_vector'),
                'summary': c.get('summary') or 'Provided by SBOM',
                'observed_ts': float(c.get('observed_ts') or now),
            }
            vulns.append(entry)
            try:
                if _record_vuln is not None:
                    ck = f"{str(name).lower()}:{str(ver or 'unknown').lower()}"
                    _record_vuln('default', ck, str(entry.get('severity') or 'unknown'), ts=now, cvss_score=entry.get('cvss_base_score'))
            except Exception:
                pass
        elif sev:
            entry = {'component': name, 'version': ver, 'severity': sev, 'cve': None, 'summary': 'Heuristic match', 'observed_ts': now}
            vulns.append(entry)
            try:
                if _record_vuln is not None:
                    ck = f"{str(name).lower()}:{str(ver or 'unknown').lower()}"
                    _record_vuln('default', ck, str(sev), ts=now, cvss_score=None)
            except Exception:
                pass
    _VULNS[sbom_id] = vulns
    # Run package detectors (best-effort) and persist lightweight factors into HopGraph when available.
    extra_factors: list[dict[str, Any]] = []
    try:
        from src.core.detectors.package_integrity import analyze_npm_package, analyze_pypi_metadata  # type: ignore
    except Exception:
        analyze_npm_package = None  # type: ignore
        analyze_pypi_metadata = None  # type: ignore

    if analyze_npm_package or analyze_pypi_metadata:
        for c in comps:
            try:
                if (c or {}).get('purl') and 'npm' in str((c or {}).get('purl')) and analyze_npm_package:
                    det = analyze_npm_package(c, known_registry=None)
                elif analyze_pypi_metadata:
                    det = analyze_pypi_metadata(c)
                else:
                    det = None
                if det:
                    if isinstance(det, list):
                        extra_factors.extend(det)
                    else:
                        extra_factors.append(det)
            except Exception:
                continue

    # Try to persist detector factors into HopGraph nodes when available (best-effort).
    # Prefer the app's lifespan-managed instance, then fall back to module global.
    hg = None
    try:
        hg = getattr(request.app.state, 'hopgraph', None)
    except Exception:
        hg = None
    if hg is None:
        # Fall back to module-level singleton
        try:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
            hg = GLOBAL_HOPGRAPH
        except Exception:
            hg = None
    if hg is None:
        # As a last resort in constrained test contexts, create and attach a new instance
        try:
            from src.graph.hopgraph import HopGraph  # type: ignore
            hg = HopGraph()
        except Exception:
            hg = None

    # Ensure hg is attached consistently so other modules/tests observe the same instance
    if hg is not None:
        try:
            setattr(request.app.state, 'hopgraph', hg)
        except Exception:
            pass
        try:
            setattr(request.app, 'GLOBAL_HOPGRAPH', hg)
        except Exception:
            pass
        try:
            import src.graph.hopgraph as _hgmod  # type: ignore
            _hgmod.GLOBAL_HOPGRAPH = hg  # type: ignore[attr-defined]
        except Exception:
            try:
                import graph.hopgraph as _hgmod2  # type: ignore
                _hgmod2.GLOBAL_HOPGRAPH = hg  # type: ignore[attr-defined]
            except Exception:
                pass

    if hg is not None:
        # create package nodes
        for c in comps:
            try:
                pkg = (c or {}).get('name')
                ver = (c or {}).get('version')
                nid = f"package:{pkg}:{ver}"
                hg.add_node_attr(nid, type='package', name=pkg, version=ver)
            except Exception:
                pass
        # attach detector factors (best-effort: use string factor name when present)
        for f in extra_factors or []:
            try:
                target = f.get('target') or ''
                nid = None
                if target:
                    # Attempt to find matching component version for target
                    ver_t = next((x.get('version') for x in comps if (x or {}).get('name') == target), '')
                    nid = f"package:{target}:{ver_t}"
                else:
                    if comps:
                        pkg0 = (comps[0] or {}).get('name')
                        ver0 = (comps[0] or {}).get('version')
                        nid = f"package:{pkg0}:{ver0}"
                factor_name = f.get('factor') or f.get('name') or 'detector_factor'
                if nid and isinstance(factor_name, str):
                    hg.add_node_factor(nid, factor_name)
            except Exception:
                pass
        # build dependency graph and add edges
        try:
            from src.core.detectors.dependency_graph import build_dependency_graph  # type: ignore
            # Build combined dependency maps from components and SBOM-standard fields
            dep_map = {}
            for c in comps:
                name = (c or {}).get('name')
                deps = (c or {}).get('dependencies') or {}
                if name and isinstance(deps, dict):
                    dep_map[name] = deps
            # CycloneDX-style top-level dependencies
            top_deps = ( (_SBOMS.get(sbom_id) or {}).get('dependencies') or (data.get('dependencies') if isinstance(data, dict) else []) )
            # SPDX-style relationships
            relationships = ( (_SBOMS.get(sbom_id) or {}).get('relationships') or (data.get('relationships') if isinstance(data, dict) else []) )
            # Create edges from component dependency maps directly (spec strings become metadata)
            for root, deps in dep_map.items():
                if not isinstance(deps, dict):
                    continue
                for child, spec in deps.items():
                    try:
                        rv = next((x.get('version') for x in comps if x.get('name') == root), '')
                        cv = next((x.get('version') for x in comps if x.get('name') == child), '')
                        src_id = f"package:{root}:{rv}"
                        dst_id = f"package:{child}:{cv}"
                        hg.add_node_attr(src_id, type='package', name=root, version=rv)
                        hg.add_node_attr(dst_id, type='package', name=child, version=cv)
                        edge_meta = {}
                        try:
                            devs = (next((x.get('devDependencies') for x in comps if x.get('name') == root), {}) or {})
                            if child in devs:
                                edge_meta['scope'] = 'dev'
                        except Exception:
                            pass
                        if spec:
                            try:
                                edge_meta['spec'] = str(spec)
                            except Exception:
                                pass
                        hg.add_edge(src_id, dst_id, 'depends_on', source='enriched', attrs=edge_meta)
                    except Exception:
                        continue
            # Create edges from CycloneDX dependencies
            if isinstance(top_deps, list) and top_deps:
                g2 = build_dependency_graph(top_deps)
                for src, children in g2.items():
                    for child in children:
                        try:
                            rv = next((x.get('version') for x in comps if (x.get('purl') or x.get('name')) == src or x.get('name') == src), '')
                            cv = next((x.get('version') for x in comps if (x.get('purl') or x.get('name')) == child or x.get('name') == child), '')
                            src_id = f"package:{src}:{rv}"
                            dst_id = f"package:{child}:{cv}"
                            hg.add_node_attr(src_id, type='package', name=src, version=rv)
                            hg.add_node_attr(dst_id, type='package', name=child, version=cv)
                            hg.add_edge(src_id, dst_id, 'depends_on', source='cyclonedx')
                        except Exception:
                            continue
            # Create edges from SPDX relationships
            if isinstance(relationships, list) and relationships:
                g3 = build_dependency_graph(relationships)
                for src, children in g3.items():
                    for child in children:
                        try:
                            rv = next((x.get('version') for x in comps if (x.get('name') == src or x.get('purl') == src)), '')
                            cv = next((x.get('version') for x in comps if (x.get('name') == child or x.get('purl') == child)), '')
                            src_id = f"package:{src}:{rv}"
                            dst_id = f"package:{child}:{cv}"
                            hg.add_node_attr(src_id, type='package', name=src, version=rv)
                            hg.add_node_attr(dst_id, type='package', name=child, version=cv)
                            hg.add_edge(src_id, dst_id, 'depends_on', source='spdx')
                        except Exception:
                            continue
        except Exception:
            pass
        # ML provenance nodes
        try:
            models = (data.get('models') if isinstance(data, dict) else None) or []
            if isinstance(models, list) and models:
                for m in models:
                    try:
                        mid = (m or {}).get('model_id') or (m or {}).get('id')
                        vendor = (m or {}).get('vendor')
                        checksum = (m or {}).get('checksum')
                        origin = (m or {}).get('origin')
                        node_id = f"model:{mid}"
                        hg.add_node_attr(node_id, type='ml_model', vendor=vendor, checksum=checksum, origin=origin)
                        # link model to all packages if requested
                        if (m or {}).get('applies_to') == 'packages':
                            for c in comps:
                                try:
                                    pkg_id = f"package:{(c or {}).get('name')}:{(c or {}).get('version') or ''}"
                                    hg.add_edge(node_id, pkg_id, 'provenance', source='enriched', attrs={'relation':'used_by'})
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except Exception:
            pass
        # Optional sandbox probe (test mode)
        try:
            if os.getenv('ENABLE_SANDBOX_PROBE','0').lower() in {'1','true','yes'}:
                from src.integrations.sandbox_adapter import submit_package_for_probe, normalize_behavior  # type: ignore
                sb_factors: list[dict[str, Any]] = []
                for c in comps:
                    try:
                        payload = {
                            'name': (c or {}).get('name'),
                            'version': (c or {}).get('version'),
                            'install_script': (c or {}).get('scripts', {}).get('install') or (c or {}).get('scripts', {}).get('postinstall') or '',
                            'setup_py': (c or {}).get('setup') or '',
                        }
                        rep = submit_package_for_probe(payload)
                        facs = normalize_behavior(rep)
                        sb_factors.extend(facs)
                        # emit to HopGraph
                        for f in facs:
                            try:
                                target = f.get('target') or (c or {}).get('name')
                                nid = f"package:{target}:{(c or {}).get('version') or ''}"
                                fname = f.get('factor') or f.get('name') or 'sandbox_factor'
                                if isinstance(fname, str):
                                    hg.add_node_factor(nid, fname)
                            except Exception:
                                continue
                    except Exception:
                        continue
                if sb_factors:
                    extra_factors.extend(sb_factors)
        except Exception:
            pass

    # Add extra_factors into response for transparency
    if extra_factors:
        try:
            vulns.extend([
                {
                    'component': ef.get('producer', 'package_integrity'),
                    'version': '',
                    'severity': 'info',
                    'summary': 'detector_factor',
                    'factors': [ef],
                }
                for ef in extra_factors
            ])
        except Exception:
            pass

    return {'sbom_id': sbom_id, 'components': len(comps), 'vulns_found': len(vulns)}


@router.get('/api/v1/sbom/vulns')  # type: ignore[misc]
async def sbom_vulns(sbom_id: str, include_suppressed: bool = False) -> dict[str, Any]:
    if sbom_id not in _SBOMS:
        raise HTTPException(status_code=404, detail='sbom_not_found')
    # Start from base vulns and apply VEX dynamically (so later updates reflect)
    comps = (_SBOMS.get(sbom_id) or {}).get('components') or []
    comp_versions = { (c.get('name') or ''): (c.get('version') or '') for c in comps if isinstance(c, dict) }
    base = list(_VULNS.get(sbom_id, []))
    vex = list(_VEX.get(sbom_id, []) or [])
    applied: list[dict[str, Any]] = []
    for v in base:
        nv = dict(v)
        comp = nv.get('component')
        ver = comp_versions.get(comp, '')
        cve = nv.get('cve')
        # Find first matching statement by comp(+version range) and cve (if provided)
        match = None
        for s in vex:
            if s.get('component') != comp:
                continue
            if cve and s.get('cve') and s.get('cve') != cve:
                continue
            rng = s.get('version_range') or s.get('version')
            if not _version_in_range(ver, rng):
                continue
            match = s
            break
        if match:
            nv['vex_status'] = match.get('status')
            nv['vex_justification'] = match.get('justification')
            if match.get('status') == 'not_affected':
                nv['suppressed'] = True
                nv['severity'] = 'none'
                nv['risk_score'] = 0.0
            elif match.get('status') == 'fixed':
                nv['severity'] = 'low'
                nv['risk_score'] = min(0.2, float(nv.get('risk_score') or 0.2))
        applied.append(nv)
    # Enrich with KEV/EPSS
    try:
        enriched = await ENRICHER.enrich(applied)
    except Exception:
        enriched = applied

    # Best-effort: Tenable VPR enrichment (if configured)
    try:
        try:
            from integrations.tenable_client import CLIENT as TENABLE  # type: ignore
        except Exception:
            from src.integrations.tenable_client import CLIENT as TENABLE  # type: ignore
        cves = [str((v.get('cve') or '')).upper() for v in enriched if v.get('cve')]
        cves = [c for c in cves if c.startswith('CVE-')]
        if cves:
            vpr_map = await TENABLE.get_vpr_for_cves(cves)  # type: ignore[attr-defined]
            if isinstance(vpr_map, dict):
                for v in enriched:
                    cv = str((v.get('cve') or '')).upper()
                    if cv and cv in vpr_map:
                        try:
                            sc = float(vpr_map[cv])
                            v['vpr'] = sc
                            v['vpr_score'] = sc
                        except Exception:
                            continue
    except Exception:
        pass

    # Attach lightweight explainability: factors -> STRIDE/DREAD/MAESTRO, controls, next steps
    explained: list[dict[str, Any]] = []
    for v in enriched:
        try:
            factors: list[str] = []
            sev = (v.get('severity') or '').lower()
            if sev == 'critical':
                factors.append('sbom:cve_critical')
            elif sev == 'high':
                factors.append('sbom:cve_high')
            # Exploitability markers
            if v.get('kev'):
                factors.append('exploit:kev')
            try:
                if float(v.get('epss') or 0.0) >= float(os.getenv('EPSS_EXPLOIT_THRESHOLD','0.7')):
                    factors.append('exploit:high_epss')
            except Exception:
                pass
            # Basic supply-chain drift marker if component has meta indicating unexpected source
            comp_name = (v.get('component') or '')
            if isinstance(comp_name, str) and 'struts' in comp_name.lower():
                factors.append('sbom:supply_chain_drift')
            # Derive threat model and mapped controls
            tmodel = aggregate_threat_model(factors)
            ctrls = controls_for_factors(factors)
            # Next steps guidance (heuristic)
            next_steps: list[str] = []
            if sev in ('critical','high'):
                next_steps.append('Prioritize patch/upgrade to a non-vulnerable version')
            if v.get('kev'):
                next_steps.append('Treat as known exploited; increase monitoring and block exploit patterns')
            if float(v.get('epss') or 0.0) >= 0.7:
                next_steps.append('High likelihood of exploitation; expedite remediation within 7 days')
            next_steps.append('Validate no indicators of exploitation across relevant logs')
            # Affected systems: accept from SBOM component metadata when provided
            affected_systems: list[str] = []
            try:
                comp_meta = next((c for c in comps if (c or {}).get('name') == v.get('component')), {})
                for key in ('systems','hosts','services','applications'):
                    vals = comp_meta.get(key)
                    if isinstance(vals, list):
                        affected_systems.extend([str(x) for x in vals if x])
            except Exception:
                pass
            nv = dict(v)
            nv['factors'] = factors
            nv['threat_model'] = tmodel
            nv['controls'] = ctrls
            nv['next_steps'] = next_steps
            if affected_systems:
                nv['affected_systems'] = sorted(list(set(affected_systems)))
            explained.append(nv)
        except Exception:
            explained.append(v)
    if not include_suppressed:
        explained = [x for x in explained if not x.get('suppressed')]
    return {'sbom_id': sbom_id, 'vulns': explained}

@router.get('/api/v1/sbom/recent')  # type: ignore[misc]
async def sbom_recent() -> dict[str, Any]:
    """Return recently uploaded SBOM IDs (most-recent first)."""
    return {'recent': list(_RECENT_SBOMS)}


@router.post('/api/v1/sbom/vex')  # type: ignore[misc]
async def sbom_vex(request: Request) -> dict[str, Any]:
    """Attach VEX statements to an SBOM.

    Body: { sbom_id: string, statements: [ {component, cve, status, justification?, notes?} ] }
    status in {"not_affected","affected","under_investigation","fixed"}
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='bad_json')
    sbom_id = (data.get('sbom_id') or '').strip()
    if not sbom_id or sbom_id not in _SBOMS:
        raise HTTPException(status_code=404, detail='sbom_not_found')
    stmts = data.get('statements') or []
    if not isinstance(stmts, list) or not stmts:
        raise HTTPException(status_code=400, detail='no_statements')
    # Store statements
    arr = _VEX.get(sbom_id) or []
    for s in stmts:
        try:
            comp = (s or {}).get('component')
            cve = (s or {}).get('cve')
            status = (s or {}).get('status')
            if not comp or not cve or not status:
                continue
            entry = {
                'component': comp,
                'cve': cve,
                'status': status,
                'justification': (s or {}).get('justification'),
                'notes': (s or {}).get('notes'),
                'version_range': (s or {}).get('version_range') or (s or {}).get('version'),
            }
            arr.append(entry)
        except Exception:
            continue
    _VEX[sbom_id] = arr
    # Persist to disk
    try:
        _persist_vex(sbom_id, stmts)
    except Exception:
        pass
    return {'sbom_id': sbom_id, 'statements': len(arr)}

# Load VEX from disk on import
try:
    _load_vex_from_disk()
except Exception:
    pass
try:
    _load_exceptions_from_disk()
except Exception:
    pass


__all__ = ['router']

# ---------------- Internal helpers for aggregation (executive report) -----------------
def get_recent_sbom_ids() -> list[str]:
    return list(_RECENT_SBOMS)

def get_sbom_vulns_data(sbom_id: str, include_suppressed: bool = False) -> list[dict[str, Any]]:
    """Return vulnerability records for a given SBOM ID (best‑effort, no enrichment).

    Used by server-side aggregation to avoid HTTP roundtrips.
    """
    comps = (_SBOMS.get(sbom_id) or {}).get('components') or []
    comp_versions = { (c.get('name') or ''): (c.get('version') or '') for c in comps if isinstance(c, dict) }
    comp_meta = { (c.get('name') or ''): c for c in comps if isinstance(c, dict) }
    base = list(_VULNS.get(sbom_id, []))
    vex = list(_VEX.get(sbom_id, []) or [])
    out: list[dict[str, Any]] = []
    for v in base:
        nv = dict(v)
        comp = nv.get('component')
        ver = comp_versions.get(comp, '')
        try:
            meta = comp_meta.get(comp, {}) or {}
            if 'purl' in meta:
                nv['purl'] = meta.get('purl')
            if 'cpe' in meta:
                nv['cpe'] = meta.get('cpe')
        except Exception:
            pass
        cve = nv.get('cve')
        match = None
        for s in vex:
            if s.get('component') != comp:
                continue
            if cve and s.get('cve') and s.get('cve') != cve:
                continue
            rng = s.get('version_range') or s.get('version')
            if not _version_in_range(ver, rng):
                continue
            match = s
            break
        if match:
            nv['vex_status'] = match.get('status')
            nv['vex_justification'] = match.get('justification')
            if match.get('status') == 'not_affected':
                nv['suppressed'] = True
                nv['severity'] = 'none'
                nv['risk_score'] = 0.0
            elif match.get('status') == 'fixed':
                nv['severity'] = 'low'
                nv['risk_score'] = min(0.2, float(nv.get('risk_score') or 0.2))
        # Attach basic explainability without KEV/EPSS (report path avoids network)
        try:
            factors: list[str] = []
            sev = (nv.get('severity') or '').lower()
            if sev == 'critical':
                factors.append('sbom:cve_critical')
            elif sev == 'high':
                factors.append('sbom:cve_high')
            nv['factors'] = factors
            nv['threat_model'] = aggregate_threat_model(factors)
            nv['controls'] = controls_for_factors(factors)
        except Exception:
            pass
        out.append(nv)
    if not include_suppressed:
        out = [x for x in out if not x.get('suppressed')]
    return out

__all__.extend(['get_recent_sbom_ids', 'get_sbom_vulns_data'])

# ---------------- Exceptions endpoints and helpers -----------------
@router.post('/api/v1/sbom/exceptions')  # type: ignore[misc]
async def sbom_exceptions_set(request: Request) -> dict[str, Any]:
    """Record temporary risk acceptance exceptions.

    Body: { sbom_id: string, items: [ {component, cve?, reason?, until_ts?} ] }
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    sbom_id = (data.get('sbom_id') or '').strip()
    if not sbom_id or sbom_id not in _SBOMS:
        raise HTTPException(status_code=404, detail='sbom_not_found')
    items = data.get('items') or []
    if not isinstance(items, list) or not items:
        raise HTTPException(status_code=400, detail='no_items')
    arr = _EXCEPTIONS.get(sbom_id) or []
    now = time.time()
    for it in items:
        try:
            comp = (it or {}).get('component')
            if not comp:
                continue
            entry = {
                'component': comp,
                'cve': (it or {}).get('cve'),
                'reason': (it or {}).get('reason'),
                'until_ts': float((it or {}).get('until_ts') or (now + 30*86400)),
            }
            arr.append(entry)
        except Exception:
            continue
    _EXCEPTIONS[sbom_id] = arr
    try:
        _persist_exc(sbom_id, items)
    except Exception:
        pass
    return {'sbom_id': sbom_id, 'exceptions': len(arr)}

@router.get('/api/v1/sbom/exceptions')  # type: ignore[misc]
async def sbom_exceptions_get(sbom_id: str) -> dict[str, Any]:
    arr = list(_EXCEPTIONS.get(sbom_id) or [])
    now = time.time()
    active = [x for x in arr if float(x.get('until_ts') or 0) >= now]
    return {'sbom_id': sbom_id, 'exceptions': active, 'count': len(active)}

def get_active_exceptions(sbom_id: str) -> list[dict[str, Any]]:
    now = time.time()
    arr = list(_EXCEPTIONS.get(sbom_id) or [])
    return [x for x in arr if float(x.get('until_ts') or 0) >= now]

__all__.extend(['get_active_exceptions'])
