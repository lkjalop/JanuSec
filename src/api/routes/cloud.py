from fastapi import APIRouter, Request, HTTPException

router = APIRouter(prefix="/api/v1/cloud", tags=["cloud"])

@router.post('/ingest')
async def ingest_cloud(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    resource = str(data.get('resource') or '')
    action = str(data.get('action') or 'list')
    hg = getattr(request.app, 'GLOBAL_HOPGRAPH', None)
    if hg is None:
        return {'status': 'mock'}
    try:
        if resource:
            hg.add_node_attr(f'cloud:{resource}', type='cloud', action=action)
            if 'public' in resource.lower():
                hg.add_node_attr('cloud:public_bucket', type='meta', resource=resource)
            # Detect KMS/secrets access anomalies: best-effort hook
            try:
                from src.core.detectors.cloud_kms_secrets import record_access as record_kms_access
            except Exception:
                record_kms_access = None
            try:
                if record_kms_access and any(x in resource.lower() for x in ('kms','secrets','key')):
                    # principal may be in data['principal'] or data['user']
                    principal = data.get('principal') or data.get('user') or data.get('caller')
                    if principal:
                        record_kms_access(hg, str(principal))
            except Exception:
                pass
            # Phase 4 IAM: Azure AD / OAuth / PIM (identity-side cloud signals)
            try:
                from src.core.detectors.iam_phase3_4 import detect_cloud_identity_phase4  # type: ignore
                ef4, atts4 = detect_cloud_identity_phase4(data if isinstance(data, dict) else {})
                if ef4:
                    for nid, fac in atts4:
                        try:
                            hg.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                            hg.add_node_factor(nid, fac)
                        except Exception:
                            pass
            except Exception:
                pass
            # Provider-specific: AWS and Okta
            try:
                provider = str((data or {}).get('provider') or '').lower()
                if provider == 'aws':
                    from src.core.detectors.iam_aws import detect_cloud_aws  # type: ignore
                    ef_aws, atts_aws = detect_cloud_aws(data if isinstance(data, dict) else {})
                    if ef_aws:
                        for nid, fac in atts_aws:
                            try:
                                hg.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                                hg.add_node_factor(nid, fac)
                            except Exception:
                                pass
                elif provider == 'okta':
                    from src.core.detectors.iam_okta import detect_identity_okta  # type: ignore
                    ef_ok, atts_ok = detect_identity_okta(data if isinstance(data, dict) else {})
                    if ef_ok:
                        for nid, fac in atts_ok:
                            try:
                                hg.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                                hg.add_node_factor(nid, fac)
                            except Exception:
                                pass
                elif provider == 'gcp':
                    from src.core.detectors.iam_gcp import detect_cloud_gcp  # type: ignore
                    from src.core.detectors.iam_gcp_org import detect_cloud_gcp_org  # type: ignore
                    ef_gcp, atts_gcp = detect_cloud_gcp(data if isinstance(data, dict) else {})
                    ef_gcp_org, atts_gcp_org = detect_cloud_gcp_org(data if isinstance(data, dict) else {})
                    for atts in (atts_gcp, atts_gcp_org):
                        if atts:
                            for nid, fac in atts:
                                try:
                                    hg.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                                    hg.add_node_factor(nid, fac)
                                except Exception:
                                    pass
                elif provider == 'azure':
                    from src.core.detectors.iam_azure_arm import detect_cloud_azure  # type: ignore
                    from src.core.detectors.iam_intune import detect_intune  # type: ignore
                    from src.core.detectors.iam_purview import detect_purview  # type: ignore
                    ef_az, atts_az = detect_cloud_azure(data if isinstance(data, dict) else {})
                    ef_intune, atts_intune = detect_intune(data if isinstance(data, dict) else {})
                    ef_pv, atts_pv = detect_purview(data if isinstance(data, dict) else {})
                    for atts in (atts_az, atts_intune, atts_pv):
                        if atts:
                            for nid, fac in atts:
                                try:
                                    hg.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                                    hg.add_node_factor(nid, fac)
                                except Exception:
                                    pass
                elif provider == 'intune':
                    from src.core.detectors.iam_intune import detect_intune  # type: ignore
                    _, atts_intune = detect_intune(data if isinstance(data, dict) else {})
                    if atts_intune:
                        for nid, fac in atts_intune:
                            try:
                                hg.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                                hg.add_node_factor(nid, fac)
                            except Exception:
                                pass
                elif provider == 'purview':
                    from src.core.detectors.iam_purview import detect_purview  # type: ignore
                    _, atts_pv = detect_purview(data if isinstance(data, dict) else {})
                    if atts_pv:
                        for nid, fac in atts_pv:
                            try:
                                hg.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                                hg.add_node_factor(nid, fac)
                            except Exception:
                                pass
            except Exception:
                pass
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {'status': 'ok'}
