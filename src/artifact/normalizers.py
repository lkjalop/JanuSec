from __future__ import annotations

from typing import Any, Dict

from .models import ArtifactObservation, ArtifactType, stable_artifact_id

EXEC_EXT = {'.exe','.dll','.sys','.ocx'}
SCRIPT_EXT = {'.ps1','.vbs','.js','.bat','.cmd','.wsf'}
DOC_EXT = {'.docm','.xlsm','.docx','.xlsx','.pptm','.pptx','.rtf','.pdf'}
EXTN_EXT = {'.crx','.xpi'}

def detect_type(raw: dict[str, Any]) -> ArtifactType:
    ext = (raw.get('extension') or raw.get('ext') or '').lower()
    (raw.get('path') or '').lower()
    if ext in EXEC_EXT:
        return ArtifactType.DRIVER if ext == '.sys' else ArtifactType.EXECUTABLE
    if ext in SCRIPT_EXT:
        return ArtifactType.SCRIPT
    if ext in DOC_EXT:
        return ArtifactType.DOCUMENT
    if ext in EXTN_EXT:
        return ArtifactType.BROWSER_EXTENSION
    if raw.get('task_name'):
        return ArtifactType.SCHEDULED_TASK
    if raw.get('wmi_consumer'):
        return ArtifactType.WMI_CONSUMER
    if raw.get('download_origin'):
        return ArtifactType.DOWNLOAD
    return ArtifactType.UNKNOWN

CANON_MAP = {
    'filename':'name','file_name':'name','image_name':'name',
    'filepath':'path','file_path':'path','image_path':'path','fullpath':'path',
    'sha256':'sha256','hash_sha256':'sha256',
    'size':'size','filesize':'size','file_size':'size',
    'host':'host','hostname':'host','computer':'host',
    'zone':'zone','zone_id':'zone','download_origin':'download_origin'
}

BOOL_LIKE = {'true':True,'false':False,'1':True,'0':False,'yes':True,'no':False}

SAFE_FIELDS = {'path','name','sha256','size','host','zone','download_origin','extension'}

def normalize(raw: dict[str, Any]) -> ArtifactObservation:
    norm: dict[str, Any] = {}
    for k,v in list(raw.items()):
        if k is None: continue
        lk = str(k).strip().lower()
        mapped = CANON_MAP.get(lk, lk)
        if isinstance(v,str):
            vs = v.strip()
            if mapped in ('size',):
                try: norm[mapped] = int(vs)
                except: pass
            else:
                norm[mapped] = vs
        else:
            norm[mapped] = v
    # Derive extension
    if 'extension' not in norm:
        path = norm.get('path') or ''
        if '.' in path:
            norm['extension'] = '.'+path.rsplit('.',1)[-1].lower()
    art_type = detect_type(norm)
    host = norm.get('host','unknown')
    aid = stable_artifact_id(host, norm.get('path'), norm.get('sha256'), art_type)
    obs = ArtifactObservation(
        artifact_id=aid,
        sha256=norm.get('sha256'),
        artifact_type=art_type,
        host=host,
        path=norm.get('path'),
        name=norm.get('name') or (norm.get('path') or 'unknown').split('/')[-1].split('\\')[-1],
        size=norm.get('size'),
        raw={k:v for k,v in norm.items() if k not in SAFE_FIELDS}
    )
    return obs
