from __future__ import annotations

PROMPT_TEMPLATE = (
    "Overview:\n<<OVERVIEW>>\n\n"
    "Key Risk Drivers:\n<<RISK_DRIVERS>>\n\n"
    "Mapping to frameworks (DREAD / MITRE / STRIDE):\n<<MAPPING>>\n\n"
    "Recommended Actions:\n<<ACTIONS>>\n\n"
    "Confidence & Caveats:\n<<CONFIDENCE>>\n\n"
    "Data Quality:\n<<DATA_QUALITY>>\n"
)


def compose_prompt(context: dict) -> str:
    rows = context.get('rows') or []
    factors = context.get('factors') or []
    overview = (
        f"Analyzing {len(rows)} rows. Top factors: "
        + ", ".join([str(f.get('name') if isinstance(f, dict) else str(f)) for f in factors[:8]])
    )
    risk_drivers = '\n'.join([
        f"- {f.get('stage')}:{f.get('name')} -> {str(f.get('value'))[:200]}" for f in (factors or [])[:10]
    ]) or 'None'
    mapping = 'Mapping not available in prompt.'
    actions = 'Recommend containment, evidence preservation, and further enrichment.'
    confidence = 'Automated estimate; validate before escalation.'
    missing = []
    if rows and isinstance(rows, list):
        sample = rows[0] if rows else {}
        if isinstance(sample, dict):
            if not any(k in sample for k in ('user','host','ip','file_hash','domain')):
                missing.append('Low canonical coverage: no user/host/ip/file_hash/domain fields')
    data_quality = '\n'.join(missing) or 'Data quality appears adequate for summary.'
    # Build Data Availability Manifest to ground LLMs and prevent hallucination
    try:
        manifest = {
            'available_fields': [],
            'missing_fields': [],
            'field_quality': {}
        }
        # standard fields we expect for forensic analysis
        standard_fields = [
            'timestamp','ts','time','evt_time',
            'src_ip','source_ip','ip','ip_src',
            'dst_ip','destination_ip','ip_dst',
            'src_port','dst_port',
            'process_name','image','process',
            'command_line','cmdline','process_cmdline',
            'parent_process','parent_image',
            'user','username','account',
            'host','hostname','computer',
            'domain','file_path','file_name',
            'file_hash','sha256','md5',
            'registry_key','registry_value'
        ]
        sample = rows[0] if rows and isinstance(rows, list) and isinstance(rows[0], dict) else {}
        for f in standard_fields:
            if f in sample:
                manifest['available_fields'].append(f)
                try:
                    vals = list({(sample.get(f) or '')})
                    manifest['field_quality'][f] = {'null_percentage': 0.0 if sample.get(f) is not None else 1.0, 'sample_values': vals[:3]}
                except Exception:
                    manifest['field_quality'][f] = {}
            else:
                manifest['missing_fields'].append(f)
    except Exception:
        manifest = {'available_fields': [], 'missing_fields': [], 'field_quality': {}}
    # Embed manifest into prompt as a clear block LLM must honor
    manifest_lines = [f"AVAILABLE FIELDS: {', '.join(manifest['available_fields']) if manifest.get('available_fields') else 'NONE'}",
                      f"MISSING FIELDS: {', '.join(manifest['missing_fields'][:40]) if manifest.get('missing_fields') else 'NONE'}"]
    manifest_block = "\n".join(manifest_lines)

    out = PROMPT_TEMPLATE.replace('<<OVERVIEW>>', overview)
    out = out + "\n\nDATA AVAILABILITY MANIFEST:\n" + manifest_block + "\n\nCRITICAL INSTRUCTIONS:\n1. ONLY reference fields listed in AVAILABLE FIELDS.\n2. For MISSING FIELDS, state what is missing and recommend collection guidance.\n3. DO NOT invent values for missing fields.\n"
    out = out.replace('<<RISK_DRIVERS>>', risk_drivers)
    out = out.replace('<<MAPPING>>', mapping)
    out = out.replace('<<ACTIONS>>', actions)
    out = out.replace('<<CONFIDENCE>>', confidence)
    out = out.replace('<<DATA_QUALITY>>', data_quality)
    # Playbook recommendations: suggest specific collections based on detected MITRE tags
    try:
        mitre_tags = (context.get('mitre_tags') or [])
        try:
            from src.analysis.playbook_db import get_playbook_for_mitre  # type: ignore
        except Exception:
            try:
                from ..analysis.playbook_db import get_playbook_for_mitre  # type: ignore
            except Exception:
                get_playbook_for_mitre = None  # type: ignore
        if mitre_tags and get_playbook_for_mitre:
            pb_lines = ['\nPLAYBOOK RECOMMENDATIONS:']
            for mid in mitre_tags[:3]:
                try:
                    p = get_playbook_for_mitre(str(mid).upper())
                except Exception:
                    p = None
                if p and isinstance(p, dict) and p.get('playbook'):
                    play = p['playbook']
                    pb_lines.append(f"- {mid}: {p.get('name') or play.get('description','')}")
                    for req in play.get('required_logs', [])[:3]:
                        cmd = req.get('command') or ''
                        pb_lines.append(f"  - {req.get('source')}: {cmd} -- {req.get('why')}")
            out = out + "\n" + "\n".join(pb_lines)
    except Exception:
        pass
    return out
