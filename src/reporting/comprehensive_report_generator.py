import json
from html import escape

def _render_row_preview(r):
    try:
        return '<pre style="background:#111; color:#e6eef8; padding:8px; border-radius:6px; overflow:auto; max-height:160px">' + escape(json.dumps(r, indent=2)) + '</pre>'
    except Exception:
        return '<pre>(failed to render)</pre>'

def build_report_html(payload):
    title = escape(str(payload.get('title','Comprehensive Findings Report')))
    rows = payload.get('rows') or []
    session = payload.get('session_id') or ''
    sections = []
    sections.append(f'<h2>{title}</h2>')
    sections.append(f'<div><strong>Session:</strong> {escape(str(session))}</div>')
    # Executive Summary
    meta = payload.get('meta') or {}
    company = meta.get('company_name') or ''
    recipients = meta.get('recipients') or []
    try:
        rec_str = ', '.join([escape(str(r)) for r in recipients]) if recipients else ''
    except Exception:
        rec_str = ''
    sections.append('<h3>Executive Summary</h3>')
    if company:
        sections.append(f'<div><strong>Company:</strong> {escape(str(company))}</div>')
    if rec_str:
        sections.append(f'<div><strong>Recipients:</strong> {rec_str}</div>')
    # Derive simple key findings from rows and correlation
    findings = []
    # high-level: count unique hosts, top verdicts, high DREAD scores
    try:
        hosts = {}
        verdicts = {}
        high_dread = []
        for r in rows[:500]:
            h = r.get('host') or r.get('hostname') or ''
            if h: hosts[h] = hosts.get(h,0) + 1
            v = r.get('verdict') or r.get('Verdict') or ''
            if v: verdicts[v] = verdicts.get(v,0) + 1
            d = None
            if isinstance(r.get('_dread'), dict): d = r.get('_dread',{}).get('score')
            elif isinstance(r.get('dread'), dict): d = r.get('dread',{}).get('score')
            try:
                if d is not None and float(d) >= 7:
                    high_dread.append({'row': r.get('process_name') or r.get('file_path') or r.get('sha256') or 'n/a', 'score': d})
            except Exception:
                pass
        top_hosts = sorted(hosts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_hosts:
            findings.append('Top hosts by row count: ' + ', '.join([f"{escape(str(h))}({c})" for h,c in top_hosts]))
        if verdicts:
            vitems = sorted(verdicts.items(), key=lambda x: x[1], reverse=True)
            findings.append('Verdict distribution: ' + ', '.join([f"{escape(str(k))}({v})" for k,v in vitems[:5]]))
        if high_dread:
            findings.append('High-severity DREAD entries: ' + ', '.join([f"{escape(str(x['row']))}: {x['score']}" for x in high_dread[:5]]))
    except Exception:
        findings.append('Key findings extraction failed.')
    # Correlation cues
    corr = payload.get('correlation') or {}
    try:
        if isinstance(corr, dict) and corr.get('verdict'):
            findings.append('Correlation verdict: ' + escape(str(corr.get('verdict'))))
        if isinstance(corr, dict) and corr.get('confidence') is not None:
            findings.append('Correlation confidence: ' + escape(str(corr.get('confidence'))))
    except Exception:
        pass
    if findings:
        sections.append('<div>' + escape('\n'.join(findings)).replace('\n','<br/>') + '</div>')
    else:
        sections.append('<div>No immediate key findings detected.</div>')
    # One-line recommendation (simple heuristic)
    try:
        if high_dread:
            recommendation = 'Recommendation: Prioritize containment and forensic capture for high DREAD findings.'
        elif corr and corr.get('verdict') and corr.get('confidence',0) >= 0.7:
            recommendation = 'Recommendation: Initiate focused incident response on correlated path with highest score.'
        else:
            recommendation = 'Recommendation: Review flagged rows and enrich telemetry, consider deeper correlation analysis.'
    except Exception:
        recommendation = 'Recommendation: Review findings.'
    sections.append(f'<div style="margin-top:8px;padding:10px;background:#10131a;border-left:4px solid #2b3443;border-radius:6px"><strong>{escape(recommendation)}</strong></div>')
    sections.append('<h3>Summary</h3>')
    summary = payload.get('summary') or {'rows': len(rows)}
    sections.append('<div><pre>'+escape(json.dumps(summary, indent=2))+'</pre></div>')
    if rows:
        sections.append('<h3>Rows</h3>')
        for i,r in enumerate(rows[:200]):
            sections.append(f'<div style="border:1px solid #333;padding:8px;margin-bottom:8px;border-radius:6px"><strong>Row {i}</strong>')
            sections.append(_render_row_preview(r))
            sections.append('</div>')

    sections.append('<h3>HopGraph Snapshot</h3>')
    # if a correlation object exists in payload include its textual summary
    corr = payload.get('correlation')
    if corr:
        try:
            sections.append('<div><pre>'+escape(json.dumps(corr, indent=2))+'</pre></div>')
        except Exception:
            sections.append('<div>Failed to render correlation</div>')
    else:
        sections.append('<div>No HopGraph data included.</div>')

    footer = '<div style="margin-top:18px;font-size:12px;color:#999">Report generated by Janusec demo runner</div>'
    html = '<!doctype html><html><head><meta charset="utf-8"><title>'+title+'</title></head><body style="background:#0b0f14;color:#e6eef8;font-family:Segoe UI,Arial,sans-serif;padding:18px">' + '\n'.join(sections) + footer + '</body></html>'
    return html
