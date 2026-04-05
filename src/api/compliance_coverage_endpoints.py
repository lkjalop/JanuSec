from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, HTMLResponse
from typing import List
from typing import Optional

from src.compliance.taxonomy import coverage, load_taxonomy

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])

@router.get("/coverage")
def compliance_coverage(framework: str = Query(..., pattern="^(mitre|nist_csf|cis_v8|iso_27001|stride|kill_chain|d3fend)$"), format: Optional[str] = Query("json")):
    cov = coverage(framework)
    if format == 'html':
        html = ["<html><head><title>Compliance Coverage</title></head><body>"]
        html.append(f"<h2>Framework Coverage: {framework}</h2>")
        html.append(f"<p><strong>Mapped:</strong> {cov['mapped']} / {cov['total_factors']} ({cov['coverage_percent']}%)</p>")
        if cov['unmapped_factors']:
            html.append("<h3>Unmapped Factors</h3><ul>")
            for k in cov['unmapped_factors'][:50]:
                html.append(f"<li>{k}</li>")
            html.append("</ul>")
        html.append("</body></html>")
        return HTMLResponse(''.join(html))
    return JSONResponse(cov)

@router.get("/taxonomy")
def taxonomy_raw():
    return load_taxonomy()

@router.get("/report")
def coverage_report(format: Optional[str] = Query("html")):
    data = load_taxonomy()
    frameworks: List[str] = data.get('frameworks', [])
    rows = []
    for fw in frameworks:
        cov = coverage(fw)
        rows.append(cov)
    if format == 'json':
        return JSONResponse({'frameworks': rows, 'generated': data.get('generated'), 'version': data.get('version')})
    # HTML default
    html = ["<html><head><title>Cross-Mapping Coverage</title></head><body>"]
    html.append("<h2>Cross-Mapping Coverage Summary</h2>")
    html.append("<table border='1' cellspacing='0' cellpadding='4'><tr><th>Framework</th><th>Mapped</th><th>Total</th><th>Coverage %</th></tr>")
    for r in rows:
        html.append(f"<tr><td>{r['framework']}</td><td>{r['mapped']}</td><td>{r['total_factors']}</td><td>{r['coverage_percent']}</td></tr>")
    html.append("</table>")
    # Sample unmapped slice for executive visibility
    unmapped = []
    for r in rows:
        for u in r.get('unmapped_factors', [])[:5]:
            unmapped.append((r['framework'], u))
    if unmapped:
        html.append("<h3>Sample Unmapped Factors (Top 5 per Framework)</h3><ul>")
        for fw,u in unmapped:
            html.append(f"<li><strong>{fw}</strong>: {u}</li>")
        html.append("</ul>")
    html.append("</body></html>")
    return HTMLResponse(''.join(html))
