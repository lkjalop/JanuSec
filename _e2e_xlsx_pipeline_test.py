"""
End-to-end pipeline test for cybstash csv1.xlsx and Cyberstash_csv2.xlsx.
Tests: upload → ingest_rows → deep_analyze → Tier1 LLM → Tier2 LLM → report
Measures latency at each stage.
"""
import os, io, json, time, csv, sys, pprint
import requests
import openpyxl

BASE = "http://localhost:8080"
HEADERS = {
    "x-api-key": "janusec-staging-local-20260324",
    "X-Tenant-ID": "e2e-test",
}
DUMP = os.path.join(os.path.dirname(__file__), "dump")

XLSX_FILES = {
    "csv1": os.path.join(DUMP, "cybstash csv1.xlsx"),
    "csv2": os.path.join(DUMP, "Cyberstash_csv2.xlsx"),
}

results = {}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: load all sheets from xlsx and flatten to dicts
# ─────────────────────────────────────────────────────────────────────────────
def load_all_sheets(path: str) -> dict:
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    sheets = {}
    for sname in wb.sheetnames:
        ws = wb[sname]
        rows = list(ws.iter_rows(values_only=True))
        if not rows:
            continue
        headers = [str(h or f"col{i}").strip() for i, h in enumerate(rows[0])]
        data = []
        for r in rows[1:]:
            d = {headers[i]: (v if v is not None else "") for i, v in enumerate(r)}
            data.append(d)
        sheets[sname] = data
    return sheets


def first_sheet_csv(path: str) -> bytes:
    """Mimick exactly what the server does: openpyxl active sheet → CSV bytes."""
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    sheet = wb.active
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in sheet.iter_rows(values_only=True):
        writer.writerow(['' if v is None else str(v) for v in row])
    return buf.getvalue().encode('utf-8')


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1: Upload via /api/v1/csv/upload (mimics UI behaviour)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 1: Upload XLSX files via /api/v1/csv/upload")
print("="*70)

for label, path in XLSX_FILES.items():
    fname = os.path.basename(path)
    raw = open(path, "rb").read()
    t0 = time.perf_counter()
    try:
        r = requests.post(
            f"{BASE}/api/v1/csv/upload",
            headers=HEADERS,
            files={"file": (fname, raw, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
            timeout=60,
        )
        elapsed = time.perf_counter() - t0
        body = r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text[:500]}
        print(f"\n[{label}] status={r.status_code}  elapsed={elapsed:.2f}s")
        print(f"  rows_processed={body.get('rows_processed') or body.get('total_rows') or '?'}")
        print(f"  rows_flagged={body.get('rows_flagged') or body.get('flagged') or '?'}")
        print(f"  session_id={body.get('session_id') or body.get('id') or '?'}")
        if r.status_code >= 400:
            print(f"  ERROR detail: {body.get('detail') or body}")
        results[f"{label}_upload"] = {"status": r.status_code, "elapsed": elapsed, "body": body}
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"\n[{label}] EXCEPTION after {elapsed:.2f}s: {e}")
        results[f"{label}_upload"] = {"status": "exception", "elapsed": elapsed, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2: Ingest_rows (all sheets from CSV2, flat rows from CSV1)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 2: ingest_rows — all sheets for CSV2")
print("="*70)

ingest_session_ids = {}

for label, path in XLSX_FILES.items():
    all_sheets = load_all_sheets(path)
    print(f"\n[{label}] sheets found: {list(all_sheets.keys())}")
    all_rows = []
    for sname, rows in all_sheets.items():
        for r in rows:
            r["_sheet"] = sname  # tag origin sheet
            all_rows.append(r)
    print(f"[{label}] total rows across all sheets: {len(all_rows)}")

    t0 = time.perf_counter()
    try:
        r = requests.post(
            f"{BASE}/api/v1/csv/ingest_rows",
            headers={**HEADERS, "Content-Type": "application/json"},
            json={"rows": all_rows, "source": f"e2e_{label}"},
            timeout=120,
        )
        elapsed = time.perf_counter() - t0
        body = r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text[:500]}
        session_id = body.get("session_id") or body.get("id") or ""
        print(f"  status={r.status_code}  elapsed={elapsed:.2f}s  session_id={session_id}")
        print(f"  rows_processed={body.get('rows_processed') or body.get('total_rows') or body.get('accepted') or '?'}")
        print(f"  rows_flagged={body.get('rows_flagged') or body.get('flagged') or '?'}")
        if r.status_code >= 400:
            print(f"  ERROR: {body.get('detail') or body}")
        ingest_session_ids[label] = session_id
        results[f"{label}_ingest"] = {"status": r.status_code, "elapsed": elapsed, "session_id": session_id, "body": body}
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"  EXCEPTION: {e}")
        results[f"{label}_ingest"] = {"status": "exception", "elapsed": elapsed, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 3: deep_analyze — trigger + poll
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 3: /api/v1/csv/deep_analyze")
print("="*70)

deep_results = {}
for label in XLSX_FILES:
    sid = ingest_session_ids.get(label, "")
    all_sheets = load_all_sheets(XLSX_FILES[label])
    all_rows = []
    for sname, rows in all_sheets.items():
        for r in rows:
            r["_sheet"] = sname
            all_rows.append(r)

    payload = {
        "rows": all_rows[:200],   # cap for test speed
        "session_id": sid or None,
        "auto_llm": True,
        "tier": "tier1",
    }
    t0 = time.perf_counter()
    try:
        r = requests.post(
            f"{BASE}/api/v1/csv/deep_analyze",
            headers={**HEADERS, "Content-Type": "application/json"},
            json=payload,
            timeout=120,
        )
        elapsed = time.perf_counter() - t0
        body = r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text[:500]}
        print(f"\n[{label}] status={r.status_code}  elapsed={elapsed:.2f}s")
        da_sid = body.get("session_id") or body.get("id") or ""
        print(f"  deep_analyze session_id={da_sid}")
        print(f"  status={body.get('status') or '?'}  step={body.get('step') or body.get('current_step') or '?'}")
        # Show top-3 rows by triage_score
        llm_rows = body.get("rows") or body.get("analyzed_rows") or []
        if llm_rows:
            top3 = sorted(llm_rows, key=lambda x: float(x.get("triage_score") or 0), reverse=True)[:3]
            print(f"  total analyzed rows: {len(llm_rows)}")
            for i, row in enumerate(top3, 1):
                print(f"  TOP{i}: triage={row.get('triage_score'):.4f}  risk={row.get('risk_level',{}).get('label')}  "
                      f"factors={row.get('factors',[])}  path={str(row.get('path') or row.get('file_path') or row.get('process') or '')[:60]}")
        if r.status_code >= 400:
            print(f"  ERROR: {body.get('detail') or body}")
        deep_results[label] = {"session_id": da_sid, "status": r.status_code, "elapsed": elapsed, "body": body}
        results[f"{label}_deep_analyze"] = deep_results[label]
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"  EXCEPTION: {e}")
        deep_results[label] = {"session_id": "", "status": "exception", "elapsed": elapsed, "error": str(e)}
        results[f"{label}_deep_analyze"] = deep_results[label]


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 4: Tier 1 LLM — /api/v1/csv/insights
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 4: /api/v1/csv/insights (Tier 1 LLM)")
print("="*70)

for label in XLSX_FILES:
    da = deep_results.get(label, {})
    da_body = da.get("body", {})
    rows = da_body.get("rows") or da_body.get("analyzed_rows") or []

    if not rows:
        # Use raw rows if deep analyze returned nothing
        all_sheets = load_all_sheets(XLSX_FILES[label])
        rows = []
        for sname, srows in all_sheets.items():
            for r in srows:
                r["_sheet"] = sname
                rows.append(r)

    top_row = sorted(rows, key=lambda x: float(x.get("triage_score") or 0), reverse=True)[0] if rows else {}

    payload = {
        "row": top_row,
        "persona": "soc_analyst",
        "tier": "tier1",
    }
    t0 = time.perf_counter()
    try:
        r = requests.post(
            f"{BASE}/api/v1/csv/insights",
            headers={**HEADERS, "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        elapsed = time.perf_counter() - t0
        body = r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text[:500]}
        print(f"\n[{label}] status={r.status_code}  elapsed={elapsed:.2f}s")
        summary = body.get("summary") or body.get("insight") or body.get("text") or ""
        print(f"  Tier1 summary ({len(summary)} chars):\n  {summary[:400]}")
        dread = body.get("dread") or body.get("dread_scores") or {}
        print(f"  DREAD: {dread}")
        print(f"  MITRE: {body.get('mitre') or '?'}")
        results[f"{label}_tier1"] = {"status": r.status_code, "elapsed": elapsed, "body": body}
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"  EXCEPTION: {e}")
        results[f"{label}_tier1"] = {"status": "exception", "elapsed": elapsed, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 5: Tier 2 LLM — /api/v1/csv/deep_analyze with tier=tier2
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 5: Tier 2 — deep_analyze with tier2")
print("="*70)

for label in XLSX_FILES:
    da = deep_results.get(label, {})
    da_sid = da.get("session_id", "")
    all_sheets = load_all_sheets(XLSX_FILES[label])
    all_rows = []
    for sname, rows in all_sheets.items():
        for r in rows:
            r["_sheet"] = sname
            all_rows.append(r)

    payload = {
        "rows": all_rows[:200],
        "session_id": da_sid or None,
        "auto_llm": True,
        "tier": "tier2",
        "persona": "executive",
    }
    t0 = time.perf_counter()
    try:
        r = requests.post(
            f"{BASE}/api/v1/csv/deep_analyze",
            headers={**HEADERS, "Content-Type": "application/json"},
            json=payload,
            timeout=180,
        )
        elapsed = time.perf_counter() - t0
        body = r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text[:500]}
        print(f"\n[{label}] status={r.status_code}  elapsed={elapsed:.2f}s")
        t2_summary = body.get("tier2_summary") or body.get("narrative") or body.get("summary") or ""
        print(f"  Tier2 narrative ({len(t2_summary)} chars):\n  {str(t2_summary)[:400]}")
        results[f"{label}_tier2"] = {"status": r.status_code, "elapsed": elapsed, "body": body}
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"  EXCEPTION: {e}")
        results[f"{label}_tier2"] = {"status": "exception", "elapsed": elapsed, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 6: Report generation
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 6: Report generation")
print("="*70)

for label in XLSX_FILES:
    da = deep_results.get(label, {})
    da_sid = da.get("session_id", "")
    # Try HTML report first (PDF depends on weasyprint)
    for fmt in ("html", "pdf"):
        url = f"{BASE}/api/v1/report/ingestion?format={fmt}&include_model=true&include_scenarios=true"
        if da_sid:
            url += f"&session_id={da_sid}"
        t0 = time.perf_counter()
        try:
            r = requests.get(url, headers=HEADERS, timeout=60)
            elapsed = time.perf_counter() - t0
            ct = r.headers.get("content-type", "")
            size = len(r.content)
            print(f"\n[{label}] {fmt.upper()} report: status={r.status_code}  {elapsed:.2f}s  {size} bytes  ct={ct}")
            if r.status_code == 200 and fmt == "html":
                # Save sample
                out = os.path.join(DUMP, f"_e2e_report_{label}.html")
                with open(out, "wb") as fh:
                    fh.write(r.content)
                print(f"  Saved → {out}")
            elif r.status_code == 200 and fmt == "pdf":
                out = os.path.join(DUMP, f"_e2e_report_{label}.pdf")
                with open(out, "wb") as fh:
                    fh.write(r.content)
                print(f"  Saved PDF → {out}  ({size/1024:.1f} KB)")
            elif r.status_code >= 400:
                body = r.json() if "json" in ct else {"raw": r.text[:300]}
                print(f"  ERROR: {body.get('detail') or body}")
            results[f"{label}_report_{fmt}"] = {"status": r.status_code, "elapsed": elapsed, "size": size}
        except Exception as e:
            elapsed = time.perf_counter() - t0
            print(f"  EXCEPTION {fmt}: {e}")
            results[f"{label}_report_{fmt}"] = {"status": "exception", "elapsed": elapsed, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 7: PageRank / DREAD audit — per-row scoring check
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 7: Per-row triage/DREAD/PageRank audit")
print("="*70)

for label in XLSX_FILES:
    all_sheets = load_all_sheets(XLSX_FILES[label])
    sample_rows = []
    for sname, rows in all_sheets.items():
        sample_rows.extend(rows[:5])

    print(f"\n[{label}] Scoring {len(sample_rows)} sample rows via /api/v1/csv/analyze_row")
    scored = []
    for row in sample_rows[:10]:
        t0 = time.perf_counter()
        try:
            r = requests.post(
                f"{BASE}/api/v1/csv/analyze_row",
                headers={**HEADERS, "Content-Type": "application/json"},
                json={"row": row},
                timeout=15,
            )
            elapsed = time.perf_counter() - t0
            if r.status_code == 200:
                body = r.json()
                scored.append({
                    "row_preview": str(list(row.values())[:3])[:60],
                    "risk_score": body.get("risk_score"),
                    "triage_score": body.get("triage_score"),
                    "final_decision": body.get("final_decision"),
                    "dread": body.get("dread", {}),
                    "mitre": body.get("mitre", []),
                    "elapsed": elapsed,
                })
            else:
                scored.append({"row_preview": str(list(row.values())[:3])[:60],
                               "error": r.status_code, "detail": r.text[:200]})
        except Exception as e:
            scored.append({"row_preview": "exception", "error": str(e)})

    for s in scored:
        dread_composite = ""
        if isinstance(s.get("dread"), dict):
            dread_composite = s["dread"].get("composite") or s["dread"].get("risk_score") or s["dread"].get("score") or ""
        print(f"  row={s['row_preview'][:50]}  risk={s.get('risk_score')}  "
              f"triage={s.get('triage_score')}  dread={dread_composite}  "
              f"decision={s.get('final_decision')}  t={s.get('elapsed',0):.3f}s")
    results[f"{label}_per_row_audit"] = scored


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("SUMMARY — Latency by Stage")
print("="*70)
for k, v in results.items():
    if isinstance(v, list):
        continue   # per_row_audit is a list, skip
    elapsed = v.get("elapsed") or 0
    status = v.get("status")
    err = v.get("error") or ""
    print(f"  {k:45s}  status={status}  t={elapsed:.2f}s  {err[:60]}")

# Save full results
out_json = os.path.join(DUMP, "_e2e_pipeline_results.json")
with open(out_json, "w", encoding="utf-8") as fh:
    slim = {}
    for k, v in results.items():
        if isinstance(v, list):
            slim[k] = v
        else:
            slim[k] = {kk: vv for kk, vv in v.items() if kk != "body"}
    json.dump(slim, fh, indent=2, default=str)
print(f"\nResults saved → {out_json}")

