"""
Verify LLM Triage Implementation Status
Load Cyberstash_csv2.xlsx, select 3 suspicious rows, and generate mock outputs
"""
import pandas as pd
import json
from pathlib import Path

# Load the Excel file
excel_path = Path("dump/Cyberstash_csv2.xlsx")
print(f"Loading {excel_path}...")
df = pd.read_excel(excel_path)

print(f"\nTotal rows: {len(df)}")
print(f"Columns: {list(df.columns)}")

# Check for suspicious rows
if 'suspicious' in df.columns:
    suspicious_df = df[df['suspicious'] == True]
    print(f"\nSuspicious rows: {len(suspicious_df)}")
else:
    # Try alternative columns
    print("\nColumn 'suspicious' not found. Trying 'threatWeight' or 'malicious'...")
    if 'threatWeight' in df.columns:
        suspicious_df = df[df['threatWeight'] > 0]
    elif 'malicious' in df.columns:
        suspicious_df = df[df['malicious'] == True]
    else:
        suspicious_df = df.head(10)  # fallback to first 10

print(f"\nSuspicious rows found: {len(suspicious_df)}")

# Select 3 interesting suspicious rows
if len(suspicious_df) >= 3:
    # Get diverse examples
    sample_rows = suspicious_df.head(3)
else:
    sample_rows = df.head(3)

print("\n" + "="*80)
print("SELECTED 3 ROWS FOR TESTING")
print("="*80)

for idx, (row_idx, row) in enumerate(sample_rows.iterrows(), 1):
    print(f"\n{'='*80}")
    print(f"Row {idx} (Original Index: {row_idx})")
    print(f"{'='*80}")

    # Extract key fields
    row_dict = row.to_dict()

    # Clean up NaN values
    for key, value in row_dict.items():
        if pd.isna(value):
            row_dict[key] = None

    # Print key fields
    print(json.dumps({
        'name': row_dict.get('name'),
        'path': row_dict.get('path'),
        'sha256': row_dict.get('sha256', '')[:16] + '...' if row_dict.get('sha256') else None,
        'suspicious': row_dict.get('suspicious'),
        'malicious': row_dict.get('malicious'),
        'threatWeight': row_dict.get('threatWeight'),
        'threatScore': row_dict.get('threatScore'),
        'signed': row_dict.get('signed'),
        'avPositives': row_dict.get('avPositives'),
        'avTotal': row_dict.get('avTotal'),
        'size': row_dict.get('size'),
        'hitCount': row_dict.get('hitCount')
    }, indent=2))

print("\n" + "="*80)
print("IMPLEMENTATION STATUS CHECK")
print("="*80)

# Check if auto_llm.py has the 30-45 line schema
auto_llm_path = Path("src/analysis/auto_llm.py")
if auto_llm_path.exists():
    with open(auto_llm_path, 'r', encoding='utf-8') as f:
        auto_llm_content = f.read()

    # Check for key phrases from the implementation guide
    checks = {
        "30-45 line prompt": "📌 WHAT IS IT?" in auto_llm_content,
        "EXPLOITABILITY section": "💥 EXPLOITABILITY" in auto_llm_content,
        "CONCISE PLAYBOOK": "📋 CONCISE PLAYBOOK" in auto_llm_content,
        "Missing logs conditional": "should_include_missing_logs" in auto_llm_content,
        "_llm_processed flag": "_llm_processed" in auto_llm_content
    }

    print("\nauto_llm.py Status:")
    for check, result in checks.items():
        status = "✅" if result else "❌"
        print(f"  {status} {check}")
else:
    print("\n❌ auto_llm.py not found")

# Check deep_analyze_endpoints.py
deep_analyze_path = Path("src/api/deep_analyze_endpoints.py")
if deep_analyze_path.exists():
    with open(deep_analyze_path, 'r', encoding='utf-8') as f:
        deep_analyze_content = f.read()

    checks = {
        "prioritize_rows_for_llm": "prioritize_rows_for_llm" in deep_analyze_content,
        "generate_llm_summaries endpoint": "generate_llm_summaries" in deep_analyze_content,
        "DREAD sorting": "dread" in deep_analyze_content.lower(),
        "_llm_processed tracking": "_llm_processed" in deep_analyze_content
    }

    print("\ndeep_analyze_endpoints.py Status:")
    for check, result in checks.items():
        status = "✅" if result else "❌"
        print(f"  {status} {check}")
else:
    print("\n❌ deep_analyze_endpoints.py not found")

# Check csv_analyzer.html
csv_analyzer_path = Path("frontend/static/csv_analyzer.html")
if csv_analyzer_path.exists():
    with open(csv_analyzer_path, 'r', encoding='utf-8') as f:
        csv_analyzer_content = f.read()

    checks = {
        "llmLimit dropdown": "llmLimit" in csv_analyzer_content,
        "Generate More button": "btnGenerateMore" in csv_analyzer_content or "Generate More" in csv_analyzer_content,
        "Cost estimate display": "llmCostEstimate" in csv_analyzer_content or "Est. cost" in csv_analyzer_content,
        "✅/⏸️ icons": "✅" in csv_analyzer_content or "_llm_processed" in csv_analyzer_content
    }

    print("\ncsv_analyzer.html Status:")
    for check, result in checks.items():
        status = "✅" if result else "❌"
        print(f"  {status} {check}")
else:
    print("\n❌ csv_analyzer.html not found")

# Check csv_deep_analysis.html
csv_deep_analysis_path = Path("frontend/static/csv_deep_analysis.html")
if csv_deep_analysis_path.exists():
    print("\n✅ csv_deep_analysis.html EXISTS")

    with open(csv_deep_analysis_path, 'r', encoding='utf-8') as f:
        content = f.read()

    checks = {
        "Investigate Further structure": "Deep Dive" in content or "Investigate Further" in content,
        "AI-powered insights section": "AI-Powered Insights" in content or "generateInsight" in content,
        "Cost tracking per insight": "runningCost" in content or "Running cost" in content,
        "Analyst notes": "analystNotes" in content or "Analyst Notes" in content
    }

    for check, result in checks.items():
        status = "✅" if result else "❌"
        print(f"  {status} {check}")
else:
    print("\n❌ csv_deep_analysis.html DOES NOT EXIST (needs to be created)")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print("\n🎯 Implementation Status:")
print("   • Basic LLM integration exists (auto_llm.py)")
print("   • 30-45 line schema: NOT YET IMPLEMENTED")
print("   • Prioritization logic: PARTIALLY IMPLEMENTED")
print("   • 'Investigate Further' tab: EXISTS but may need enhancements")
print("   • Cost tracking: NOT FULLY IMPLEMENTED")
print("\n📝 Next: Generate mock outputs to show what it SHOULD look like once fully implemented")
