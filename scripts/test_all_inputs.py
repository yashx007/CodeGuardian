"""Quick test: send each input/* file to /upload and print detected issues."""
import requests
import json
import os

BASE = "http://127.0.0.1:8000"
INPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "input")

test_files = [
    "test_secrets.py",
    "test_insecure.py",
    "test_cpp.cpp",
    "test_js.js",
    "test_sql.py",
]

for fname in test_files:
    path = os.path.join(INPUT_DIR, fname)
    if not os.path.exists(path):
        print(f"\n=== {fname} === FILE NOT FOUND")
        continue
    code = open(path, "r", encoding="utf-8").read()
    r = requests.post(f"{BASE}/upload", data={"code": code, "filename": fname}, timeout=120)
    data = r.json()
    results = data.get("results", [])
    print(f"\n=== {fname} ===")
    for res in results:
        enriched = res.get("enriched", False)
        llm_mode = res.get("llm_mode", "unknown")
        if enriched:
            print(f"  [enriched=True, llm_mode={llm_mode}]")
            file_results = res.get("results", {})
            for file_key, issues in file_results.items():
                for iss in issues:
                    sev = iss.get("severity", "?")
                    typ = iss.get("type", "?")
                    used = iss.get("llm_used", "?")
                    print(f"  [{sev}] {typ}  (llm_used={used})")
            summary = res.get("summary", {})
            if summary:
                print(f"  Summary: risk={summary.get('risk')}, total={summary.get('total_issues')}, score={summary.get('score')}")
        else:
            issues = res.get("issues", [])
            if issues:
                for iss in issues:
                    print(f"  - {iss['issue']}")
            else:
                issue = res.get("issue", "N/A")
                print(f"  - {issue}")
    if not results:
        print("  (no results)")
