"""Quick script to check if CodeGuardian is using NIM LLM (online) or offline templates."""
import requests
import json
import sys

BASE = "http://127.0.0.1:8000"

# 1. Health check
try:
    r = requests.get(f"{BASE}/health", timeout=5)
    print(f"[1] Server health: {r.json()}")
except Exception as e:
    print(f"[1] Server is NOT running: {e}")
    sys.exit(1)

# 2. Upload a small test file and inspect the response
print("\n[2] Uploading input/test_secrets.py to /upload ...")
with open("input/test_secrets.py", "rb") as f:
    r = requests.post(f"{BASE}/upload", files={"files": ("test_secrets.py", f)}, timeout=120)

data = r.json()
# /upload wraps results in a list
if "results" in data and data["results"]:
    data = data["results"][0]
enriched = data.get("enriched", "N/A")
llm_mode = data.get("llm_mode", "N/A")

print(f"    enriched : {enriched}")
print(f"    llm_mode : {llm_mode}")

if llm_mode == "nim" and enriched:
    print("\n    >>> LLM is ONLINE (NIM inference + embedding active) <<<")
else:
    print("\n    >>> LLM is OFFLINE (using local templates) <<<")

# Extract issues — enriched responses nest them under results -> filename -> list
issues = data.get("issues", [])
if not issues:
    # enriched format: results is a dict { filename: [ {issue_dict}, ... ] }
    results_dict = data.get("results", {})
    if isinstance(results_dict, dict):
        for fname, file_issues in results_dict.items():
            if isinstance(file_issues, list):
                issues.extend(file_issues)

print(f"\n[3] Issues found: {len(issues)}")
for i, issue in enumerate(issues, 1):
    llm_used = issue.get("llm_used", "N/A")
    explanation = issue.get("explanation", "")
    short_exp = (explanation[:150] + "...") if len(explanation) > 150 else explanation
    print(f"    Issue {i}: {issue.get('type', issue.get('issue', '?'))}")
    print(f"      severity    : {issue.get('severity', 'N/A')}")
    print(f"      llm_used    : {llm_used}")
    print(f"      explanation  : {short_exp}")
    print()

# Summary
summary = data.get("summary", {})
if summary:
    print(f"[4] Summary: risk={summary.get('risk_level','?')}, score={summary.get('risk_score','?')}")
