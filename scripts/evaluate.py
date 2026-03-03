"""Run a lightweight offline evaluation of CodeGuardian.

This script scans a set of sample files in `input/`, produces Stage2 findings
and Stage3 enrichments, and writes a JSON report to `evaluation/evaluation_results.json`.

Usage:
    python scripts/evaluate.py

It does not call any external LLMs by default (uses the configured Reasoner).
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Ensure project root is on sys.path when script is executed from scripts/
sys.path.insert(0, str(ROOT))

from agent import parser as stage2_parser
from agent.reasoning import reasoner
INPUT_DIR = ROOT / "input"
OUT_DIR = ROOT / "evaluation"
OUT_DIR.mkdir(exist_ok=True)
OUT_FILE = OUT_DIR / "evaluation_results.json"

# Sample files to evaluate; pick a mix that's present in repo
SAMPLES = [
    "test_cpp.cpp",
    "test_js.js",
    "test_secrets.py",
    "test_sql.py",
    "test_insecure.py",
]

results = {}
summary = {"total_files": 0, "total_issues": 0, "by_severity": {}}

for fname in SAMPLES:
    path = INPUT_DIR / fname
    if not path.exists():
        print(f"Skipping missing sample: {fname}")
        continue
    print(f"Analyzing {fname}...")
    # Stage2: static analysis
    try:
        issues = stage2_parser.analyze_code(str(path))
    except Exception as e:
        issues = [{"error": str(e)}]
    # Stage3: enrich
    enriched = reasoner.enrich({fname: issues})
    results[fname] = enriched

    summary["total_files"] += 1
    total = enriched.get("summary", {}).get("total_issues", 0)
    summary["total_issues"] += total
    counts = enriched.get("summary", {}).get("counts", {}) or {}
    for sev, cnt in counts.items():
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + cnt

out = {"summary": summary, "results": results}

with OUT_FILE.open("w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)

print("Wrote evaluation results to:", OUT_FILE)
print(json.dumps(summary, indent=2))
