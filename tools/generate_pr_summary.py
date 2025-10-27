"""Generate a short markdown PR summary from scan_results.json or results.sarif.

Usage:
  python tools/generate_pr_summary.py scan_results.json > pr_summary.md
"""
import json
import sys
from pathlib import Path

input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('scan_results.json')
if not input_path.exists():
    print('# CodeGuardian scan — no results found')
    sys.exit(0)

data = json.load(open(input_path))

# data may be flat list or dict mapping file->issues
issues = []
if isinstance(data, list):
    issues = data
elif isinstance(data, dict):
    for fp, its in data.items():
        for it in its:
            it2 = dict(it)
            it2['file'] = fp
            issues.append(it2)

# summarize counts by type
from collections import Counter
cnt = Counter(it.get('type','') for it in issues)

lines = []
lines.append('# CodeGuardian Scan Summary')
lines.append('')
lines.append('## Findings')
lines.append('')
if not issues:
    lines.append('No issues found.')
else:
    for k,v in cnt.most_common():
        lines.append(f'- **{k}**: {v}')
    lines.append('')
    lines.append('### Top 10 issues')
    lines.append('')
    for it in issues[:10]:
        file = it.get('file')
        typ = it.get('type')
        line = it.get('line') or it.get('startLine')
        msg = it.get('message')
        snippet = it.get('snippet','')
        lines.append(f'- {typ} in `{file}`:{line} — {msg}  \n  ```\n  {snippet}\n  ```')

print('\n'.join(lines))
