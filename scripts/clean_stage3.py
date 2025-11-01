import json
import re
import sys
from pathlib import Path

def is_valid_url(u: str) -> bool:
    # Basic URL validation using regex and parse
    if not isinstance(u, str):
        return False
    u = u.strip()
    # must start with http or https
    if not re.match(r'^https?://', u, re.IGNORECASE):
        return False
    # simple no-spaces check
    if '\\s' in u:
        return False
    # domain check
    m = re.match(r'^https?://([^/\s]+)', u)
    return bool(m and '.' in m.group(1))

def sanitize_text(s: str) -> str:
    if not isinstance(s, str):
        return s
    # remove control chars except common whitespace
    s = ''.join(ch for ch in s if ch.isprintable())
    # collapse multiple spaces
    s = re.sub(r'[ \t]+', ' ', s)
    # strip leading/trailing whitespace
    return s.strip()

def normalize_reference(ref):
    # Return (normalized_obj or None)
    if isinstance(ref, str):
        ref_s = sanitize_text(ref)
        if is_valid_url(ref_s):
            return {'url': ref_s}
        return None
    if isinstance(ref, dict):
        url = ref.get('url') or ref.get('link') or ref.get('href')
        if url and is_valid_url(url):
            out = {'url': sanitize_text(url)}
            # capture a short description if present
            desc = ref.get('description') or ref.get('name')
            if desc:
                out['description'] = sanitize_text(desc)
            return out
        return None
    return None

def clean_stage3(in_path: Path, out_path: Path):
    doc = json.loads(in_path.read_text(encoding='utf-8'))
    removed_refs = 0
    normalized = 0

    results = doc.get('results', {})
    for file, issues in results.items():
        for issue in issues:
            # sanitize strings in selected fields
            for key in ('explanation','fix','message','snippet'):
                if key in issue:
                    issue[key] = sanitize_text(issue[key])

            # normalize references
            refs = issue.get('references') or []
            new_refs = []
            for r in refs:
                nr = normalize_reference(r)
                if nr:
                    new_refs.append(nr)
                    if isinstance(r, str):
                        normalized += 1
                    else:
                        # if dict and cleaned/described
                        normalized += 1
                else:
                    removed_refs += 1
            issue['references'] = new_refs

    # write cleaned file
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding='utf-8')
    return {'removed_refs': removed_refs, 'normalized_refs': normalized}

def main():
    if len(sys.argv) < 2:
        print('usage: python scripts/clean_stage3.py <input.json> [output.json]')
        raise SystemExit(1)
    in_path = Path(sys.argv[1])
    if not in_path.exists():
        print('input not found:', in_path)
        raise SystemExit(1)
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else in_path.with_name(in_path.stem + '.cleaned.json')
    stats = clean_stage3(in_path, out_path)
    print('wrote:', out_path)
    print('stats:', stats)

if __name__ == '__main__':
    main()
