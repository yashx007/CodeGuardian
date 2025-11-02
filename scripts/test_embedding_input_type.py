import os, requests, traceback

BASE = os.environ.get('NIM_BASE_URL', 'https://integrate.api.nvidia.com').rstrip('/') + '/v1'
EMB_MODEL = os.environ.get('NIM_EMBEDDING_MODEL', 'nvidia/nv-embedcode-7b-v1')
EMB_KEY = os.environ.get('NIM_API_KEY_EMBEDDING') or os.environ.get('NIM_API_KEY')

emb_url = f"{BASE}/embeddings"
headers = {'Content-Type': 'application/json'}
if EMB_KEY:
    headers['Authorization'] = 'Bearer ' + EMB_KEY

payload = {
    "model": EMB_MODEL,
    "input": ["hello world"],
    "input_type": "query",
    "encoding_format": "float",
    "truncate": "NONE"
}

print('POST', emb_url)
print('Headers:', headers)
try:
    r = requests.post(emb_url, json=payload, headers=headers, timeout=20)
    print('Status:', r.status_code)
    try:
        data = r.json()
        print('JSON response (first 800 chars):')
        import json
        print(json.dumps(data, indent=2)[:800])
        # try to extract embedding
        if isinstance(data, dict):
            if 'embeddings' in data:
                emb = data['embeddings']
                print('Got embeddings count:', len(emb))
            elif 'data' in data:
                items = data['data']
                if items and isinstance(items, list) and 'embedding' in items[0]:
                    print('Got embeddings via data[0]["embedding"], length:', len(items[0]['embedding']))
    except Exception:
        print('Response not JSON:')
        print(r.text[:800])
except Exception:
    print('Request failed:')
    traceback.print_exc()
