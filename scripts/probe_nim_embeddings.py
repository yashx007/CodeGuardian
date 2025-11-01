import os
from pathlib import Path
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / '.env')
except Exception:
    pass

if 'BASE_URL' in os.environ and 'NIM_BASE_URL' not in os.environ:
    os.environ['NIM_BASE_URL'] = os.environ['BASE_URL']

embedding_url = os.environ.get('NIM_EMBEDDING_URL')
base_env = os.environ.get('NIM_BASE_URL')
if not embedding_url and base_env:
    base = base_env.rstrip('/')
    if not base.endswith('/v1'):
        base = base + '/v1'
    embedding_url = base + '/embeddings'

if not embedding_url:
    print('no embeddings URL configured')
    raise SystemExit(1)

api_key = os.environ.get('NIM_API_KEY_EMBEDDING') or os.environ.get('NIM_API_KEY')
print('probing embeddings:', embedding_url)

try:
    import requests
except Exception:
    print('requests missing')
    raise

headers = {'Content-Type': 'application/json'}
if api_key:
    headers['Authorization'] = f'Bearer {api_key}'

payload = {
    'model': os.environ.get('NIM_EMBEDDING_MODEL','nvidia/nv-embedcode-7b-v1'),
    'input': ['test embedding'],
    'input_type': 'query'
}

try:
    r = requests.post(embedding_url, json=payload, headers=headers, timeout=15)
    print('status_code=', r.status_code)
    text = r.text
    print('response_snippet=', text[:800])
except Exception as e:
    print('error calling embeddings endpoint:', e)
    raise
