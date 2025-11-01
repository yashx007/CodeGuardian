import os
import json
from pathlib import Path
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / '.env')
except Exception:
    pass

# map BASE_URL if present
if 'BASE_URL' in os.environ and 'NIM_BASE_URL' not in os.environ:
    os.environ['NIM_BASE_URL'] = os.environ['BASE_URL']

inference = os.environ.get('NIM_INFERENCE_URL')
base_env = os.environ.get('NIM_BASE_URL')
if not inference and base_env:
    base = base_env.rstrip('/')
    if not base.endswith('/v1'):
        base = base + '/v1'
    inference = base + '/chat/completions'
api_key = os.environ.get('NIM_API_KEY_INFERENCE') or os.environ.get('NIM_API_KEY')
print('probing:', inference)
if not inference:
    print('no inference URL configured')
    raise SystemExit(1)

try:
    import requests
except Exception:
    print('requests missing')
    raise

headers = {'Content-Type':'application/json'}
if api_key:
    headers['Authorization'] = f'Bearer {api_key}'

payload = {'model': os.environ.get('NIM_INFERENCE_MODEL','llama-3.1-nemotron-nano-8b-v1'), 'messages':[{'role':'user','content':'test'}], 'max_tokens':64}

r = requests.post(inference, json=payload, headers=headers, timeout=10)
print('status_code=', r.status_code)
print('response_snippet=', r.text[:800])
