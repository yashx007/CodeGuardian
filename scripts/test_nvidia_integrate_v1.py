"""Connectivity test for NVIDIA 'integrate' v1 endpoints.

Writes concise, sanitized output. Uses env vars in the current shell:
- NIM_BASE_URL (optional, defaults to https://integrate.api.nvidia.com/v1)
- NIM_API_KEY_EMBEDDING
- NIM_API_KEY_INFERENCE
- NIM_EMBEDDING_MODEL (defaults to nvidia/nv-embedcode-7b-v1)
- NIM_INFERENCE_MODEL (defaults to nvidia/llama-3.1-nemotron-nano-8b-v1)

Run: python scripts/test_nvidia_integrate_v1.py
"""
import os
import requests
import json
import traceback

BASE = os.environ.get('NIM_BASE_URL', 'https://integrate.api.nvidia.com')
BASE = BASE.rstrip('/') + '/v1'
EMB_KEY = os.environ.get('NIM_API_KEY_EMBEDDING') or os.environ.get('NIM_API_KEY')
INF_KEY = os.environ.get('NIM_API_KEY_INFERENCE') or os.environ.get('NIM_API_KEY')
EMB_MODEL = os.environ.get('NIM_EMBEDDING_MODEL', 'nvidia/nv-embedcode-7b-v1')
INF_MODEL = os.environ.get('NIM_INFERENCE_MODEL', 'nvidia/llama-3.1-nemotron-nano-8b-v1')


def short(x, n=800):
    s = x if isinstance(x, str) else json.dumps(x)
    return s if len(s) <= n else s[:n] + '... [truncated]'


print('Using base v1 url:', BASE)
print('Embedding model:', EMB_MODEL)
print('Inference model:', INF_MODEL)
print()

# Embedding test
try:
    emb_url = f"{BASE}/embeddings"
    headers = {'Content-Type': 'application/json'}
    if EMB_KEY:
        headers['Authorization'] = 'Bearer ' + EMB_KEY
    payload = {"model": EMB_MODEL, "input": ["hello world"], "input_type": "query", "encoding_format": "float"}
    print('POST', emb_url)
    r = requests.post(emb_url, json=payload, headers=headers, timeout=15)
    print('Status:', r.status_code)
    print('Response (sanitized):')
    print(short(r.text))
except Exception:
    print('Embedding request failed:')
    traceback.print_exc()

print('\n' + '='*60 + '\n')

# Inference test (chat/completions)
try:
    chat_url = f"{BASE}/chat/completions"
    headers = {'Content-Type': 'application/json'}
    if INF_KEY:
        headers['Authorization'] = 'Bearer ' + INF_KEY
    payload = {
        "model": INF_MODEL,
        "messages": [{"role": "system", "content": "You are concise."}, {"role": "user", "content": "Explain SQL injection in one sentence."}],
        "max_tokens": 200,
        "temperature": 0,
    }
    print('POST', chat_url)
    r = requests.post(chat_url, json=payload, headers=headers, timeout=20)
    print('Status:', r.status_code)
    print('Response (sanitized):')
    print(short(r.text))
except Exception:
    print('Inference request failed:')
    traceback.print_exc()
