"""Probe NIM header formats for embeddings and chat endpoints.

Tries different header shapes and prints the headers sent and the server response.
Stops early for a 200 OK.
"""
import os
import requests
import json
import traceback

BASE = os.environ.get('NIM_BASE_URL', 'https://integrate.api.nvidia.com').rstrip('/') + '/v1'
EMB_MODEL = os.environ.get('NIM_EMBEDDING_MODEL', 'nvidia/nv-embedcode-7b-v1')
INF_MODEL = os.environ.get('NIM_INFERENCE_MODEL', 'nvidia/llama-3.1-nemotron-nano-8b-v1')
EMB_KEY = os.environ.get('NIM_API_KEY_EMBEDDING') or os.environ.get('NIM_API_KEY')
INF_KEY = os.environ.get('NIM_API_KEY_INFERENCE') or os.environ.get('NIM_API_KEY')

emb_url = f"{BASE}/embeddings"
chat_url = f"{BASE}/chat/completions"

header_variants = [
    ("Authorization: Bearer", lambda k: {"Authorization": f"Bearer {k}"}),
    ("Authorization: ApiKey", lambda k: {"Authorization": f"ApiKey {k}"}),
    ("Authorization: Key", lambda k: {"Authorization": f"Key {k}"}),
    ("x-api-key", lambda k: {"x-api-key": k}),
    ("api-key", lambda k: {"api-key": k}),
]


def short(s, n=600):
    s = s or ''
    return s if len(s) <= n else s[:n] + '... [truncated]'


def try_request(url, headers, payload):
    print('\n-> Request URL:', url)
    print('-> Headers sent:', headers)
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=20)
        print('-> Status code:', r.status_code)
        body = r.text
        print('-> Response body (sanitized):\n', short(body))
        return r.status_code
    except Exception:
        print('-> Request failed:')
        traceback.print_exc()
        return None


def main():
    if not EMB_KEY and not INF_KEY:
        print('No API keys found in env (NIM_API_KEY_EMBEDDING / NIM_API_KEY_INFERENCE / NIM_API_KEY). Aborting.')
        return

    # Embedding test
    if EMB_KEY:
        print('=== Embedding endpoint probe ===')
        emb_payload = {"model": EMB_MODEL, "input": ["hello world"], "encoding_format": "float"}
        for name, fn in header_variants:
            hdr = fn(EMB_KEY)
            hdr['Content-Type'] = 'application/json'
            print('\n-- Trying header variant:', name)
            status = try_request(emb_url, hdr, emb_payload)
            if status == 200:
                print('Embedding succeeded with header:', name)
                break
    else:
        print('Skipping embedding probe (no embedding key)')

    # Chat/completions test
    if INF_KEY:
        print('\n=== Chat/completions endpoint probe ===')
        chat_payload = {
            "model": INF_MODEL,
            "messages": [{"role": "system", "content": "You are concise."}, {"role": "user", "content": "Explain SQL injection in one sentence."}],
            "max_tokens": 80,
        }
        for name, fn in header_variants:
            hdr = fn(INF_KEY)
            hdr['Content-Type'] = 'application/json'
            print('\n-- Trying header variant:', name)
            status = try_request(chat_url, hdr, chat_payload)
            if status == 200:
                print('Inference succeeded with header:', name)
                break
    else:
        print('Skipping inference probe (no inference key)')


if __name__ == '__main__':
    main()
