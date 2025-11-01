from pathlib import Path
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / '.env')
except Exception:
    pass

from agent.nim_client import NIMClient
import os

# Some users include spaces around '=' or quotes in .env files. To be robust here
# we manually parse the repo .env and set os.environ for any entries we find.
env_path = Path(__file__).parent.parent / '.env'
if env_path.exists():
    try:
        with env_path.open('r', encoding='utf-8') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                if '=' not in ln:
                    continue
                k, v = ln.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                # populate environment (don't overwrite existing keys)
                if k and v and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass

c = NIMClient()
# If user provided BASE_URL in .env, map it to NIM_BASE_URL for compatibility
if 'BASE_URL' in os.environ and 'NIM_BASE_URL' not in os.environ:
    os.environ['NIM_BASE_URL'] = os.environ['BASE_URL']
    # re-create client so it picks up mapped value
    c = NIMClient()
print('inference_url=', c.inference_url)
print('embedding_url=', c.embedding_url)
print('supports_embeddings=', c.supports_embeddings)

h = c.check_health()
print('health:', h if h else 'no health')

m = c.list_models()
print('models:', 'ok' if m else 'none')

resp = None
try:
    resp = c.chat_completion('Hello from CodeGuardian - please respond with a short sentence identifying the responder', max_tokens=80)
except Exception as e:
    print('chat_completion exception:', e)

print('chat_response_present=', bool(resp))
if resp and isinstance(resp, dict):
    ch = resp.get('choices')
    if isinstance(ch, list) and ch:
        first = ch[0]
        if isinstance(first, dict):
            if 'message' in first and isinstance(first['message'], dict) and 'content' in first['message']:
                print('first_choice:', first['message']['content'][:400])
            elif 'text' in first:
                print('first_choice_text:', str(first['text'])[:400])
            else:
                print('first_choice_raw:', str(first)[:400])
    else:
        print('resp_raw:', str(resp)[:400])
else:
    print('no usable response')
    
print('\n-- parsed env preview --')
for key in ['CODEGUARDIAN_LLM_MODE', 'NIM_BASE_URL', 'NIM_INFERENCE_URL', 'NIM_EMBEDDING_URL', 'NIM_API_KEY', 'NIM_API_KEY_INFERENCE', 'NIM_API_KEY_EMBEDDING']:
    val = os.environ.get(key)
    if val:
        if 'KEY' in key or 'API' in key:
            print(key + '=<present>')
        else:
            print(f"{key}={val}")
    else:
        print(key + '=<missing>')
