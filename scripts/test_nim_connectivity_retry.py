import os, traceback
from agent.nim_client import NIMClient

base = os.environ.get('NIM_BASE_URL')
if not base:
    print('NIM_BASE_URL not set')
    raise SystemExit(1)

# strip leading vendor prefix if present
emb_model = os.environ.get('NIM_EMBEDDING_MODEL','').split('/')[-1]
inf_model = os.environ.get('NIM_INFERENCE_MODEL','').split('/')[-1]
emb_url = f"{base.rstrip('/')}/models/{emb_model}/embeddings"
inf_url = f"{base.rstrip('/')}/models/{inf_model}/infer"
print('Trying embedding_url:', emb_url)
print('Trying inference_url:', inf_url)
client = NIMClient(inference_url=inf_url, embedding_url=emb_url)

try:
    e = client.embed(['hello world'])
    print('Embed OK, len=', len(e), 'vec_len=', len(e[0]) if e else 'n/a')
except Exception:
    print('Embed failed:')
    traceback.print_exc()

try:
    out = client.explain('One sentence about SQL injection', max_tokens=80)
    print('Infer OK, out=', out[:400])
except Exception:
    print('Infer failed:')
    traceback.print_exc()
