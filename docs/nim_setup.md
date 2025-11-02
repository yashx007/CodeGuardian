NIM setup for CodeGuardian

This document explains how to configure NVIDIA NIM endpoints for CodeGuardian, and how to enable the `nv-embedcode-7b-v1` embedding model.


Environment variables

- `CODEGUARDIAN_LLM_MODE`: set to `nim` to enable online mode in the LLM client.
- `NIM_API_KEY`: optional global API key/token for your NIM deployment (fallback only).
- `NIM_API_KEY_EMBEDDING`: API key/token to use specifically for embedding requests (recommended if you have separate keys).
- `NIM_API_KEY_INFERENCE`: API key/token to use specifically for inference requests (recommended if you have separate keys).
- `NIM_BASE_URL`: base URL for your NIM host (e.g. `https://nim.example.com`).
- `NIM_EMBEDDING_MODEL`: model name for embeddings. Default used by the code is `nv-embedcode-7b-v1`.
- `NIM_INFERENCE_MODEL`: model name for inference (e.g., `llama-3.1-nemotron-nano-4b-v1.1` or `llama-3.1-nemotron-nano-8b-v1`).

You can instead provide explicit endpoints:
- NIM_EMBEDDING_URL: full embedding endpoint URL
- NIM_INFERENCE_URL: full inference endpoint URL

Default URL patterns

If you set `NIM_BASE_URL` and `NIM_EMBEDDING_MODEL` / `NIM_INFERENCE_MODEL` the client will construct endpoints using these patterns:

- Embedding: {NIM_BASE_URL}/models/{NIM_EMBEDDING_MODEL}/embeddings
- Inference: {NIM_BASE_URL}/models/{NIM_INFERENCE_MODEL}/infer

PowerShell example (current session)

```powershell
$env:CODEGUARDIAN_LLM_MODE = "nim"
$env:NIM_BASE_URL = "https://nim.example.com"
$env:NIM_EMBEDDING_MODEL = "nv-embedcode-7b-v1"
$env:NIM_INFERENCE_MODEL = "llama-3.1-nemotron-nano-4b-v1.1"
$env:NIM_API_KEY = "sk_..."
$env:NIM_API_KEY_EMBEDDING = "nvapi-..."
$env:NIM_API_KEY_INFERENCE = "nvapi-..."
```

Or provide full URLs:

```powershell
$env:NIM_EMBEDDING_URL = "https://nim.example.com/models/nv-embedcode-7b-v1/embeddings"
$env:NIM_INFERENCE_URL = "https://nim.example.com/models/llama-3.1-nemotron-nano-4b-v1.1/infer"
$env:NIM_API_KEY = "sk_..."

Persisting keys (.env and PowerShell)

For local development you can store keys in a `.env` file (recommended for dev only). Example `.env` entries:

```env
CODEGUARDIAN_LLM_MODE=nim
NIM_BASE_URL=https://nim.example.com
NIM_EMBEDDING_MODEL=nv-embedcode-7b-v1
NIM_INFERENCE_MODEL=llama-3.1-nemotron-nano-8b-v1
NIM_API_KEY_EMBEDDING=nvapi-<your-embedding-key>
NIM_API_KEY_INFERENCE=nvapi-<your-inference-key>
# optional fallback
NIM_API_KEY=nvapi-<fallback-key>
```

Add `python-dotenv` to your environment and load `.env` early in the app startup (the repo TODO plans to add this). Example Python snippet to load on startup:

```py
from dotenv import load_dotenv
load_dotenv()  # reads .env into the process environment
```

If you prefer PowerShell persistence across sessions, use `setx` (note: setx writes to user environment and requires a new shell to take effect):

```powershell
setx NIM_API_KEY_EMBEDDING "nvapi-..."
setx NIM_API_KEY_INFERENCE "nvapi-..."
```
```

Notes

- The code expects embedding responses in one of these shapes:
  - `{"embeddings": [[...], ...]}`
  - `{"data": [{"embedding": [...]}, ...]}`

- The inference endpoint is expected to accept a JSON payload like `{"prompt": "...", "max_tokens": 512}` and return `{"text": "..."}` or a `choices` array. Adjust `agent/nim_client.py` if your deployment uses a different schema.

- For retrieval, we recommend normalization of vectors and FAISS IndexFlatIP or IndexHNSWFlat for production.

If you want, paste your actual NIM endpoint patterns and I will update `agent/nim_client.py` to exactly match your API schema.
NIM_EMBEDDING_MODEL=nvidia/nv-embedcode-7b-v1
NIM_INFERENCE_MODEL=nvidia/llama-3.1-nemotron-nano-8b-v1
NIM_BASE_URL=https://integrate.api.nvidia.com
CODEGUARDIAN_LLM_MODE=nim
