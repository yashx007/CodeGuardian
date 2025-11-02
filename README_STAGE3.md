# CodeGuardian — Stage 3 (AI Reasoning & Explanation Layer)

This file summarizes what Stage 3 provides and how to run, test, and deploy the reasoning layer.

## What Stage 3 delivers
- A Reasoner (`agent/reasoning.py`) that enriches Stage 2 detections with explanations, fixes, severity, references, and a project-level risk summary.
- An LLM abstraction (`agent/llm_client.py`) supporting offline templates, NVIDIA NIM, and Amazon SageMaker.
- A SageMaker runtime wrapper (`agent/aws_client.py`) and tests that mock SageMaker behavior.
- Knowledge base (`agent/knowledge_base.py`) seeded with 50+ curated entries and a `KnowledgeStore` (FAISS optional) for retrieval.
- FastAPI app (`app/app.py`) with `/analyze`, `/summary` endpoints and a `backend` query param to force the LLM backend per-request.
- Unit tests and CI workflow (GitHub Actions) that run tests in offline mode.

## Quickstart — run tests
Install dev deps (virtualenv recommended).

1. Create virtualenv and activate (Windows PowerShell):

```powershell
python -m venv .venv
. .venv\Scripts\Activate.ps1
```

2. Install and run tests:

```powershell
pip install -r requirements.txt
pytest -q
```

CI note: the included GitHub Actions workflow runs tests in `CODEGUARDIAN_LLM_MODE=offline` to keep CI hermetic.

## Run the API locally
```powershell
$env:PYTHONPATH='.'; uvicorn app.app:app --reload
```

Call the analyze endpoint. Example forcing SageMaker mode for a single request (demo only; tests mock SageMaker):

```powershell
http POST :8000/analyze backend==sagemaker stage2:='{"input/test.py": [{"type": "hardcoded secret", "line": 1, "snippet": "pw=1", "message": "secret"}] }'
```

## Docker
Build and run locally:

```powershell
docker build -t codeguardian:stage3 .
docker run -p 8000:8000 codeguardian:stage3
```

## SageMaker / Production notes
- Deploy NVIDIA NIM models to SageMaker endpoints (LLM and Embeddings). Set `SAGEMAKER_LLM_ENDPOINT` and `SAGEMAKER_EMBEDDING_ENDPOINT` env vars to use them.
- For CI or local dev, prefer `CODEGUARDIAN_LLM_MODE=offline` or use the provided mock tests.

## Next steps (optional)
- Add `/chat` interactive endpoint (short session context) — helpful for conversational follow-ups.
- Persist analyses to SQLite or S3 for audit history (`/history` endpoint).
- Expand KB with CWE/OWASP IDs and more examples.
