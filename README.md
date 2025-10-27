# CodeGuardian

Minimal instructions to run the project locally, run CI checks, and collaborate safely.

Requirements
- Python 3.10+ (3.11 recommended)

Quick start (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Run backend (FastAPI)
uvicorn app.app:app --reload --host 0.0.0.0 --port 8000

# FastAPI provides interactive docs at http://127.0.0.1:8000/docs
```

Run tests and checks locally

```powershell
$env:PYTHONPATH='.'; pytest -q
black --check .
flake8 .
mypy .
bandit -r .
safety check
```

Hackathon quick demo

Focus on core functionality for a short demo: code analysis, chat sessions (persisted), and history retrieval. The following shows a simple way to run and exercise the app locally.

1. Start the server (see Quick start above).
2. In another PowerShell, run the demo script which exercises upload/analyze/chat flows (this uses `requests` and is CI-friendly):

```powershell
python scripts/demo_demo.py
```

Environment configuration (optional)
- `CHAT_DB` — path to SQLite DB for chat sessions (default: `data/sessions.db`). Use a temp path for tests.
- `CHAT_SESSION_TTL_SECONDS` — session TTL in seconds (default: 3600). Set to <=0 to disable expiry.
- `CHAT_CONTEXT_TURNS` — how many turns to include in LLM context (default: 10).
- `CHAT_EVICT_INTERVAL_SECONDS` — background eviction interval in seconds (default: 60).

Notes
- FastAPI includes an interactive UI at `/docs` (Swagger) which is handy for live demos.
- The demo script shows basic usage; feel free to adapt it for screenshots or a short recorded walkthrough.

Collaboration rules
- Use feature branches and open PRs to `main`.
- CI is mandatory on PRs and must pass before merging.
- Update `CODEOWNERS` to include your teammate(s) to request reviews automatically.
- Use `docs/branch-protection.md` for GitHub branch protection setup steps.
