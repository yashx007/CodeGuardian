# CodeGuardian

Minimal instructions to run the project locally, run CI checks, and collaborate safely.

Requirements
- Python 3.11+

Quick start (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Run backend
uvicorn backend.app:app --reload

# In another shell, run frontend (optional)
streamlit run frontend/app.py
```

Run tests and checks locally

```powershell
pytest -q
black --check .
flake8 .
mypy .
bandit -r .
safety check
```

Collaboration rules
- Use feature branches and open PRs to `main`.
- CI is mandatory on PRs and must pass before merging.
- Update `CODEOWNERS` to include your teammate(s) to request reviews automatically.
- Use `docs/branch-protection.md` for GitHub branch protection setup steps.
