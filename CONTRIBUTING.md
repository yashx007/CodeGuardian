# Contributing to CodeGuardian

Thanks for helping build CodeGuardian! This document explains how to collaborate, run checks locally, and make safe PRs.

1. Invite collaborator
- On GitHub, go to Settings -> Manage access -> Invite a collaborator. Add your teammate's GitHub username.

2. Branch strategy
- Use feature branches named `feature/<short-description>` or `fix/<short-description>`.
- Push to the remote branch and open a Pull Request (PR) targeting `main` (or `develop` if used).

3. PR requirements
- All PRs must:
  - Include a short description and testing steps.
  - Pass the CI workflow (lint, tests, bandit).
  - Have at least one approving review from a collaborator.

4. Running checks locally
- Create a virtualenv and install dependencies:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
```

- Run linters and tests:

```powershell
flake8 .
pytest -q
bandit -r .
```

5. Code owners and reviews
- The `CODEOWNERS` file defines who should review PRs touching certain paths.

6. Security
- Use `bandit` for quick security scans. CI will run it on every PR.

If you're unsure, open a draft PR and ask for feedback.
