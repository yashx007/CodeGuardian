Eval Embeddings Script
======================

This folder contains `eval_embeddings.py`, a small evaluation harness that:

- Builds embeddings for a small set of labeled security snippets.
- Constructs a FAISS index (if `faiss` and `numpy` are installed).
- Computes simple retrieval metrics: precision@k and MRR.

Usage
-----

- Quick mock run (no NIM, no faiss required):

```powershell
$env:PYTHONPATH='.'; python scripts/eval_embeddings.py --mock
```

This uses a deterministic, SHA256-based embedding shim so you can run the evaluation in CI or on machines without native deps.

- Real evaluation using NIM + FAISS:

1. Install dependencies (recommended using conda on Windows):

```powershell
# create env if needed
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# install numpy via pip
pip install numpy
# Installing faiss on Windows is easiest via conda-forge
# If you have conda/miniconda:
conda install -c conda-forge faiss-cpu numpy
```

2. Set NIM environment variables (or create a `.env` file in the repo root):

- `NIM_BASE_URL` (e.g. https://integrate.api.nvidia.com)
- `NIM_API_KEY_EMBEDDING` or `NIM_API_KEY` (for embeddings)

3. Run evaluation:

```powershell
$env:PYTHONPATH='.'; python scripts/eval_embeddings.py
```

Notes on Windows + FAISS
------------------------
- FAISS does not have an official pip wheel for all Windows/Python combinations. Using conda-forge (`conda install -c conda-forge faiss-cpu`) is the most reliable approach.
- If you cannot install FAISS, run the script in `--mock` mode to exercise the code paths and produce deterministic metrics that are reproducible for CI.

Troubleshooting
---------------
- If the script errors with missing numpy/faiss, use `--mock` or install the missing packages.
- If NIM embedding calls fail, ensure your `NIM_BASE_URL` and keys are set and correct. The script will fall back to mock embeddings if NIM is unreachable.
