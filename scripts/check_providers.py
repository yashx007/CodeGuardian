"""Check configured LLM/embedding providers (NIM or SageMaker) and run simple probes.

This script prints diagnostics and attempts one explain() and one embed() call when possible.
Run with the repo root on PYTHONPATH, e.g.:

PowerShell:
$env:PYTHONPATH='.'; python scripts/check_providers.py

Set provider env vars beforehand (NIM or SageMaker) as needed.
"""
from __future__ import annotations

import os
import json
import sys
from typing import Any


def _print(title: str, v: Any = None):
    print(f"--- {title} ---")
    if v is None:
        return
    if isinstance(v, (dict, list)):
        print(json.dumps(v, indent=2))
    else:
        print(v)


def main():
    # show env vars of interest
    keys = [
        "CODEGUARDIAN_LLM_MODE",
        "NIM_INFERENCE_URL",
        "NIM_EMBEDDING_URL",
        "NIM_BASE_URL",
        "NIM_API_KEY",
        "NIM_INFERENCE_MODEL",
        "NIM_EMBEDDING_MODEL",
        "SAGEMAKER_LLM_ENDPOINT",
        "SAGEMAKER_EMBEDDING_ENDPOINT",
        "AWS_REGION",
    ]

    env = {k: os.environ.get(k) for k in keys}
    _print("Environment (relevant)", env)

    # Import local clients
    try:
        from agent.llm_client import LLMClient
    except Exception as e:
        print("Failed to import LLMClient:", e)
        sys.exit(2)

    # instantiate client with configured mode
    mode = os.environ.get("CODEGUARDIAN_LLM_MODE", "offline")
    client = LLMClient(mode=mode)
    _print("LLMClient.mode", client.mode)
    _print("LLMClient.online_available", client.online_available)
    _print("NIM client instance", type(getattr(client, "nim", None)).__name__)
    _print("SageMaker client instance", type(getattr(client, "sagemaker", None)).__name__)

    # Try a small explain probe if online is available
    if client.mode == "nim" and client.nim is not None and client.online_available:
        print("Attempting NIM explain probe...")
        try:
            out = client.nim.explain("Ping from CodeGuardian probe: explain this in one line.")
            _print("NIM explain output", out)
        except Exception as e:
            _print("NIM explain failed", str(e))

        print("Attempting NIM embed probe...")
        try:
            em = client.nim.embed(["test embedding"[:512]])
            _print("NIM embed output (len)", len(em))
            if em:
                _print("NIM embed vector length", len(em[0]))
        except Exception as e:
            _print("NIM embed failed", str(e))

    elif client.mode == "sagemaker" and client.sagemaker is not None and client.online_available:
        print("Attempting SageMaker explain probe...")
        try:
            out = client.sagemaker.explain("Ping from CodeGuardian probe: explain this in one line.")
            _print("SageMaker explain output", out)
        except Exception as e:
            _print("SageMaker explain failed", str(e))

        print("Attempting SageMaker embed probe...")
        try:
            em = client.sagemaker.embed(["test embedding"])
            _print("SageMaker embed output (len)", len(em))
            if em:
                _print("SageMaker embed vector length", len(em[0]))
        except Exception as e:
            _print("SageMaker embed failed", str(e))

    else:
        print("Online LLM not configured/available. The client will use offline templates.")


if __name__ == "__main__":
    main()
