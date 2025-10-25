# Agent parser (Stage 2)

This module implements a lightweight static analyzer for Python source code used in Stage 2 of CodeGuardian.

Detections implemented:

- Insecure Function Usage: eval, exec, compile, input
- Insecure pickling: pickle.load / loads
- Dangerous imports: os, subprocess
- Deprecated hashes: md5, sha1 (via attribute usage)
- Hardcoded secrets and tokens via regex patterns

Usage:

python -m agent.parser path/to/file.py

Or import analyze_code from `agent.parser` and call with a file path. It returns a list of dicts with keys: `type`, `line`, `snippet`, `message`.

Optional dependencies for improved parsing:

- JavaScript AST parsing (better than regex): install Node and run `npm install` in the repo root (this will install `esprima`). The scanner will automatically use `agent/js_parser.js` when available.
- C/C++ parsing: installing `libclang` and the Python `clang` bindings improves C/C++ detection. On Ubuntu:

		sudo apt-get install -y clang libclang-dev
		pip install clang

CI / runner recommendations for libclang
-------------------------------------

To run the libclang-enhanced C/C++ checks in CI (and to ensure tests that rely on libclang run), make sure your CI runner contains a system libclang and the Python bindings. For GitHub Actions (Ubuntu runners) you can add a step like:

```yaml
- name: Install libclang + clang
	run: sudo apt-get update; sudo apt-get install -y clang libclang-dev

- name: Install Python deps
	run: python -m pip install -r requirements.txt
```

On Windows runners you may need to install LLVM/Clang and ensure the libclang DLL is on PATH. One option is to use the LLVM installer or chocolatey packages and set the PATH accordingly. Ensure the Python `clang` package matches the libclang version available on the system.

Environment flags
-----------------
The parser supports two environment variables to control libclang behavior and logging:

- `CODEGUARDIAN_SNIPPET_CONTEXT` — number of context lines to include around C/C++ extents when extracting snippets (default: 1).
- `CODEGUARDIAN_DEBUG` — set to `1` to enable debug logging during parsing attempts (helpful in CI to diagnose parse failures).


