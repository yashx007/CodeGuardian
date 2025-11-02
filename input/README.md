Sample test inputs for Stage 2 extractor. Files:

- test_insecure.py: insecure functions, regex, deprecated hashes, SQL concatenation
- test_secrets.py: obvious hardcoded secrets and tokens
- test_sql.py: SQL concatenation example
- test_js.js: JS eval, child_process and hardcoded secret
- test_cpp.cpp: C++ uses of strcpy and system

Run the scanner from repo root:

PowerShell:
& .venv\Scripts\Activate.ps1
python agent/parser.py input --flatten

Or on Unix-like shells:
python3 agent/parser.py input --flatten
