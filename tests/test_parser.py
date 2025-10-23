import json
from pathlib import Path

import pytest

from agent.parser import analyze_code


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_detect_eval_and_input(tmp_path: Path):
    code = """
user = input('enter: ')
result = eval(user)
"""
    p = write_tmp(tmp_path, "sample_eval.py", code)
    results = analyze_code(str(p))
    types = [r["type"] for r in results]
    snippets = [r["snippet"] for r in results]
    assert any(r["type"] == "Insecure Function Usage" and "eval" in r["snippet"] for r in results)
    assert any(r["type"] == "Insecure Function Usage" and "input" in r["snippet"] for r in results)


def test_detect_hardcoded_password(tmp_path: Path):
    code = """
password = 'admin123'
print('do something')
"""
    p = write_tmp(tmp_path, "sample_secret.py", code)
    results = analyze_code(str(p))
    assert any(r["type"] == "Hardcoded Secret" for r in results)


def test_detect_dangerous_imports_and_deprecated_hash(tmp_path: Path):
    code = """
import os
import subprocess
import hashlib

hashlib.md5(b'data')
os.system('ls')
"""
    p = write_tmp(tmp_path, "sample_danger.py", code)
    results = analyze_code(str(p))
    types = [r["type"] for r in results]
    assert any(t == "Dangerous Import" for t in types)
    assert any(t == "Deprecated Hash" for t in types)


def test_js_heuristics_eval_and_child_process(tmp_path: Path):
    code = """
const { exec } = require('child_process');
let user = 'input';
eval(user);
exec('ls ' + user);
"""
    p = write_tmp(tmp_path, "sample.js", code)
    # analyze_text_for_js is internal; use analyze_path to exercise full path
    from agent.parser import analyze_path

    results = analyze_path(str(tmp_path), recursive=False)
    # find our file
    issues = []
    for fp, its in results.items():
        if fp.endswith("sample.js"):
            issues = its
    types = [i["type"] for i in issues]
    assert any(t == "Insecure Function Usage" for t in types)
    assert any(t == "Suspicious Subprocess Call" for t in types)


def test_cpp_heuristics_system_and_hardcoded(tmp_path: Path):
    code = """
#include <stdlib.h>
int main(){
  system("ls");
  const char* password = "s3cr3t";
  return 0;
}
"""
    p = write_tmp(tmp_path, "sample.cpp", code)
    from agent.parser import analyze_path

    results = analyze_path(str(tmp_path), recursive=False)
    issues = []
    for fp, its in results.items():
        if fp.endswith("sample.cpp"):
            issues = its
    types = [i["type"] for i in issues]
    assert any(t == "Dangerous Function" for t in types)
    assert any(t == "Hardcoded Secret" for t in types)


def test_sql_fstring_and_format_detection(tmp_path: Path):
    code_f = """
user = 'admin'
query = f"SELECT * FROM users WHERE name = '{user}'"
cursor.execute(query)
"""
    code_format = """
params = {'name': 'bob'}
query = "SELECT * FROM users WHERE name = '{name}'".format(**params)
cursor.execute(query)
"""
    p1 = write_tmp(tmp_path, "fstring.py", code_f)
    p2 = write_tmp(tmp_path, "format.py", code_format)
    from agent.parser import analyze_code

    res1 = analyze_code(str(p1))
    res2 = analyze_code(str(p2))
    assert any(r["type"] == "Possible SQL Injection" for r in res1)
    assert any(r["type"] == "Possible SQL Injection" for r in res2)
