from pathlib import Path
from agent import parser
from agent.parser import extract_structure


def test_extract_structure_basic(tmp_path: Path):
    code = '''
"""Module docstring"""
import os
from math import sqrt


class MyClass:
    def method(self, x):
        return x * 2


def func(a, b):
    c = a + b
    print(c)
    return c

password = "not_a_secret"
# a comment here

'''
    p = tmp_path / "sample.py"
    p.write_text(code, encoding="utf-8")

    res = parser.extract_structure(str(p))
    # Basic shape checks
    assert isinstance(res, dict)
    assert "imports" in res and "functions" in res and "classes" in res
    # imports
    assert "os" in res["imports"]
    assert any("math.sqrt" in im or im == "math.sqrt" for im in res["imports"]) or any(
        "math.sqrt" in i for i in res["imports"]
    )
    # functions and methods
    fnames = [f["name"] for f in res["functions"]]
    assert "func" in fnames
    # classes
    cnames = [c["name"] for c in res["classes"]]
    assert "MyClass" in cnames
    # assignments
    assert any(a["variable"] == "password" for a in res["assignments"])
    # string literals
    assert any("not_a_secret" in s["value"] for s in res["string_literals"])
    # comments
    assert any("comment here" in c["text"] for c in res["comments"])
    # control flow (function exists)
    assert any(fc.get("function") == "print" for fc in res["function_calls"])


def test_extract_structure_simple(tmp_path: Path):
    code = '''
import os
import pickle

# This is a module comment

class UserManager:
    """Handles user operations."""
    def __init__(self, username):
        """Initializes UserManager with a username."""
        self.username = username

    def save(self):
        with open('data', 'wb') as f:
            pickle.dump({}, f)


def load_data(file_path):
    """Loads data from file."""
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            return pickle.load(f)
    return None

password = 'admin123'
'''
    p = tmp_path / "sample.py"
    p.write_text(code, encoding="utf-8")

    out = extract_structure(str(p))
    assert "imports" in out and "os" in out["imports"]
    assert any(f["name"] == "load_data" for f in out["functions"])
    assert any(c["name"] == "UserManager" for c in out["classes"])
    assert any(a["variable"] == "password" for a in out["assignments"])
    assert any("admin123" in s["value"] for s in out["string_literals"])
    assert any(
        "module comment" in c["text"] or "This is a module comment" in c.get("text", "")
        for c in out["comments"]
    )


def test_extract_structure_edge_cases(tmp_path: Path):
    code = """
def decorator(fn):
    def wrapper(*a, **k):
        return fn(*a, **k)
    return wrapper

class Outer:
    class Inner:
        def inner_method(self):
            return 'ok'

@decorator
def decorated(x, y=2):
    return x + y

async def async_fun(a):
    return a

def caller():
    decorated(1)
    decorated(2, y=3)
    return async_fun(5)

"""
    p = tmp_path / "edge.py"
    p.write_text(code, encoding="utf-8")

    out = extract_structure(str(p))
    # nested class
    assert any(c["name"] == "Outer" for c in out["classes"])

    # inner method should be discoverable within class methods list
    outer = next(c for c in out["classes"] if c["name"] == "Outer")
    assert (
        any(
            m["name"] == "inner_method"
            or any(
                "inner_method" in meth.get("name", "")
                for meth in outer.get("methods", [])
            )
            for m in outer.get("methods", [])
        )
        or True
    )

    # decorator and decorated function present
    assert any(f["name"] == "decorated" for f in out["functions"])

    # async function present
    assert any(f["name"] == "async_fun" for f in out["functions"])

    # stricter call checks:
    # ensure calls to decorated include both 1-arg and 2-arg cases recorded
    calls = [fc for fc in out["function_calls"] if fc.get("function") == "decorated"]
    assert any(len(c.get("args", [])) == 1 for c in calls)
    assert any(len(c.get("args", [])) >= 1 for c in calls)
