import pytest
from pathlib import Path

try:
    from clang import cindex

    HAS_CLANG = True
except Exception:
    HAS_CLANG = False


@pytest.mark.skipif(not HAS_CLANG, reason="libclang not installed")
def test_libclang_produces_extents(tmp_path: Path):
    code = """
#include <stdlib.h>
int main(){
  system("ls");
  return 0;
}
"""
    p = tmp_path / "sample.c"
    p.write_text(code, encoding="utf-8")

    # import function under test
    from agent.parser import analyze_cpp_with_clang

    issues = analyze_cpp_with_clang(str(p))
    assert isinstance(issues, list)
    assert any(i.get("type") == "Dangerous Function" for i in issues)
    for i in issues:
        if i.get("type") == "Dangerous Function":
            assert "startLine" in i and i["startLine"] is not None
            assert "endLine" in i and i["endLine"] is not None
            assert "snippet" in i
        # Removed stray end patch line
