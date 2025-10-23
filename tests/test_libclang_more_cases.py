import pytest
from pathlib import Path

try:
    import importlib
    HAS_CLANG = importlib.util.find_spec('clang.cindex') is not None
except Exception:
    HAS_CLANG = False


@pytest.mark.skipif(not HAS_CLANG, reason="libclang not installed")
def test_libclang_handles_missing_includes(tmp_path: Path):
    # source references a header that doesn't exist on the system;
    # libclang should still parse enough to find calls
    code = '''
#include "nonexistent_header.h"
int main(){
  system("ls");
  return 0;
}
'''
    p = tmp_path / 'missing_include.c'
    p.write_text(code, encoding='utf-8')

    from agent.parser import analyze_cpp_with_clang
    issues = analyze_cpp_with_clang(str(p))
    assert isinstance(issues, list)
    assert any(i.get('type') == 'Dangerous Function' for i in issues)


@pytest.mark.skipif(not HAS_CLANG, reason="libclang not installed")
def test_libclang_complex_expression(tmp_path: Path):
    # macro-wrapped call and member expressions
    code = '''
#define CALL(x) x
struct S { int (*fn)(const char*); };
int main(){
  CALL(system)("ls");
  return 0;
}
'''
    p = tmp_path / 'complex.c'
    p.write_text(code, encoding='utf-8')

    from agent.parser import analyze_cpp_with_clang
    issues = analyze_cpp_with_clang(str(p))
    assert isinstance(issues, list)
    # allow heuristic fallback to detect it
    assert any(i.get('type') == 'Dangerous Function' for i in issues)


@pytest.mark.skipif(not HAS_CLANG, reason="libclang not installed")
def test_snippet_context_respects_env(tmp_path: Path, monkeypatch):
    # set a larger context to ensure snippet includes surrounding lines
    monkeypatch.setenv('CODEGUARDIAN_SNIPPET_CONTEXT', '2')
    code = '''
#include <stdlib.h>
// comment above
int main(){
  // inner comment
  system("ls");
  return 0;
}
'''
    p = tmp_path / 'context.c'
    p.write_text(code, encoding='utf-8')
    from agent import parser
    # re-importing function to pick up env change isn't necessary; the
    # function reads env at import time
    issues = parser.analyze_cpp_with_clang(
        str(p)
    )
    for it in issues:
        if it.get('type') == 'Dangerous Function':
            # snippet should be present and include context lines when
            # context>0
            assert 'snippet' in it
            snip = it.get('snippet') or ''
            assert snip.strip() != ''
            # with context=2 we expect at least two lines in the
            # snippet in most cases
            assert len(snip.splitlines()) >= 2
