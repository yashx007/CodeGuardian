"""Attempt to locate libclang DLL on Windows and print the path.

Usage: python scripts/find_libclang_windows.py
Outputs a single path or exits 1 if not found.
"""
import sys
import os
from pathlib import Path

def search_paths():
    candidates = []
    # common Chocolatey / LLVM install locations
    candidates += [r"C:\Program Files\LLVM\bin", r"C:\Program Files (x86)\LLVM\bin"]
    # Visual Studio/Windows kits
    candidates += [os.environ.get('LLVM_HOME', ''), os.environ.get('ProgramFiles', ''), os.environ.get('ProgramFiles(x86)', '')]
    for base in candidates:
        if not base:
            continue
        p = Path(base)
        if p.exists():
            for f in p.rglob('libclang*.dll'):
                print(str(f))
                return 0
    # fallback: try PATH
    for part in os.environ.get('PATH', '').split(os.pathsep):
        p = Path(part)
        if p.exists():
            for f in p.glob('libclang*.dll'):
                print(str(f))
                return 0
    return 1

if __name__ == '__main__':
    code = search_paths()
    sys.exit(code)
