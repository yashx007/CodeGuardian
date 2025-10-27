"""Simple demo script for CodeGuardian hackathon.

This script exercises key endpoints: /upload (paste), /analyze (stage2-like json), /chat and /chat/{session}/history.
Run the FastAPI server first: `uvicorn app.app:app --reload` and then run this script.
"""
import os
import time
import requests

BASE = os.environ.get("CG_BASE", "http://127.0.0.1:8000")


def pretty(j):
    import json

    print(json.dumps(j, indent=2))


def demo_upload_paste():
    print("\n== Upload (paste) demo ==")
    code = """
def insecure_eval(user_input):
    return eval(user_input)
"""
    files = {"code": (None, code), "filename": (None, "example.py")}
    r = requests.post(f"{BASE}/upload", files=files)
    print(r.status_code)
    pretty(r.json())


def demo_analyze_paste():
    print("\n== Analyze (paste) demo ==")
    code = "print('hello')\nuser = input()\nprint(user)"  # trivial sample
    data = {"code": code, "filename": "demo.py"}
    r = requests.post(f"{BASE}/analyze", data=data)
    print(r.status_code)
    pretty(r.json())


def demo_chat_flow():
    print("\n== Chat demo ==")
    # start a session
    r = requests.post(f"{BASE}/chat", json={"message": "Hello, what can you do?"})
    print(r.status_code)
    j = r.json()
    pretty(j)
    sid = j.get("session_id")

    # follow up
    r2 = requests.post(f"{BASE}/chat", json={"session_id": sid, "message": "Any advice for insecure eval?"})
    pretty(r2.json())

    # fetch history
    hr = requests.get(f"{BASE}/chat/{sid}/history")
    print("History:")
    pretty(hr.json())


if __name__ == "__main__":
    print("CodeGuardian demo starting against", BASE)
    print("Make sure the server is running (uvicorn app.app:app --reload)")
    try:
        demo_upload_paste()
    except Exception as e:
        print("Upload demo failed:", e)
    try:
        demo_analyze_paste()
    except Exception as e:
        print("Analyze demo failed:", e)
    try:
        demo_chat_flow()
    except Exception as e:
        print("Chat demo failed:", e)
    print("Demo finished.")
