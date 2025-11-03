import io
import zipfile
import tarfile
import asyncio
import urllib.request
from typing import List, Optional
from dotenv import load_dotenv

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from agent.engine import engine
from agent import parser as stage2_parser
from agent.reasoning import reasoner, Reasoner
from agent import persistence
from fastapi import Depends
from app.routes_chat import router as chat_router


# Load local .env for development (safe: .env is gitignored)
load_dotenv()

app = FastAPI(title="CodeGuardian API")

# include chat routes
app.include_router(chat_router)


class ScanResult(BaseModel):
    filename: str
    issue: str
    suggestion: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def uploader_ui():
    html = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>CodeGuardian Uploader</title>
        <style>body{font-family:sans-serif;margin:2rem} textarea{width:100%;height:200px}</style>
      </head>
      <body>
        <h1>CodeGuardian — Upload / Paste / Fetch</h1>

        <h2>Upload files (single or multiple)</h2>
        <form id="fileForm">
          <input type="file" id="files" name="files" multiple />
          <button type="button" onclick="submitFiles()">Upload & Scan</button>
        </form>

        <h2>Upload archive (.zip, .tar, .tgz)</h2>
        <form id="archiveForm">
          <input type="file" id="archive" name="archive" />
          <button type="button" onclick="submitArchive()">Upload Archive</button>
        </form>

        <h2>Paste code</h2>
        <form id="pasteForm">
          <input type="text" id="pasteFilename" placeholder="filename (e.g. example.py)" />
          <br/>
          <textarea id="code"></textarea>
          <br/>
          <button type="button" onclick="submitPaste()">Submit Code</button>
        </form>

        <h2>Fetch from URL</h2>
        <form id="urlForm">
          <input type="url" id="url" placeholder="https://example.com/file.py" style="width:60%" />
          <button type="button" onclick="submitURL()">Fetch & Scan</button>
        </form>

        <h2>Results</h2>
        <pre id="out">No results yet.</pre>

        <script>
        async function submitFiles(){
          const files = document.getElementById('files').files;
          const fd = new FormData();
          for (let f of files) fd.append('files', f);
          const res = await fetch('/upload', { method: 'POST', body: fd });
          const j = await res.json();
          document.getElementById('out').textContent = JSON.stringify(j, null, 2);
        }
        async function submitArchive(){
          const f = document.getElementById('archive').files[0];
          const fd = new FormData();
          fd.append('files', f);
          const res = await fetch('/upload', { method: 'POST', body: fd });
          const j = await res.json();
          document.getElementById('out').textContent = JSON.stringify(j, null, 2);
        }
        async function submitPaste(){
          const code = document.getElementById('code').value;
          const filename = document.getElementById('pasteFilename').value || 'pasted.py';
          const fd = new FormData();
          fd.append('code', code);
          fd.append('filename', filename);
          const res = await fetch('/upload', { method: 'POST', body: fd });
          const j = await res.json();
          document.getElementById('out').textContent = JSON.stringify(j, null, 2);
        }
        async function submitURL(){
          const url = document.getElementById('url').value;
          const fd = new FormData();
          fd.append('url', url);
          const res = await fetch('/upload', { method: 'POST', body: fd });
          const j = await res.json();
          document.getElementById('out').textContent = JSON.stringify(j, null, 2);
        }
        </script>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


async def _fetch_url_content(url: str) -> Optional[bytes]:
    # Try to fetch using httpx if available; otherwise use urllib in a thread
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url)
            r.raise_for_status()
            return r.content
    except Exception:
        try:
            # fallback to sync urllib in thread
            return await asyncio.to_thread(
                lambda: urllib.request.urlopen(url, timeout=10).read()
            )
        except Exception:
            return None


def _scan_and_pack(filename: str, content: str):
    try:
        res = engine.scan_code(filename, content)
        return {
            "filename": filename,
            "issue": res.get("issue"),
            "suggestion": res.get("suggestion"),
        }
    except Exception as e:
        return {"filename": filename, "error": str(e)}


@app.post("/upload")
async def upload(
    files: List[UploadFile] = File(None),
    code: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
):
    """Accept multiple upload modes: files (single/multiple/archives), pasted
    code, or a URL.
    """
    results = []

    # Process uploaded files if any
    if files:
        for f in files:
            name = f.filename or "uploaded"
            data = await f.read()
            # handle archives
            lower = name.lower()
            try:
                if lower.endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        for nm in z.namelist():
                            try:
                                b = z.read(nm)
                                try:
                                    text = b.decode("utf-8", errors="ignore")
                                except Exception:
                                    continue
                                results.append(_scan_and_pack(nm, text))
                            except Exception:
                                continue
                    continue
                if (
                    lower.endswith(".tar")
                    or lower.endswith(".tgz")
                    or lower.endswith(".tar.gz")
                ):
                    try:
                        with tarfile.open(fileobj=io.BytesIO(data)) as t:
                            for member in t.getmembers():
                                if member.isreg():
                                    fh = t.extractfile(member)
                                    if fh is None:
                                        continue
                                    b = fh.read()
                                    try:
                                        text = b.decode("utf-8", errors="ignore")
                                    except Exception:
                                        continue
                                    results.append(_scan_and_pack(member.name, text))
                        continue
                    except Exception:
                        pass
                # otherwise treat as a regular text file
                text = data.decode("utf-8", errors="ignore")
                results.append(_scan_and_pack(name, text))
            except Exception as e:
                results.append({"filename": name, "error": str(e)})

        return JSONResponse({"results": results})

    # Process pasted code
    if code is not None:
        fn = filename or "pasted.py"
        results.append(_scan_and_pack(fn, code))
        return JSONResponse({"results": results})

    # Process URL
    if url:
        content = await _fetch_url_content(url)
        if content is None:
            return JSONResponse({"error": "Failed to fetch URL"}, status_code=400)
        try:
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        results.append(_scan_and_pack(url, text))
        return JSONResponse({"results": results})

    return JSONResponse({"error": "No input provided"}, status_code=400)


@app.post("/analyze")
async def analyze(
    stage2: Optional[dict] = None,
    files: List[UploadFile] = File(None),
    code: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    backend: Optional[str] = None,
):
    """Analyze input using Stage 2 parser and Stage 3 reasoner.

    Modes:
    - Provide `stage2` JSON (mapping file->issues) directly
    - Upload files (same as /upload) and they will be analyzed with Stage 2
    - Paste code via 'code' and 'filename'
    """
    # If a backend is specified for this request, create a request-scoped Reasoner
    req_reasoner = reasoner
    if backend:
        try:
            req_reasoner = Reasoner(llm_mode=backend)
        except Exception:
            # fallback to global reasoner
            req_reasoner = reasoner

    # If user provided Stage 2 JSON directly
    if stage2:
        enriched = req_reasoner.enrich(stage2)
        # persist the report (best-effort)
        try:
            persistence.save_report("stage2_input", enriched.get("summary", {}), enriched)
        except Exception:
            pass
        return JSONResponse(enriched)

    results = []
    # uploaded files
    if files:
        for f in files:
            try:
                text = await f.read()
                text = text.decode("utf-8", errors="ignore")
            except Exception:
                continue
            issues = stage2_parser.analyze_code("uploaded:" + (f.filename or "file"))
            enriched = req_reasoner.enrich({f.filename or "uploaded": issues})
            # persist
            try:
                persistence.save_report(f.filename or "uploaded", enriched.get("summary", {}), enriched)
            except Exception:
                pass
            results.append(enriched)
        return JSONResponse({"results": results})

    # pasted code
    if code is not None:
        fn = filename or "pasted.py"
        # write to temp file? stage2 parser accepts path -> use analyze_code by writing to a temporary path
        # Note: parser.analyze_code accepts a file path string and loads the file.
        # To analyze pasted code we create a temporary file and pass its path
        # to the existing analyzer rather than trying to call internal helpers.
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=True) as tf:
            tf.write(code)
            tf.flush()
            issues = stage2_parser.analyze_code(tf.name)

        enriched = req_reasoner.enrich({fn: issues})
        try:
            persistence.save_report(fn, enriched.get("summary", {}), enriched)
        except Exception:
            pass
        return JSONResponse(enriched)

    return JSONResponse({"error": "No input provided to analyze"}, status_code=400)


@app.get("/summary")
def summary(path: Optional[str] = None):
    """Run a scan on a path and return severity breakdown and top risky files.

    If path is omitted, returns an empty summary.
    """
    if not path:
        return JSONResponse(
            {"summary": {"counts": {}, "risk": "Unknown", "total_issues": 0}}
        )

    findings = stage2_parser.analyze_path(path, recursive=True)
    enriched = reasoner.enrich(findings)
    # keep only summary
    return JSONResponse({"summary": enriched.get("summary")})


@app.get("/history")
def history(limit: int = 50):
    """Return recent analysis summaries (id, filename, timestamp, summary)."""
    try:
        reports = persistence.list_reports(limit=limit)
        return JSONResponse({"reports": reports})
    except Exception:
        return JSONResponse({"error": "Failed to read history"}, status_code=500)


@app.get("/history/{report_id}")
def history_get(report_id: int):
    """Return a full saved report by id."""
    try:
        rep = persistence.get_report(report_id)
        if rep is None:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return JSONResponse({"report": rep})
    except Exception:
        return JSONResponse({"error": "Failed to read report"}, status_code=500)
