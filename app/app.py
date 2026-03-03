import io
import zipfile
import tarfile
import asyncio
import urllib.request
from typing import List, Optional
from dotenv import load_dotenv

# Load .env BEFORE any agent imports so NIM_BASE_URL, NIM_API_KEY etc. are visible
load_dotenv()

from fastapi import FastAPI, UploadFile, File, Form, Body
from fastapi.responses import HTMLResponse, JSONResponse
import os
import logging
from logging.handlers import RotatingFileHandler
from pydantic import BaseModel

from agent.engine import engine
from agent import parser as stage2_parser
from agent.reasoning import reasoner, Reasoner
from agent import persistence
from fastapi import Depends
from app.routes_chat import router as chat_router


app = FastAPI(title="CodeGuardian API")

# include chat routes
app.include_router(chat_router)

# Ensure logs directory exists and configure logging
LOG_DIR = os.environ.get("CG_LOG_DIR", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, "app.log")
handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
handler.setFormatter(formatter)
logger = logging.getLogger("codeguardian")
if not logger.handlers:
    logger.addHandler(handler)
logger.setLevel(os.environ.get("CG_LOG_LEVEL", "INFO"))


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
        <style>
          * { box-sizing: border-box; }
          body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 2rem; background: #0d1117; color: #c9d1d9; }
          h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }
          h2 { color: #8b949e; font-size: 1rem; margin-top: 1.5rem; }
          input[type="file"], input[type="text"], input[type="url"] {
            background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
            border-radius: 6px; padding: 8px 12px; margin: 4px 0; font-size: .9rem;
          }
          input[type="url"] { width: 60%; }
          textarea {
            width: 100%; height: 200px; background: #161b22; color: #c9d1d9;
            border: 1px solid #30363d; border-radius: 6px; padding: 10px; font-family: monospace; font-size: .85rem;
          }
          button {
            background: #238636; color: #fff; border: none; border-radius: 6px;
            padding: 8px 18px; font-size: .9rem; cursor: pointer; margin: 4px 0;
          }
          button:hover { background: #2ea043; }
          button:disabled { background: #21262d; color: #484f58; cursor: not-allowed; }

          /* Loader overlay */
          #loader {
            display: none; align-items: center; gap: 12px;
            background: #1c2533; border: 1px solid #30363d; border-radius: 8px;
            padding: 16px 24px; margin: 1rem 0; font-size: .95rem; color: #58a6ff;
          }
          #loader.active { display: flex; }
          .spinner {
            width: 22px; height: 22px; border: 3px solid #30363d;
            border-top-color: #58a6ff; border-radius: 50%;
            animation: spin .8s linear infinite;
          }
          @keyframes spin { to { transform: rotate(360deg); } }
          #loader-text { flex: 1; }
          #elapsed { color: #8b949e; font-size: .85rem; }

          /* Results */
          #results-section { margin-top: 1.5rem; }
          pre#out {
            background: #161b22; border: 1px solid #30363d; border-radius: 6px;
            padding: 16px; overflow-x: auto; max-height: 600px; overflow-y: auto;
            font-size: .82rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word;
          }
          .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: .75rem; font-weight: 600; margin-left: 6px; }
          .badge-online { background: #238636; color: #fff; }
          .badge-offline { background: #da3633; color: #fff; }
        </style>
      </head>
      <body>
        <h1>&#128737; CodeGuardian — Upload / Paste / Fetch</h1>

        <h2>Upload files (single or multiple)</h2>
        <form id="fileForm">
          <input type="file" id="files" name="files" multiple />
          <button type="button" onclick="submitFiles()">Upload &amp; Scan</button>
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
          <textarea id="code" placeholder="Paste your code here..."></textarea>
          <br/>
          <button type="button" onclick="submitPaste()">Submit Code</button>
        </form>

        <h2>Fetch from URL</h2>
        <form id="urlForm">
          <input type="url" id="url" placeholder="https://example.com/file.py" />
          <button type="button" onclick="submitURL()">Fetch &amp; Scan</button>
        </form>

        <!-- Loading indicator -->
        <div id="loader">
          <div class="spinner"></div>
          <span id="loader-text">Scanning...</span>
          <span id="elapsed"></span>
        </div>

        <div id="results-section">
          <h2>Results</h2>
          <pre id="out">No results yet.</pre>
        </div>

        <script>
        let timerInterval = null;

        function showLoader(message) {
          const loader = document.getElementById('loader');
          const loaderText = document.getElementById('loader-text');
          const elapsed = document.getElementById('elapsed');
          const outEl = document.getElementById('out');

          loaderText.textContent = message || 'Processing...';
          elapsed.textContent = '0s';
          loader.classList.add('active');
          outEl.textContent = '';

          // Disable all buttons
          document.querySelectorAll('button').forEach(b => b.disabled = true);

          const start = Date.now();
          timerInterval = setInterval(() => {
            const secs = Math.floor((Date.now() - start) / 1000);
            elapsed.textContent = secs + 's';
            // Update status messages as time progresses
            if (secs >= 3 && secs < 10) loaderText.textContent = 'Running pattern engine & sending to NIM LLM...';
            else if (secs >= 10 && secs < 25) loaderText.textContent = 'Waiting for NIM inference model response...';
            else if (secs >= 25 && secs < 60) loaderText.textContent = 'Still processing — enriching issues with LLM explanations...';
            else if (secs >= 60) loaderText.textContent = 'Almost done — large file takes longer...';
          }, 1000);
        }

        function hideLoader() {
          document.getElementById('loader').classList.remove('active');
          document.querySelectorAll('button').forEach(b => b.disabled = false);
          if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
        }

        async function doScan(fd, label) {
          showLoader('Uploading ' + label + '...');
          try {
            const res = await fetch('/upload', { method: 'POST', body: fd });
            const j = await res.json();
            hideLoader();
            document.getElementById('out').textContent = JSON.stringify(j, null, 2);
          } catch (err) {
            hideLoader();
            document.getElementById('out').textContent = 'Error: ' + err.message;
          }
        }

        async function submitFiles(){
          const files = document.getElementById('files').files;
          if (!files.length) { alert('Please select a file first.'); return; }
          const fd = new FormData();
          for (let f of files) fd.append('files', f);
          await doScan(fd, files.length + ' file(s)');
        }
        async function submitArchive(){
          const f = document.getElementById('archive').files[0];
          if (!f) { alert('Please select an archive first.'); return; }
          const fd = new FormData();
          fd.append('files', f);
          await doScan(fd, f.name);
        }
        async function submitPaste(){
          const code = document.getElementById('code').value;
          if (!code.trim()) { alert('Please paste some code first.'); return; }
          const filename = document.getElementById('pasteFilename').value || 'pasted.py';
          const fd = new FormData();
          fd.append('code', code);
          fd.append('filename', filename);
          await doScan(fd, filename);
        }
        async function submitURL(){
          const url = document.getElementById('url').value;
          if (!url.trim()) { alert('Please enter a URL first.'); return; }
          const fd = new FormData();
          fd.append('url', url);
          await doScan(fd, url);
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
    """Run Stage-2 engine scan and optionally Stage-3 NIM enrichment.

    When CODEGUARDIAN_LLM_MODE == 'nim' the Reasoner is invoked so that each
    finding is enriched via the NIM inference model and the knowledge-store
    uses NIM embeddings for retrieval.  In offline mode we return the raw
    engine results for fast, deterministic output.
    """
    try:
        res = engine.scan_code(filename, content)
        all_issues = res.get("issues", [])

        if not all_issues:
            return {
                "filename": filename,
                "issue": res.get("issue"),
                "suggestion": res.get("suggestion"),
            }

        # Convert engine issues → Stage-2 format expected by the Reasoner
        stage2_issues = []
        lines = content.splitlines()
        for iss in all_issues:
            # engine issues have 'issue' and 'suggestion' keys
            issue_text = iss.get("issue", "")
            suggestion = iss.get("suggestion", "")
            # try to find the first relevant line number
            line_no = iss.get("line")
            snippet = iss.get("snippet", "")
            if not line_no:
                # best-effort: search for a matching line
                for idx, ln in enumerate(lines, 1):
                    if _issue_matches_line(issue_text, ln):
                        line_no = idx
                        snippet = ln.strip()
                        break
            stage2_issues.append({
                "type": issue_text,
                "line": line_no,
                "snippet": snippet,
                "message": suggestion,
            })

        # If NIM mode is active, enrich through Stage-3 (inference + embeddings)
        llm_mode = os.environ.get("CODEGUARDIAN_LLM_MODE", "offline")
        if llm_mode == "nim":
            try:
                enriched = reasoner.enrich({filename: stage2_issues})
                # persist the report
                try:
                    persistence.save_report(filename, enriched.get("summary", {}), enriched)
                except Exception:
                    pass
                return {
                    "filename": filename,
                    "enriched": True,
                    "llm_mode": "nim",
                    "results": enriched.get("results", {}),
                    "summary": enriched.get("summary", {}),
                }
            except Exception:
                logger.exception("Stage-3 NIM enrichment failed; returning engine results")

        # Offline / fallback: still enrich through Stage-3 offline templates
        try:
            enriched = reasoner.enrich({filename: stage2_issues})
            try:
                persistence.save_report(filename, enriched.get("summary", {}), enriched)
            except Exception:
                pass
            return {
                "filename": filename,
                "enriched": True,
                "llm_mode": llm_mode,
                "results": enriched.get("results", {}),
                "summary": enriched.get("summary", {}),
            }
        except Exception:
            logger.exception("Stage-3 enrichment failed; returning raw engine results")
            return {
                "filename": filename,
                "issues": all_issues,
            }
    except Exception as e:
        return {"filename": filename, "error": str(e)}


def _issue_matches_line(issue_text: str, line: str) -> bool:
    """Heuristic: does the engine issue text relate to this source line?"""
    it = issue_text.lower()
    ln = line.lower()
    if "password" in it and ("password" in ln or "passwd" in ln):
        return True
    if "api key" in it and ("api_key" in ln or "apikey" in ln):
        return True
    if "aws" in it and "akia" in ln:
        return True
    if "jwt" in it and "eyj" in ln:
        return True
    if "secret" in it and "secret" in ln:
        return True
    if "sql" in it and ("select" in ln or "insert" in ln):
        return True
    if "eval" in it and "eval" in ln:
        return True
    if "pickle" in it and "pickle" in ln:
        return True
    if "shell" in it and "shell" in ln:
        return True
    if "md5" in it or "sha1" in it or "sha-1" in it:
        if "md5" in ln or "sha1" in ln:
            return True
    if "strcpy" in it and "strcpy" in ln:
        return True
    if "system" in it and "system" in ln:
        return True
    if "regex" in it and "re." in ln:
        return True
    return False


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
    logger.info("/upload called: files=%s code_present=%s url=%s", bool(files), code is not None, bool(url))
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

    if results:
        logger.info("/upload returning %d result(s) for uploaded files", len(results))
        return JSONResponse({"results": results})

    # Process pasted code
    if code is not None:
        fn = filename or "pasted.py"
        results.append(_scan_and_pack(fn, code))
        logger.info("/upload returning %d result(s) for pasted code (%s)", len(results), fn)
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
        logger.info("/upload returning %d result(s) for fetched URL %s", len(results), url)
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
    logger.info("/analyze called: backend=%s stage2_provided=%s files=%s code_present=%s", backend, bool(stage2), bool(files), code is not None)

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
        logger.info("/analyze returned enriched stage2 with total_issues=%s", enriched.get("summary", {}).get("total_issues"))
        return JSONResponse(enriched)

    results = []
    # uploaded files
    if files:
        import tempfile, os
        for f in files:
            try:
                data = await f.read()
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue
            # Write to a temp file so analyze_code can read it from disk
            fname = f.filename or "uploaded"
            suffix = os.path.splitext(fname)[1] or ".txt"
            with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as tf:
                tf.write(text)
                tmp_path = tf.name
            try:
                issues = stage2_parser.analyze_code(tmp_path)
            except Exception:
                issues = []
            finally:
                os.unlink(tmp_path)
            enriched = req_reasoner.enrich({fname: issues})
            # persist
            try:
                persistence.save_report(f.filename or "uploaded", enriched.get("summary", {}), enriched)
            except Exception:
                pass
            results.append(enriched)
    if results:
        logger.info("/analyze returning %d enriched result(s) for uploaded files", len(results))
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
        logger.info("/analyze returning enriched result for pasted file %s (total_issues=%s)", fn, enriched.get("summary", {}).get("total_issues"))
        return JSONResponse(enriched)

    return JSONResponse({"error": "No input provided to analyze"}, status_code=400)


@app.post("/analyze_json")
async def analyze_json(payload: dict = Body(...)):
    """Accept a pure JSON payload for programmatic use.

    Expected shape: {"stage2": {file: [issues]}, "backend": "sagemaker"}
    This is a convenience endpoint for clients that prefer application/json.
    """
    stage2 = payload.get("stage2")
    backend = payload.get("backend")

    if not stage2:
        logger.warning("/analyze_json called with no stage2 payload")
        return JSONResponse({"error": "No stage2 payload provided"}, status_code=400)

    # If a backend is specified for this request, create a request-scoped Reasoner
    req_reasoner = reasoner
    if backend:
        try:
            req_reasoner = Reasoner(llm_mode=backend)
        except Exception:
            req_reasoner = reasoner

    enriched = req_reasoner.enrich(stage2)
    # persist the report (best-effort)
    try:
        persistence.save_report("stage2_input", enriched.get("summary", {}), enriched)
    except Exception:
        pass
    logger.info("/analyze_json returned enriched stage2 with total_issues=%s (backend=%s)", enriched.get("summary", {}).get("total_issues"), backend)
    return JSONResponse(enriched)


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
    logger.info("/summary ran on path=%s total_issues=%s", path, enriched.get("summary", {}).get("total_issues"))
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
