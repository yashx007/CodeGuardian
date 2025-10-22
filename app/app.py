"""FastAPI application for CodeGuardian minimal scaffold."""

from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel

from agent.engine import engine


app = FastAPI(title="CodeGuardian API")


class ScanResult(BaseModel):
    issue: str
    suggestion: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResult)
async def scan(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")
    filename = file.filename or "uploaded_file"
    res = engine.scan_code(filename, content)
    return ScanResult(issue=res["issue"], suggestion=res["suggestion"])
