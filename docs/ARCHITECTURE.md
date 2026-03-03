# CodeGuardian — System Architecture

## Overview
CodeGuardian is an end‑to‑end system for detecting code security issues, generating human‑readable explanations and remediation suggestions, and persisting audit reports. It combines a static analysis Stage‑2 engine with an LLM‑backed Stage‑3 Reasoner, supports archive and multi‑file ingestion, and uses NVIDIA NIM for model inference with an offline template fallback.

## High‑level Components
- Frontend (Browser UI): small HTML uploader served by the FastAPI app (`GET /`).
- FastAPI App (`app/app.py`): HTTP endpoints for upload, analyze and history.
- Stage‑2 Engine (`agent/engine.py`): static parsing and issue detection; returns issues per file.
- Reasoner (`agent/reasoning.py`): orchestrates LLM calls, retrieval from KB, and enrichment of Stage‑2 findings.
- LLM clients (`agent/llm_client.py`): modes: `offline`, `nim`.
- NIM wrapper (`agent/nim_client.py`): inference and embedding helpers.
- Knowledge Base (KB + embeddings): retrieval store (FAISS or similar) used to ground prompts.
- Persistence (`agent/persistence.py`): SQLite-backed storage of reports and chat sessions (`data/reports.db`).

## Data Flow
1. User uploads files/pastes code/provides URL to `POST /upload`.
2. Server extracts archives, decodes text, and calls `engine.scan_code(filename, content)`.
3. Stage‑2 returns issues (type, line, snippet, message) per file.
4. `Reasoner.enrich(stage2)` retrieves KB context, constructs prompts and calls `LLMClient.explain()`.
5. LLM (NIM or offline templates) returns explanation/fix/references.
6. Enriched report is persisted via `persistence.save_report(...)` and returned as JSON to client.

## API Summary
- `GET /` — uploader UI.
- `POST /upload` — multipart upload or paste/URL; returns `{"results": [...]}`.
- `POST /analyze` — analyze with optional `backend` (llm mode); returns enriched JSON.
- `POST /analyze_json` — accepts Stage‑2 JSON payload and optional `backend`.
- `GET /summary`, `GET /history` — summary and persisted report listing.

## Persistence Schema
SQLite `reports` table:
- `id INTEGER PRIMARY KEY`
- `filename TEXT`
- `timestamp TEXT`
- `summary TEXT` (JSON)
- `payload TEXT` (full report JSON)

Chat sessions stored in `data/sessions.db` with `sessions(session_id, messages, last_active)`.

## Deployment Notes
- Environment variables control LLM backend: `CODEGUARDIAN_LLM_MODE`, `NIM_*`, etc.
- Production recommendations:
  - Run the FastAPI app inside a container behind a reverse proxy (TLS), and restrict LLM API keys to least privilege.
  - Use a managed DB or ensure `data/` is persisted across restarts.
  - Add rate limiting and request size limits on `POST /upload`.

## Security Considerations
- Secrets: keep `NIM_API_KEY` and other LLM keys out of source control (use a secret manager).
- Validate and sanitize uploaded content; avoid executing untrusted code.
- Use circuit breakers / timeouts for LLM calls and fallback to offline templates.

## Diagrams (PlantUML sources)
PlantUML sources are in `docs/uml/`:
- `er_data_model.puml` — ER diagram for Reports/Findings/Sessions.
- `class_core.puml` — core classes and relationships.
- `use_case.puml` — actors and primary use cases.
- `activity_scan.puml` — activity diagram for upload → analysis → persist flow.
- `sequence_upload_scan.puml` — upload → scan → reasoner → persist sequence.

## How to render PlantUML
Install PlantUML (Java + plantuml.jar) or use VS Code PlantUML extension.

Example CLI (requires `plantuml` on PATH):

```bash
plantuml -tpng docs/uml/sequence_upload_scan.puml
plantuml -tpng docs/uml/class_core.puml
plantuml -tpng docs/uml/er_data_model.puml
plantuml -tpng docs/uml/use_case.puml
plantuml -tpng docs/uml/activity_scan.puml
```

Or preview in VS Code: open `.puml` and use PlantUML preview, then export PNG/SVG.

## Next steps / suggestions
- Render the `.puml` files to PNG/SVG and add them to `docs/` for the project README.
- Optionally add a `docs/uml/README.md` with CI steps to auto‑generate diagrams.

