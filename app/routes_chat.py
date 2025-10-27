from __future__ import annotations

from typing import Dict, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from uuid import uuid4
import os
from datetime import datetime, timezone

from agent.llm_client import LLMClient
from agent import persistence
import asyncio
from typing import Callable

router = APIRouter()

# In-memory sessions: session_id -> {messages: [...], last_active: isotimestamp}
SESSIONS: Dict[str, Dict] = {}

# session TTL in seconds; 0 means never expire. Default 3600s
DEFAULT_TTL = int(os.environ.get("CHAT_SESSION_TTL_SECONDS", "3600"))
# how many user-assistant turns to keep in context
CHAT_CONTEXT_TURNS = int(os.environ.get("CHAT_CONTEXT_TURNS", "10"))


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str
    backend: Optional[str] = None


class ChatResponse(BaseModel):
    session_id: str
    reply: str
    turns: int


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_expired(session: Dict) -> bool:
    ttl = int(os.environ.get("CHAT_SESSION_TTL_SECONDS", str(DEFAULT_TTL)))
    # ttl <= 0 means never expire
    if ttl <= 0:
        return False
    last = session.get("last_active")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
    except Exception:
        return True
    age = (datetime.now(timezone.utc) - last_dt).total_seconds()
    return age > ttl


@router.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    # ensure session id
    sid = req.session_id or str(uuid4())

    # attempt to load persisted session if not in memory
    if sid not in SESSIONS:
        loaded = persistence.load_session(sid)
        if loaded:
            SESSIONS[sid] = {"messages": loaded.get("messages", []), "last_active": loaded.get("last_active")}

    # create session structure if missing or expired
    if sid in SESSIONS and _is_expired(SESSIONS[sid]):
        # remove from memory and persistence
        try:
            persistence.delete_session(sid)
        except Exception:
            pass
        del SESSIONS[sid]

    if sid not in SESSIONS:
        SESSIONS[sid] = {"messages": [], "last_active": _now_iso()}

    session = SESSIONS[sid]

    # append user message
    session["messages"].append({"role": "user", "text": req.message})

    # build a synthetic 'issue' to reuse LLMClient.explain interface
    issue = {"type": "chat", "message": req.message, "snippet": "", "line": 0}

    # include conversation history in context (trim to recent turns)
    max_msgs = CHAT_CONTEXT_TURNS * 2
    recent = session["messages"][-max_msgs:]
    history_text = "\n".join([f"{m['role']}: {m['text']}" for m in recent])
    context = {"history": history_text}

    # initialize LLM client with optional backend override
    client = LLMClient(mode=req.backend if req.backend else None)
    try:
        out = client.explain(issue, context=context)
        reply = out.get("explanation") or out.get("fix") or ""
    except Exception:
        reply = "(LLM unavailable)"

    # append assistant reply and update last_active
    session["messages"].append({"role": "assistant", "text": reply})
    session["last_active"] = _now_iso()

    # persist session (best-effort)
    try:
        persistence.save_session(sid, session["messages"], session["last_active"])
    except Exception:
        pass

    return ChatResponse(session_id=sid, reply=reply, turns=len(session["messages"]))


class ChatHistoryResponse(BaseModel):
    session_id: str
    messages: List[Dict]
    last_active: Optional[str]


@router.get("/chat/{session_id}/history", response_model=ChatHistoryResponse)
def chat_history(session_id: str):
    # try in-memory first
    if session_id not in SESSIONS:
        # try to load from persistence
        loaded = persistence.load_session(session_id)
        if not loaded:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")
        SESSIONS[session_id] = {"messages": loaded.get("messages", []), "last_active": loaded.get("last_active")}

    session = SESSIONS[session_id]
    if _is_expired(session):
        # expire and remove from memory and persistence
        try:
            persistence.delete_session(session_id)
        except Exception:
            pass
        del SESSIONS[session_id]
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session expired")

    return ChatHistoryResponse(session_id=session_id, messages=session["messages"], last_active=session.get("last_active"))


@router.delete("/chat/{session_id}")
def chat_delete(session_id: str):
    # remove from memory
    if session_id in SESSIONS:
        del SESSIONS[session_id]
    # remove persisted
    try:
        persistence.delete_session(session_id)
    except Exception:
        pass
    return {}, 204


def evict_expired_once() -> int:
    """Perform a single eviction pass. Returns number of sessions removed."""
    removed = 0
    # check in-memory sessions
    for sid in list(SESSIONS.keys()):
        session = SESSIONS.get(sid)
        if session and _is_expired(session):
            try:
                persistence.delete_session(sid)
            except Exception:
                pass
            del SESSIONS[sid]
            removed += 1

    # check persisted sessions that might not be in memory
    try:
        for meta in persistence.list_sessions():
            sid = meta.get("session_id")
            if not sid:
                continue
            last_active = meta.get("last_active")
            # construct a small session-like object for expiry check
            session_like = {"last_active": last_active}
            if _is_expired(session_like):
                try:
                    persistence.delete_session(sid)
                    removed += 1
                except Exception:
                    pass
    except Exception:
        # best-effort; ignore persistence read errors
        pass

    return removed


async def _evict_loop(interval: int):
    while True:
        try:
            removed = evict_expired_once()
            if removed:
                # minor logging to stdout for debug in dev (non-blocking)
                print(f"chat-evict: removed {removed} expired sessions")
        except Exception:
            pass
        await asyncio.sleep(interval)


# Background eviction task handle
_EVICTOR_TASK: Optional[asyncio.Task] = None


@router.on_event("startup")
async def _start_evictor():
    global _EVICTOR_TASK
    try:
        interval = int(os.environ.get("CHAT_EVICT_INTERVAL_SECONDS", "60"))
    except Exception:
        interval = 60
    if _EVICTOR_TASK is None:
        _EVICTOR_TASK = asyncio.create_task(_evict_loop(interval))


@router.on_event("shutdown")
async def _stop_evictor():
    global _EVICTOR_TASK
    if _EVICTOR_TASK is not None:
        _EVICTOR_TASK.cancel()
        try:
            await _EVICTOR_TASK
        except Exception:
            pass
        _EVICTOR_TASK = None
