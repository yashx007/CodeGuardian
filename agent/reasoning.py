"""Stage 3: reasoning engine that converts Stage 2 findings into enriched explanations.

Design:
- Accepts Stage 2 findings (list or dict mapping file->issues)
- Uses LLMClient + KnowledgeBase to produce explanation, fix, severity, and references
- Works offline (deterministic templates) and can switch to online LLM via env
"""

from __future__ import annotations

import os
import logging
from typing import Dict, Any, List, Union

from .llm_client import LLMClient
from .knowledge_base import KnowledgeBase
from .knowledge_store import KnowledgeStore

logger = logging.getLogger("codeguardian.reasoning")


def _map_severity(issue_type: str) -> str:
    t = (issue_type or "").lower()
    if "secret" in t or "hardcoded" in t:
        return "High"
    if "sql" in t or "injection" in t:
        return "High"
    if "deprecated" in t or "deprecated hash" in t:
        return "Medium"
    if "insecure" in t or "suspicious" in t:
        return "Medium"
    if "regex" in t:
        return "Low"
    return "Medium"


class Reasoner:
    def __init__(self, llm_mode: str | None = None):
        self.llm = LLMClient(mode=llm_mode)
        # try to initialize a knowledge store if available
        try:
            # build entries from static KB for retrieval
            static = KnowledgeBase()
            entries = [(k, v.get("summary", "")) for k, v in static._kb.items()]
            self.store = KnowledgeStore(entries=entries)
            self.kb = KnowledgeBase(use_store=True, store=self.store)
        except Exception:
            # fallback to static KB
            self.store = None
            self.kb = KnowledgeBase()

    def enrich_issue(self, file: str, issue: Dict[str, Any]) -> Dict[str, Any]:
        # Base fields
        enriched: Dict[str, Any] = {
            "file": file,
            "type": issue.get("type"),
            "line": issue.get("line"),
            "snippet": issue.get("snippet"),
            "message": issue.get("message"),
        }

        # severity
        severity = _map_severity(issue.get("type", ""))
        enriched["severity"] = severity

        # consult KB
        kb_entry = self.kb.query(issue.get("type", ""))

        # call LLM client for explanation/fix
        try:
            llm_out = self.llm.explain(issue, context={"file": file, "kb": kb_entry})
        except Exception:
            logger.exception("LLM client failed; using fallback templates")
            llm_out = {
                "explanation": issue.get("message", ""),
                "fix": "Review the finding and apply best practices.",
                "references": [],
            }

        enriched["explanation"] = llm_out.get("explanation")
        enriched["fix"] = llm_out.get("fix")
        # prefer LLN-provided references but merge KB refs
        refs = list(llm_out.get("references", []))
        if isinstance(kb_entry, dict):
            for r in kb_entry.get("references", []) if kb_entry.get("references") else []:
                if r not in refs:
                    refs.append(r)
        enriched["references"] = refs

        return enriched

    def enrich(self, findings: Union[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Accept Stage 2 output in two forms:
        - dict mapping filepath -> list of issue dicts
        - list of issue dicts (flattened)

        Returns a dict: {file: [enriched issues]} and global summary.
        """
        results: Dict[str, List[Dict[str, Any]]] = {}
        if isinstance(findings, list):
            # if flat list but items might contain 'file'
            for it in findings:
                fp = it.get("file") or "<unknown>"
                results.setdefault(fp, []).append(it)
        elif isinstance(findings, dict):
            results = {k: v for k, v in findings.items()}
        else:
            raise TypeError("Unsupported findings format")

        enriched_results: Dict[str, List[Dict[str, Any]]] = {}
        for fp, issues in results.items():
            enriched_list: List[Dict[str, Any]] = []
            for it in issues:
                try:
                    enriched_list.append(self.enrich_issue(fp, it))
                except Exception:
                    logger.exception("Failed to enrich issue: %s", it)
            enriched_results[fp] = enriched_list

        # build summary
        counts = {"High": 0, "Medium": 0, "Low": 0}
        for fp, issues in enriched_results.items():
            for it in issues:
                sev = it.get("severity") or "Medium"
                counts[sev] = counts.get(sev, 0) + 1

        # compute overall risk heuristic using weighted scoring
        total = sum(counts.values())
        # weights: High=5, Medium=3, Low=1
        weights = {"High": 5, "Medium": 3, "Low": 1}
        weighted_sum = sum(counts.get(k, 0) * w for k, w in weights.items())
        # normalize by max possible (if all issues were High)
        max_possible = total * weights["High"] if total > 0 else 1
        score = weighted_sum / max_possible if max_possible else 0.0

        if score >= 0.7:
            risk = "High"
        elif score >= 0.3:
            risk = "Medium"
        else:
            risk = "Low"

        # build a human-readable rationale
        rationale_parts = []
        if counts.get("High", 0):
            rationale_parts.append(f"{counts['High']} high-severity issue(s)")
        if counts.get("Medium", 0):
            rationale_parts.append(f"{counts['Medium']} medium-severity issue(s)")
        if counts.get("Low", 0):
            rationale_parts.append(f"{counts['Low']} low-severity issue(s)")
        if not rationale_parts:
            rationale = "No issues detected."
        else:
            rationale = ", ".join(rationale_parts) + "."

        # compute top risky files by weighted file score
        file_scores: Dict[str, int] = {}
        for fp, issues in enriched_results.items():
            s = 0
            for it in issues:
                s += weights.get(it.get("severity") or "Medium", 3)
            file_scores[fp] = s

        top_files = sorted(file_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        top_files_list = [
            {"file": fp, "score": sc, "issues": len(enriched_results.get(fp, []))}
            for fp, sc in top_files
        ]

        return {
            "results": enriched_results,
            "summary": {
                "counts": counts,
                "risk": risk,
                "total_issues": total,
                "score": round(score, 2),
                "rationale": rationale,
                "top_files": top_files_list,
            },
        }


# convenience default reasoner
reasoner = Reasoner()
