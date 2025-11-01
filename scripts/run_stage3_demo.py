import os
import json
from pathlib import Path

from agent import parser
from agent.reasoning import Reasoner
try:
    # load .env if present to make it easy to run the demo with local keys
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / '.env')
except Exception:
    # python-dotenv not installed or .env missing -- that's fine
    pass


def main():
    # Force nim mode to use test-friendly fake client when available
    os.environ["CODEGUARDIAN_LLM_MODE"] = "nim"

    sample = Path(__file__).parent.parent / "input" / "test_insecure.py"
    if not sample.exists():
        print("sample input missing:", sample)
        return

    issues = parser.analyze_code(str(sample))
    print(f"Stage2 found {len(issues)} issues")

    r = Reasoner(llm_mode="nim")
    # print LLM client status
    try:
        print(f"LLM client mode={r.llm.mode} online_available={r.llm.online_available}")
    except Exception:
        pass

    out = r.enrich({str(sample): issues})

    # Ensure Output directory exists at repo root
    output_dir = Path(__file__).parent.parent / "Output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save enriched Stage3 output with timestamped filename
    from datetime import datetime

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_file = output_dir / f"stage3-{ts}.json"
    with out_file.open("w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

    print(f"Saved Stage3 output to: {out_file}")
    # Also save a cleaned copy for easy consumption (suffix .cleaned.json)
    cleaned_file = output_dir / f"stage3-{ts}.cleaned.json"
    try:
        with cleaned_file.open("w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        print(f"Saved cleaned Stage3 output to: {cleaned_file}")
    except Exception:
        # if writing cleaned fails, continue silently
        pass
    # Also print a short summary to stdout
    try:
        summary = out.get("summary") or {}
        total = summary.get("total_issues", sum(len(v) for v in out.get("files", {}).values()) if out.get("files") else 0)
        print(f"Summary: total_issues={total}  summary_keys={list(summary.keys())}")
    except Exception:
        pass
    # report how many issues used online vs offline explain
    try:
        counts = {"online": 0, "offline": 0}
        for fp, issues in out.get("results", {}).items():
            for it in issues:
                used = it.get("llm_used", "offline")
                counts[used] = counts.get(used, 0) + 1
        print(f"LLM usage: online={counts['online']} offline={counts['offline']}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
