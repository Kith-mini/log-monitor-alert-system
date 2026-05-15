import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from dotenv import load_dotenv
load_dotenv()

FAKE_ERRORS = [
    {
        "line_no": 42,
        "timestamp": "2026-05-12T10:21:03",
        "level": "CRITICAL",
        "raw": "2026-05-12T10:21:03 CRITICAL DatabaseConnectionError: connection pool exhausted (pool_size=5)",
    },
    {
        "line_no": 55,
        "timestamp": "2026-05-12T10:21:15",
        "level": "CRITICAL",
        "raw": "2026-05-12T10:21:15 CRITICAL DatabaseConnectionError: connection pool exhausted (pool_size=5)",
    },
    {
        "line_no": 61,
        "timestamp": "2026-05-12T10:21:44",
        "level": "ERROR",
        "raw": "2026-05-12T10:21:44 ERROR TimeoutError: upstream API /payments timed out after 30s",
    },
]

def main():
    print("── Step 1: Analysing with Claude ───────────────────────────────")
    from ai.ai_analyser import analyse
    diagnosis = analyse(FAKE_ERRORS, skip_throttle=True)
    print(f"  Root cause : {diagnosis['root_cause']}")
    print(f"  Severity   : {diagnosis['severity']}")
    print(f"  Tokens used: {diagnosis['tokens_used']}")

    print("\n── Step 2: Building report ──────────────────────────────────────")
    from ai.report_builder import build_ai_report
    report = build_ai_report(FAKE_ERRORS, diagnosis)
    print(report[:800] + "\n…[truncated]" if len(report) > 800 else report)

    print("\n── Step 3: Sending to Telegram ──────────────────────────────────")
    from ai.telegram_notifier import send
    send(report)
    print("  Telegram dispatch complete.")

    print("\n── Smoke test PASSED ────────────────────────────────────────────")

if __name__ == "__main__":
    main()
