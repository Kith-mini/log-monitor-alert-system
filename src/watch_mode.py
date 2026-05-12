"""
watch_mode.py
Real-time log watcher. Checks the log file every INTERVAL seconds.
When new errors appear, triggers the full AI pipeline automatically.
Run: python src/watch_mode.py --log data/sample.log --interval 30
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))

from log_monitor import scan_log, save_report, build_basic_report, load_state, save_state


def log(msg: str) -> None:
    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def run_ai(errors: list, send_telegram: bool) -> None:
    from ai.ai_analyser import analyse
    from ai.report_builder import build_ai_report
    from ai.telegram_notifier import send as tg_send

    log(f"Sending {len(errors)} error(s) to Claude...")
    diagnosis = analyse(errors)
    log(f"Severity: {diagnosis['severity']} | Root cause: {diagnosis['root_cause'][:60]}...")
    report_md = build_ai_report(errors, diagnosis)
    save_report(report_md, suffix="_ai")

    if send_telegram:
        log("Sending report to Telegram...")
        tg_send(report_md)
        log("Telegram delivered.")


def watch(log_path: str, interval: int, send_telegram: bool, ai: bool) -> None:
    log(f"Watching {log_path} every {interval}s  |  AI={ai}  |  Telegram={send_telegram}")
    log("Press Ctrl+C to stop.\n")

    consecutive_empty = 0

    while True:
        try:
            state = load_state()
            errors = scan_log(log_path, last_line=state["last_line"])

            with open(log_path) as f:
                total_lines = sum(1 for _ in f)
            state["last_line"] = total_lines
            save_state(state)

            if errors:
                consecutive_empty = 0
                log(f"Found {len(errors)} new error(s)!")
                save_report(build_basic_report(errors))

                if ai:
                    run_ai(errors, send_telegram)
                else:
                    log("No AI flag — basic report only.")
            else:
                consecutive_empty += 1
                if consecutive_empty % 10 == 1:
                    log(f"No new errors. Watching... (check #{consecutive_empty})")

            time.sleep(interval)

        except KeyboardInterrupt:
            log("Watch mode stopped.")
            break
        except FileNotFoundError:
            log(f"ERROR: Log file not found: {log_path}")
            log("Retrying in 10 seconds...")
            time.sleep(10)
        except Exception as e:
            log(f"Unexpected error: {e}")
            log("Retrying in 10 seconds...")
            time.sleep(10)


def parse_args():
    parser = argparse.ArgumentParser(description="Real-time log watcher")
    parser.add_argument("--log",      required=True, help="Path to log file to watch")
    parser.add_argument("--interval", type=int, default=30, help="Check every N seconds (default: 30)")
    parser.add_argument("--ai",       action="store_true", help="Run Claude AI analysis on errors")
    parser.add_argument("--telegram", action="store_true", help="Send report to Telegram")
    parser.add_argument("--reset",    action="store_true", help="Reset state before watching")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.reset:
        from log_monitor import save_state
        save_state({"seen_hashes": [], "last_line": 0})
        log("State reset.")

    watch(
        log_path=args.log,
        interval=args.interval,
        send_telegram=args.telegram,
        ai=args.ai,
    )


if __name__ == "__main__":
    main()
