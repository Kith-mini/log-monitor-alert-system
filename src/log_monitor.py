#!/usr/bin/env python3
"""
Log Monitoring & Alert System (Python)

- Scans a log file for error patterns (regex)
- Creates Markdown + JSON reports
- Sends optional email alerts via SMTP
- Uses state file to avoid duplicate alerts
"""

from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Event:
    timestamp: str
    level: str
    message: str
    raw: str


DEFAULT_PATTERNS = [
    r"\bERROR\b",
    r"\bCRITICAL\b",
    r"\bFATAL\b",
]


def load_state(state_path: Path) -> Dict:
    if not state_path.exists():
        return {"last_position": 0, "seen_hashes": []}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {"last_position": 0, "seen_hashes": []}


def save_state(state_path: Path, state: Dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def hash_line(line: str) -> str:
    return str(abs(hash(line)))


def parse_event_line(line: str) -> Optional[Event]:
    m = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)$", line.strip())
    if not m:
        return None
    ts, level, msg = m.group(1), m.group(2), m.group(3)
    return Event(timestamp=ts, level=level, message=msg, raw=line.rstrip("\n"))


def compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def matches_any(line: str, compiled_patterns: List[re.Pattern]) -> bool:
    return any(p.search(line) for p in compiled_patterns)


def scan_log(
    log_path: Path,
    compiled_patterns: List[re.Pattern],
    use_state: bool,
    state_path: Path,
) -> Tuple[List[Event], Dict]:
    state = load_state(state_path) if use_state else {"last_position": 0, "seen_hashes": []}
    last_position = state.get("last_position", 0)
    seen_hashes = set(state.get("seen_hashes", []))

    events: List[Event] = []

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        if use_state:
            f.seek(last_position)

        for line in f:
            if not line.strip():
                continue
            if not matches_any(line, compiled_patterns):
                continue

            line_id = hash_line(line)
            if use_state and line_id in seen_hashes:
                continue

            parsed = parse_event_line(line)
            if parsed is None:
                parsed = Event(timestamp="unknown", level="unknown", message=line.strip(), raw=line.strip())
            events.append(parsed)

            if use_state:
                seen_hashes.add(line_id)

        new_position = f.tell()

    if use_state:
        state["last_position"] = new_position
        state["seen_hashes"] = list(seen_hashes)[-500:]

    return events, state


def summarize(events: List[Event]) -> Dict:
    counts: Dict[str, int] = {}
    for e in events:
        counts[e.level.upper()] = counts.get(e.level.upper(), 0) + 1
    return {"total_matches": len(events), "counts_by_level": counts}


def write_reports(events: List[Event], summary: Dict, reports_dir: Path) -> Tuple[Path, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    md_path = reports_dir / f"report-{stamp}.md"
    json_path = reports_dir / f"report-{stamp}.json"

    md_lines = []
    md_lines.append(f"# Log Monitoring Report ({stamp})\n\n")
    md_lines.append("## Summary\n")
    md_lines.append(f"- Total matches: **{summary['total_matches']}**\n")
    md_lines.append("### Counts by Level\n")
    for k, v in summary["counts_by_level"].items():
        md_lines.append(f"- {k}: {v}\n")

    md_lines.append("\n## Events\n")
    if not events:
        md_lines.append("_No matches found._\n")
    else:
        for e in events:
            md_lines.append(f"- **{e.timestamp}** [{e.level}] {e.message}\n")

    md_path.write_text("".join(md_lines), encoding="utf-8")

    payload = {
        "generated_at": stamp,
        "summary": summary,
        "events": [asdict(e) for e in events],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return md_path, json_path


def send_email_alert(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    mail_from: str,
    mail_to: str,
    subject: str,
    body: str,
    use_tls: bool,
) -> None:
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.set_content(body)

    server = smtplib.SMTP(smtp_host, smtp_port)
    try:
        if use_tls:
            server.starttls()
        if smtp_user:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)
    finally:
        server.quit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Log Monitoring & Alert System")
    parser.add_argument("--log", default="data/sample.log", help="Path to log file")
    parser.add_argument("--pattern", action="append", help="Regex pattern (repeatable)")
    parser.add_argument("--no-state", action="store_true", help="Disable state (dedupe + last position)")
    parser.add_argument("--state", default="data/state.json", help="Path to state file")
    parser.add_argument("--reports", default="reports", help="Reports output directory")

    parser.add_argument("--email", action="store_true", help="Send email alert if matches found")
    parser.add_argument("--smtp-tls", action="store_true", help="Use STARTTLS")

    args = parser.parse_args()

    # Load from .env or OS env
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    mail_from = os.getenv("MAIL_FROM", "")
    mail_to = os.getenv("MAIL_TO", "")

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"ERROR: log file not found: {log_path}", file=sys.stderr)
        return 2

    patterns = args.pattern if args.pattern else DEFAULT_PATTERNS
    compiled = compile_patterns(patterns)

    events, state = scan_log(
        log_path=log_path,
        compiled_patterns=compiled,
        use_state=(not args.no_state),
        state_path=Path(args.state),
    )

    summary = summarize(events)
    md_path, json_path = write_reports(events, summary, Path(args.reports))

    print(f"Report written: {md_path}")
    print(f"Report written: {json_path}")

    if not args.no_state:
        save_state(Path(args.state), state)

    if args.email and events:
        missing = []
        if not smtp_host:
            missing.append("SMTP_HOST")
        if not mail_from:
            missing.append("MAIL_FROM")
        if not mail_to:
            missing.append("MAIL_TO")
        if not smtp_pass:
            missing.append("SMTP_PASS (App Password)")

        if missing:
            print("Email not sent. Missing settings:", ", ".join(missing), file=sys.stderr)
            return 3

        subject = f"[ALERT] Log monitor found {summary['total_matches']} event(s)"
        body_lines = [
            "Log Monitor Alert",
            "",
            f"Total matches: {summary['total_matches']}",
            f"Counts: {summary['counts_by_level']}",
            "",
            "Top events:",
        ]
        for e in events[:10]:
            body_lines.append(f"- {e.timestamp} [{e.level}] {e.message}")

        send_email_alert(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_pass=smtp_pass,
            mail_from=mail_from,
            mail_to=mail_to,
            subject=subject,
            body="\n".join(body_lines),
            use_tls=args.smtp_tls,
        )
        print("Email alert sent.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
