#!/usr/bin/env python3
"""
Log Monitoring & Alert System (Python)

Features:
- Scans a log file for error patterns (regex)
- Creates Markdown + JSON reports (only when matches exist)
- Creates an HTML dashboard report (only when matches exist)
- Sends optional email alerts via SMTP (only when matches exist)
- Uses state file to avoid duplicate alerts
- Watch mode for real-time monitoring (polling every N seconds)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import sys
import time
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
    """
    Reads log file. If use_state=True, continues from last_position and avoids duplicates.
    Returns (events, updated_state).
    """
    state = load_state(state_path) if use_state else {"last_position": 0, "seen_hashes": []}
    last_position = int(state.get("last_position", 0))
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
        state["seen_hashes"] = list(seen_hashes)[-500:]  # keep last 500

    return events, state


def summarize(events: List[Event]) -> Dict:
    counts: Dict[str, int] = {}
    for e in events:
        lvl = e.level.upper()
        counts[lvl] = counts.get(lvl, 0) + 1
    return {"total_matches": len(events), "counts_by_level": counts}


def write_reports(events: List[Event], summary: Dict, reports_dir: Path) -> Tuple[Path, Path]:
    """
    Markdown + JSON
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    md_path = reports_dir / f"report-{stamp}.md"
    json_path = reports_dir / f"report-{stamp}.json"

    # Markdown
    md_lines: List[str] = []
    md_lines.append(f"# Log Monitoring Report ({stamp})\n\n")
    md_lines.append("## Summary\n")
    md_lines.append(f"- Total matches: **{summary['total_matches']}**\n")
    md_lines.append("### Counts by Level\n")
    for k, v in summary["counts_by_level"].items():
        md_lines.append(f"- {k}: {v}\n")

    md_lines.append("\n## Events\n")
    for e in events:
        md_lines.append(f"- **{e.timestamp}** [{e.level}] {e.message}\n")

    md_path.write_text("".join(md_lines), encoding="utf-8")

    # JSON
    payload = {
        "generated_at": stamp,
        "summary": summary,
        "events": [asdict(e) for e in events],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return md_path, json_path


def write_html_report(events: List[Event], summary: Dict, reports_dir: Path) -> Path:
    """
    Simple HTML dashboard (no external libs)
    Generates report-YYYYmmdd-HHMMSS.html
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    html_path = reports_dir / f"report-{stamp}.html"

    counts = summary.get("counts_by_level", {})
    total = summary.get("total_matches", 0)

    # Table rows
    rows = ""
    for e in events:
        rows += f"<tr><td>{e.timestamp}</td><td>{e.level}</td><td>{e.message}</td></tr>\n"

    # Simple bar chart using CSS widths
    bars = ""
    max_count = max(counts.values()) if counts else 1
    for level, c in counts.items():
        width = int((c / max_count) * 300)  # 300px max
        bars += f"""
        <div class="bar-row">
          <div class="bar-label">{level} ({c})</div>
          <div class="bar" style="width:{width}px;"></div>
        </div>
        """

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Log Monitoring Report {stamp}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    .card {{ border: 1px solid #3333; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f4f4f4; }}
    .bar-row {{ display:flex; align-items:center; gap:12px; margin: 6px 0; }}
    .bar-label {{ width: 140px; font-weight: 600; }}
    .bar {{ height: 14px; background: #4c8bf5; border-radius: 8px; }}
    .muted {{ color:#666; }}
  </style>
</head>
<body>
  <h1>Log Monitoring Report</h1>
  <p class="muted">Generated at: {stamp}</p>

  <div class="card">
    <h2>Summary</h2>
    <p><b>Total matches:</b> {total}</p>
    <h3>Counts by Level</h3>
    {bars if bars else "<p class='muted'>No matches found.</p>"}
  </div>

  <div class="card">
    <h2>Events</h2>
    {"<p class='muted'>No matches found.</p>" if not events else f"""
    <table>
      <thead><tr><th>Timestamp</th><th>Level</th><th>Message</th></tr></thead>
      <tbody>
        {rows}
      </tbody>
    </table>
    """}
  </div>
</body>
</html>
"""
    html_path.write_text(html, encoding="utf-8")
    return html_path


def send_email_alert(
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
    parser.add_argument("--smtp-tls", action="store_true", help="Use STARTTLS for SMTP")
    parser.add_argument("--watch", action="store_true", help="Continuously monitor the log file")
    parser.add_argument("--interval", type=int, default=10, help="Seconds between checks in watch mode")

    args = parser.parse_args()

    # Load from .env / OS env
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

    def run_once() -> int:
        events, state = scan_log(
            log_path=log_path,
            compiled_patterns=compiled,
            use_state=(not args.no_state),
            state_path=Path(args.state),
        )

        # If no new matches, do nothing (important for watch mode)
        if not events:
            print("No new errors detected – skipping report/email")
            return 0

        summary = summarize(events)

        md_path, json_path = write_reports(events, summary, Path(args.reports))
        html_path = write_html_report(events, summary, Path(args.reports))

        print(f"Report written: {md_path}")
        print(f"Report written: {json_path}")
        print(f"Report written: {html_path}")

        if not args.no_state:
            save_state(Path(args.state), state)

        if args.email:
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

    # WATCH MODE
    if args.watch:
        print(f"Watching {log_path} every {args.interval}s (Ctrl+C to stop)...")
        try:
            while True:
                run_once()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Stopped watch mode.")
        return 0

    # NORMAL MODE (single run)
    return run_once()


if __name__ == "__main__":
    raise SystemExit(main())
