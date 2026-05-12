import argparse
import json
import os
import re
import smtplib
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})?"
    r".*?(?P<level>ERROR|CRITICAL|FATAL)",
    re.IGNORECASE,
)

STATE_FILE = Path("data/.monitor_state.json")
REPORTS_DIR = Path("data/reports")

def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"seen_hashes": [], "last_line": 0}

def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def scan_log(log_path, last_line=0):
    matches = []
    with open(log_path) as f:
        for i, line in enumerate(f):
            if i < last_line:
                continue
            m = LOG_PATTERN.search(line)
            if m:
                matches.append({
                    "line_no": i + 1,
                    "timestamp": m.group("timestamp") or datetime.utcnow().isoformat(),
                    "level": m.group("level").upper(),
                    "raw": line.strip(),
                })
    return matches

def build_basic_report(errors):
    lines = [
        f"# Log Monitor Report — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"\n**Errors detected:** {len(errors)}\n",
        "## Error List\n",
    ]
    for e in errors:
        lines.append(f"- `[{e['timestamp']}]` **{e['level']}** — {e['raw']}")
    return "\n".join(lines)

def save_report(content, suffix=""):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H%M%S")
    path = REPORTS_DIR / f"incident_{ts}{suffix}.md"
    path.write_text(content)
    print(f"[monitor] Report saved → {path}")
    return path

def send_email(subject, body, use_tls=False):
    sender = os.environ["EMAIL_USER"]
    password = os.environ["EMAIL_PASS"]
    recipient = os.environ.get("EMAIL_TO", sender)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.attach(MIMEText(body, "plain"))
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", 587 if use_tls else 465))
    if use_tls:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
    else:
        with smtplib.SMTP_SSL(host, port) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
    print(f"[monitor] Email sent → {recipient}")

def run_ai_pipeline(errors, send_telegram=False):
    sys.path.insert(0, str(Path(__file__).parent))
    from ai.ai_analyser import analyse
    from ai.report_builder import build_ai_report
    print(f"[ai] Sending {len(errors)} errors to Claude...")
    diagnosis = analyse(errors)
    report_md = build_ai_report(errors, diagnosis)
    save_report(report_md, suffix="_ai")
    if send_telegram:
        from ai.telegram_notifier import send as tg_send
        print("[ai] Sending to Telegram...")
        tg_send(report_md)
    return report_md

def parse_args():
    parser = argparse.ArgumentParser(description="Log Monitor & Alert System")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--email", action="store_true", help="Send SMTP email")
    parser.add_argument("--smtp-tls", action="store_true", help="Use STARTTLS")
    parser.add_argument("--ai", action="store_true", help="Run Claude AI analysis")
    parser.add_argument("--telegram", action="store_true", help="Send to Telegram")
    parser.add_argument("--reset", action="store_true", help="Reset state")
    return parser.parse_args()

def main():
    args = parse_args()
    state = load_state()
    if args.reset:
        state = {"seen_hashes": [], "last_line": 0}
        print("[monitor] State reset.")
    print(f"[monitor] Scanning {args.log} from line {state['last_line']}...")
    errors = scan_log(args.log, last_line=state["last_line"])
    with open(args.log) as f:
        total_lines = sum(1 for _ in f)
    state["last_line"] = total_lines
    save_state(state)
    if not errors:
        print("[monitor] No new errors detected.")
        return
    print(f"[monitor] {len(errors)} error(s) found.")
    basic_report = build_basic_report(errors)
    save_report(basic_report)
    if args.email:
        send_email(f"[ALERT] {len(errors)} log error(s)", basic_report, use_tls=args.smtp_tls)
    if args.ai:
        run_ai_pipeline(errors, send_telegram=args.telegram)

if __name__ == "__main__":
    main()
