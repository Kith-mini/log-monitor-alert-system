# AI-Powered Log Monitoring & Alert System

A Python-based DevOps tool that monitors log files in real-time, detects critical events, analyses them with Claude AI, generates incident reports, sends alerts via email and Telegram, and displays them in a web dashboard.

## Features

- Regex detection for ERROR / CRITICAL / FATAL logs
- Automated Markdown & JSON reports saved to disk
- SMTP email alerts using secure .env configuration
- State tracking to avoid duplicate alerts
- AI-powered root cause analysis using Claude API
- Severity rating — CRITICAL / HIGH / MEDIUM / LOW
- AI-generated remediation steps
- Telegram incident report notifications
- Real-time watch mode — monitors log continuously
- Web dashboard — view all reports in browser
- Cron job support — runs automatically every 5 minutes
- Ubuntu + VS Code + Git workflow

## Tech Stack

- Python 3.12
- Claude API (Anthropic) — AI analysis
- Flask — web dashboard
- Telegram Bot API — notifications
- SMTP (Gmail App Password) — email alerts
- Regex — log pattern detection
- Git & GitHub — version control

## How It Works

1. Script reads log file line by line
2. Regex matches ERROR / CRITICAL / FATAL patterns
3. Matched errors sent to Claude API for analysis
4. Claude identifies root cause, severity, remediation steps
5. Incident report saved to data/reports/
6. Alert sent via email and/or Telegram
7. Dashboard displays all reports at localhost:5000

## Project Structure

```
log-monitor-alert-system/
├── src/
│   ├── log_monitor.py           # Main script
│   ├── watch_mode.py            # Real-time watcher (Phase 2)
│   ├── dashboard.py             # Web dashboard (Phase 3)
│   └── ai/
│       ├── __init__.py
│       ├── ai_analyser.py       # Claude API integration
│       ├── error_extractor.py   # Error structuring
│       ├── report_builder.py    # Incident report builder
│       └── telegram_notifier.py # Telegram delivery
├── data/
│   ├── sample.log
│   └── reports/                 # AI reports saved here
├── systemd/
│   └── log-monitor.service
├── test_ai_pipeline.py
├── requirements.txt
└── .env.example
```

## Setup

```bash
git clone https://github.com/Kith-mini/log-monitor-alert-system.git
cd log-monitor-alert-system
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
```

## Environment Variables

```
ANTHROPIC_API_KEY=sk-ant-...
TELEGRAM_BOT_TOKEN=your_token
TELEGRAM_CHAT_ID=your_chat_id
EMAIL_USER=you@gmail.com
EMAIL_PASS=your_app_password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
```

## Run Commands

```bash
# One-time scan with email
python src/log_monitor.py --log data/sample.log --email --smtp-tls

# One-time scan with AI + Telegram
python src/log_monitor.py --log data/sample.log --ai --telegram

# Real-time watch mode (Phase 2)
# Checks every 30 seconds, auto-alerts on new errors
python src/watch_mode.py --log data/sample.log --ai --telegram

# Web dashboard (Phase 3)
# Open http://localhost:5000 in your browser after running
python src/dashboard.py

# Smoke test
python test_ai_pipeline.py
```

## Cron Job Setup (Phase 4)

To run automatically every 5 minutes on Ubuntu:

```bash
crontab -e
```

Add this line (replace paths with your actual paths):

```
*/5 * * * * cd /path/to/log-monitor-alert-system && .venv/bin/python src/log_monitor.py --log data/sample.log --ai --telegram >> /tmp/cron_log_monitor.log 2>&1
```

Check it ran:

```bash
cat /tmp/cron_log_monitor.log
```

## What I Learned

- Log analysis and pattern detection
- Incident monitoring and reporting
- Claude AI API integration
- Telegram Bot API
- Flask web development
- Cron job scheduling on Ubuntu
- Secure email automation
- Real-time file monitoring
- DevOps troubleshooting process
- Feature branch Git workflow
