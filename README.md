# AI-Powered Log Monitoring & Alert System

A Python-based DevOps tool that monitors log files, detects critical events,
analyses them with Claude AI, generates incident reports, and sends alerts
via email and Telegram.

## Features

- Regex detection for ERROR / CRITICAL / FATAL logs
- Automated Markdown & JSON reports saved to disk
- SMTP email alerts using secure .env configuration
- State tracking to avoid duplicate alerts
- AI-powered root cause analysis using Claude API
- Severity rating — CRITICAL / HIGH / MEDIUM / LOW
- AI-generated remediation steps
- Telegram incident report notifications
- Ubuntu + VS Code + Git workflow

## Tech Stack

- Python
- Ubuntu
- Claude API (Anthropic)
- Telegram Bot API
- SMTP (Gmail App Password)
- Regex
- Git & GitHub

## How It Works

1. Script reads log file line by line
2. Regex matches ERROR / CRITICAL / FATAL patterns
3. Matched errors sent to Claude API for analysis
4. Claude identifies root cause, severity, remediation steps
5. Incident report saved to data/reports/
6. Alert sent via email and/or Telegram

## Project Structure

log-monitor-alert-system/
├── src/
│   ├── log_monitor.py
│   └── ai/
│       ├── ai_analyser.py
│       ├── error_extractor.py
│       ├── report_builder.py
│       └── telegram_notifier.py
├── data/
│   └── sample.log
├── systemd/
├── test_ai_pipeline.py
├── requirements.txt
└── .env.example

## Setup

git clone https://github.com/Kith-mini/log-monitor-alert-system.git
cd log-monitor-alert-system
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

## Environment Variables

ANTHROPIC_API_KEY=sk-ant-...
TELEGRAM_BOT_TOKEN=your_token
TELEGRAM_CHAT_ID=your_chat_id
EMAIL_USER=you@gmail.com
EMAIL_PASS=your_app_password

## Run Project

# Email only (original)
python src/log_monitor.py --log data/sample.log --email --smtp-tls

# With AI + Telegram
python src/log_monitor.py --log data/sample.log --ai --telegram

# Smoke test
python test_ai_pipeline.py

## What I Learned

- Log analysis and pattern detection
- Incident monitoring and reporting
- Claude AI API integration
- Telegram Bot API
- Secure email automation
- DevOps troubleshooting process
- Feature branch Git workflow
