# Log Monitoring & Alert System

A Python-based DevOps tool that monitors log files, detects critical events, generates reports, and sends email alerts.

## Features
- Regex detection for ERROR / CRITICAL / FATAL logs  
- Automated Markdown & JSON reports  
- SMTP email alerts using secure .env configuration  
- State tracking to avoid duplicate alerts  
- Ubuntu + VS Code + Git workflow  

## Tech Stack
- Python  
- Ubuntu  
- SMTP (Gmail App Password)  
- Regex  
- Git & GitHub

## How It Works
1. Script reads log file line by line  
2. Regex matches ERROR/CRITICAL patterns  
3. Reports are generated  
4. If issues found → email alert sent  

## Run Project

python src/log_monitor.py --log data/sample.log --email --smtp-tls


## What I Learned
- Log analysis  
- Incident monitoring  
- Secure email automation  
- DevOps troubleshooting process
