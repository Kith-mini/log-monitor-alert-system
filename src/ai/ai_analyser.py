import os
import time
import anthropic
from dotenv import load_dotenv
from .error_extractor import enrich, format_for_prompt

load_dotenv()
_last_call_time = 0.0
THROTTLE_SECONDS = 60

SYSTEM_PROMPT = """\
You are a senior DevOps engineer analysing production log errors.
Respond in EXACTLY this format:

ROOT CAUSE: <one sentence>
SEVERITY: <LOW | MEDIUM | HIGH | CRITICAL>
REMEDIATION:
1. <step one>
2. <step two>
3. <step three>
IMPACT: <affected services or users>\
"""

def analyse(errors, skip_throttle=False):
    global _last_call_time
    if not skip_throttle:
        elapsed = time.time() - _last_call_time
        if elapsed < THROTTLE_SECONDS:
            time.sleep(int(THROTTLE_SECONDS - elapsed))
    enriched = enrich(errors)
    formatted = format_for_prompt(enriched)
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=600,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Analyse these {len(enriched)} log error(s):\n\n{formatted}"}],
    )
    _last_call_time = time.time()
    raw = response.content[0].text.strip()
    parsed = _parse(raw)
    return dict(
        root_cause=parsed.get("ROOT CAUSE", "Unable to determine."),
        severity=parsed.get("SEVERITY", "UNKNOWN"),
        remediation=parsed.get("REMEDIATION", "No steps returned."),
        impact=parsed.get("IMPACT", "Unknown."),
        error_count=len(enriched),
        model="claude-haiku-4-5",
        tokens_used=response.usage.input_tokens + response.usage.output_tokens,
        raw_response=raw,
    )

def _parse(text):
    result, key, lines = {}, None, []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("ROOT CAUSE:"):
            _flush(result, key, lines); key="ROOT CAUSE"; lines=[s[11:].strip()]
        elif s.startswith("SEVERITY:"):
            _flush(result, key, lines); key="SEVERITY"; lines=[s[9:].strip()]
        elif s.startswith("REMEDIATION:"):
            _flush(result, key, lines); key="REMEDIATION"; lines=[]
        elif s.startswith("IMPACT:"):
            _flush(result, key, lines); key="IMPACT"; lines=[s[7:].strip()]
        elif key and s:
            lines.append(s)
    _flush(result, key, lines)
    return result

def _flush(result, key, lines):
    if key and lines:
        result[key] = "\n".join(lines)
