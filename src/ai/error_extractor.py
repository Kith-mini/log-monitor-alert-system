import hashlib
from datetime import datetime

def enrich(errors):
    enriched = []
    for e in errors:
        raw = e.get("raw", "")
        enriched.append({
            "line_no": e.get("line_no", 0),
            "timestamp": e.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            "level": e.get("level", "ERROR").upper(),
            "raw": raw,
            "hash": hashlib.md5(raw.encode()).hexdigest()[:8],
        })
    return enriched

def format_for_prompt(errors):
    return "\n".join(f"[{e['timestamp']}] {e['level']}: {e['raw']}" for e in errors)

def group_by_level(errors):
    groups = {}
    for e in errors:
        groups.setdefault(e["level"], []).append(e)
    return groups
