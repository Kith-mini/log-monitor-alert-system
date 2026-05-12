from datetime import datetime
from .error_extractor import group_by_level, enrich

def build_ai_report(errors, diagnosis):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    enriched = enrich(errors)
    grouped = group_by_level(enriched)
    lines = [
        f"# Incident Report — {ts}", "",
        f"Severity: {diagnosis['severity']} | Errors: {diagnosis['error_count']}",
        "", "## Root Cause", "", diagnosis["root_cause"],
        "", "## Impact", "", diagnosis["impact"],
        "", "## Remediation", "", diagnosis["remediation"],
        "", "## Error Log", "",
    ]
    for level in ["CRITICAL", "FATAL", "ERROR"]:
        if level in grouped:
            lines.append(f"### {level} ({len(grouped[level])})")
            for e in grouped[level]:
                lines.append(f"- L{e['line_no']} [{e['timestamp']}] {e['raw']}")
            lines.append("")
    lines.append(f"*Generated {ts} | tokens: {diagnosis['tokens_used']}*")
    return "\n".join(lines)
