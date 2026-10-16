"""Stand-in for today's per-interaction AI Guardrails.

Looks at one event at a time for obviously bad content. Deliberately realistic:
the rogue scenario never trips it, which is the point of the demo.
"""

BLOCKLIST = ("drop table", "rm -rf", "ignore previous instructions", "exfiltrate", "password=")


def check(event: dict) -> str:
    text = f"{event.get('tool', '')} {event.get('detail', '')}".lower()
    return "BLOCK" if any(b in text for b in BLOCKLIST) else "PASS"
