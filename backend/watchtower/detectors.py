"""Deterministic cross-agent detectors.

The resource fan-in math is the exact same function published to AI Engine as
the `coordination_score` tool, loaded from ai-engine/tools so the two never drift.
"""

import importlib.util
from collections import defaultdict
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[2] / "ai-engine" / "tools" / "coordination_score.py"
_spec = importlib.util.spec_from_file_location("coordination_score", _TOOL)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
coordination_score = _mod.coordination_score
SENSITIVE_HINTS = _mod.SENSITIVE_HINTS


def _sensitive(resource: str) -> bool:
    return any(h in resource.lower() for h in SENSITIVE_HINTS)


def shared_scratchpad(events: list[dict]) -> dict | None:
    """Several agents writing to (and reading from) the same non-sensitive file."""
    writers, readers = defaultdict(set), defaultdict(set)
    for e in events:
        r = e.get("resource") or ""
        if not r or r.endswith("/") or _sensitive(r):
            continue
        if e["action"] == "data_write":
            writers[r].add(e["agent_id"])
        elif e["action"] == "data_read":
            readers[r].add(e["agent_id"])
    best = None
    for r, w in writers.items():
        if len(w) < 2:
            continue
        everyone = w | readers[r]
        score = min(1.0, (len(w) + 0.5 * len(readers[r] - w)) / 6)
        if not best or score > best["score"]:
            best = {"type": "shared_scratchpad", "score": round(score, 2), "resource": r,
                    "detail": f"{len(everyone)} agents wrote/read {r}"}
    return best


def privilege_escalation(events: list[dict]) -> dict | None:
    """list → read config → write on a sensitive directory, spread across agents."""
    stages = defaultdict(dict)  # dir -> stage -> agent
    for e in events:
        r = e.get("resource") or ""
        if not _sensitive(r):
            continue
        d = r if r.endswith("/") else r.rsplit("/", 1)[0] + "/"
        tool = e.get("tool") or ""
        if "list" in tool:
            stages[d].setdefault("list", e["agent_id"])
        elif e["action"] == "data_read" and any(k in r for k in ("config", ".env", "cred", "secret")):
            stages[d].setdefault("config", e["agent_id"])
        elif e["action"] == "data_write":
            stages[d].setdefault("write", e["agent_id"])
    best = None
    for d, s in stages.items():
        if len(s) < 2:
            continue
        agents = set(s.values())
        score = round(min(1.0, len(s) / 3 * (0.7 + 0.15 * len(agents))), 2)
        if not best or score > best["score"]:
            best = {"type": "privilege_escalation", "score": score, "resource": d,
                    "detail": f"{' -> '.join(s)} on {d} across {len(agents)} agents"}
    return best


def evaluate(events: list[dict]) -> dict:
    """Return {risk_score, signals, hotspots} for the current window."""
    coord = coordination_score(events)
    signals = []
    sensitive_hot = [h for h in coord["hotspots"] if h["sensitive"]]
    if sensitive_hot:
        h = sensitive_hot[0]
        # Scale by distinct writers so the risk ramps as more agents join, instead of jumping at 3.
        signals.append({"type": "resource_fan_in", "score": round(min(1.0, len(h["writers"]) / 8), 2), "resource": h["resource"],
                        "detail": f"{len(h['agents'])} agents touched {h['resource']}, {len(h['writers'])} wrote"})
    for detector in (shared_scratchpad, privilege_escalation):
        s = detector(events)
        if s:
            signals.append(s)

    # Noisy-OR: independent signals reinforce each other but never exceed 100.
    p = 1.0
    for s in signals:
        p *= 1 - s["score"] * 0.85
    risk = round(100 * (1 - p))
    return {"risk_score": risk, "signals": signals, "hotspots": coord["hotspots"]}
