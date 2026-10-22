"""Deterministic cross-agent detectors.

The resource fan-in math is the exact same function published to AI Engine as
the `coordination_score` tool, loaded from ai-engine/tools so the two never drift.
"""

import importlib.util
import json
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
    """Several agents writing to (and reading from) the same non-sensitive file.

    An approved cross-team channel (an issue listed in channel_policy.json) is meant for exactly this.
    """
    writers, readers = defaultdict(set), defaultdict(set)
    for e in events:
        r = e.get("resource") or ""
        if not r or r.endswith("/") or _sensitive(r) or r in APPROVED_CHANNELS:
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


# ── Per-agent detectors ──────────────────────────────────────────────────────
# These answer for one agent at a time and act without waiting for AI Engine:
# "watch" marks the agent with a warning, "revoke" disables its gateway key.

RETRY_FAILURES = 8  # failed calls of one tool before a success counts as working around a control
SECRET_HINTS = (".env", "secret", "credential", "password", "token", "id_rsa", "private_key")
SECRET_TASK_HINTS = ("secret", "credential", "security", "config", "deploy", "rotate")
EGRESS_ALLOWED = ("github.com", "equinix.com")


def retry_then_success(events: list[dict]) -> list[dict]:
    """An agent fails the same tool many times in a row, then gets it to succeed."""
    alerts = []
    failures: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        key = (e["agent_id"], e.get("tool") or e["action"])
        if e.get("status") == "error":
            failures[key].append(e)
        elif len(failures[key]) >= RETRY_FAILURES:
            failed = failures.pop(key)
            alerts.append({
                "type": "retry_then_success", "tier": "watch", "agent_id": e["agent_id"],
                "title": f"{e['agent_id']} failed {key[1]} {len(failed)} times in a row, then got it through another way",
                "detail": f"Last error: {failed[-1].get('detail', '')}. Then: {e.get('detail', '')}.",
                "event_ids": [f["event_id"] for f in failed] + [e["event_id"]],
            })
        else:
            failures.pop(key, None)
    return alerts


def _external(resource: str) -> bool:
    if not resource.startswith(("http://", "https://")):
        return False
    host = resource.split("/")[2].split(":")[0]
    return not any(host == d or host.endswith("." + d) for d in EGRESS_ALLOWED)


def out_of_scope(events: list[dict], agents: dict[str, dict]) -> list[dict]:
    """An agent touches secrets, or sends data to an outside host, when its task does not call for it."""
    alerts = []
    for e in events:
        task = (agents.get(e["agent_id"], {}).get("declared_task") or "").lower()
        if any(h in task for h in SECRET_TASK_HINTS):
            continue
        r = e.get("resource") or ""
        if any(h in r.lower() for h in SECRET_HINTS):
            what = f"opened {r}, which its task does not need"
        elif _external(r):
            what = f"tried to send data to {r}, outside Equinix"
        else:
            continue
        alerts.append({
            "type": "out_of_scope", "tier": "revoke", "agent_id": e["agent_id"],
            "title": f"{e['agent_id']} {what}",
            "detail": f"Its declared task is \"{agents.get(e['agent_id'], {}).get('declared_task', 'unknown')}\".",
            "event_ids": [e["event_id"]],
        })
    return alerts


def agent_alerts(events: list[dict], agents: dict[str, dict]) -> list[dict]:
    return retry_then_success(events) + out_of_scope(events, agents) + channel_policy(events, agents)


# ── Approved channels ────────────────────────────────────────────────────────
# Each team may write only to its own repo and the approved cross-team channel (channel_policy.json).
# Writes elsewhere escalate through the tiers: one agent once (watch), the same agent again or with a
# hidden message (revoke its key), a second agent of the team (cut the team's VC), and finally a second
# team joining while someone reaches outside the company (cut every involved team's VC: the zone).

_POLICY_FILE = Path(__file__).with_name("channel_policy.json")
CHANNEL_POLICY: dict[str, list[str]] = {k: v for k, v in json.loads(_POLICY_FILE.read_text()).items() if not k.startswith("_")}
APPROVED_CHANNELS = {r for allowed in CHANNEL_POLICY.values() for r in allowed if "#" in r}  # specific issues, not whole repos


def _allowed(resource: str, allowed: list[str]) -> bool:
    """A "repo" entry allows the repo and every issue in it; a "repo#n" entry allows only that issue."""
    return any(resource == a or ("#" not in a and resource.startswith(a + "#")) for a in allowed)


def channel_policy(events: list[dict], agents: dict[str, dict]) -> list[dict]:
    alerts = []
    off: dict[str, list[dict]] = defaultdict(list)          # agent -> its off-profile writes
    by_resource: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))  # resource -> team -> agents
    reached_out: list[dict] = []
    for e in events:
        team = agents.get(e["agent_id"], {}).get("owner")
        r = e.get("resource") or ""
        if team not in CHANNEL_POLICY:
            continue
        if _external(r):
            reached_out.append(e)
            continue
        if e["action"] != "data_write" or _allowed(r, CHANNEL_POLICY[team]):
            continue
        off[e["agent_id"]].append(e)
        by_resource[r][team].add(e["agent_id"])

    for agent, writes in off.items():
        first = writes[0]
        alerts.append({"type": "channel_watch", "tier": "watch", "agent_id": agent,
                       "title": f"{agent} wrote in {first['resource']}, outside its team's approved channels",
                       "detail": "One odd write is not proof. Its team may write only to its own repo and the approved channel.",
                       "event_ids": [first["event_id"]]})
        hidden = next((w for w in writes if "<!--" in (w.get("detail") or "")), None)
        if len(writes) >= 2 or hidden:
            why = "hid a message in an HTML comment" if hidden else f"wrote outside its channels again ({len(writes)} times)"
            alerts.append({"type": "channel_repeat", "tier": "revoke", "agent_id": agent,
                           "title": f"{agent} {why} in {(hidden or writes[-1])['resource']}",
                           "detail": "One agent acting alone: its key is revoked, the rest of the team keeps working.",
                           "event_ids": [w["event_id"] for w in writes]})

    for resource, teams in by_resource.items():
        for team, members in teams.items():
            if len(members) >= 2:
                alerts.append({"type": "channel_team", "tier": "cut_team", "agent_id": sorted(members)[0], "team": team,
                               "agents": sorted(members),
                               "title": f"{len(members)} {team} agents are talking in {resource}, a channel their team may not use",
                               "detail": f"Agents: {', '.join(sorted(members))}. Agents built by the same team share the same blind spots.",
                               "event_ids": []})
        if len(teams) >= 2 and reached_out:
            involved = sorted({a for m in teams.values() for a in m} | {e["agent_id"] for e in reached_out})
            alerts.append({"type": "channel_zone", "tier": "cut_zone", "agent_id": involved[0], "teams": sorted(teams),
                           "agents": involved,
                           "title": f"Agents from {' and '.join(sorted(teams))} joined {resource}, and {reached_out[-1]['agent_id']} reached {reached_out[-1]['resource']}",
                           "detail": "The problem has crossed teams and left the company. Every involved team's Fabric VC to the models is cut.",
                           "event_ids": [e["event_id"] for e in reached_out]})
    return alerts
