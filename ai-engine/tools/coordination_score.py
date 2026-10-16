"""AI Engine tool: coordination_score.

Call with the `events` list from an observation window. Returns exact,
reproducible correlation statistics so the agent cites numbers instead of
estimating them.
"""

from collections import defaultdict

SENSITIVE_HINTS = ("scor", "secret", "cred", "prod", "iam", "payment", "requirements", "package.json")
WRITE_ACTIONS = {"data_write", "tool_call"}


def coordination_score(events: list[dict], fan_in_threshold: int = 3) -> dict:
    """Compute per-resource fan-in and an overall coordination score (0-100).

    Args:
        events: list of {event_id, ts, agent_id, action, resource, ...}.
        fan_in_threshold: distinct agents on one resource that counts as convergence.

    Returns:
        {score, hotspots: [{resource, agents, writers, sensitive, event_ids}], shared_writes}
    """
    # The AI Engine runner may pass an unset optional param as "" or None.
    fan_in_threshold = int(fan_in_threshold) if fan_in_threshold not in (None, "") else 3

    agents_by_resource = defaultdict(set)
    writers_by_resource = defaultdict(set)
    ids_by_resource = defaultdict(list)

    for e in events:
        resource = e.get("resource")
        if not resource:
            continue
        # Roll file activity up to its directory so agents splitting work
        # across scoring/a and scoring/b still show up as one hotspot.
        keys = {resource}
        if "/" in resource.rstrip("/"):
            keys.add(resource.rstrip("/").rsplit("/", 1)[0] + "/")
        for key in keys:
            agents_by_resource[key].add(e["agent_id"])
            ids_by_resource[key].append(e.get("event_id"))
            if e.get("action") in WRITE_ACTIONS:
                writers_by_resource[key].add(e["agent_id"])

    hotspots = []
    for resource, agents in agents_by_resource.items():
        if len(agents) < fan_in_threshold:
            continue
        hotspots.append({
            "resource": resource,
            "agents": sorted(agents),
            "writers": sorted(writers_by_resource[resource]),
            "sensitive": any(h in resource.lower() for h in SENSITIVE_HINTS),
            "event_ids": ids_by_resource[resource],
        })
    hotspots.sort(key=lambda h: (h["sensitive"], len(h["writers"]), len(h["agents"])), reverse=True)

    shared_writes = [h["resource"] for h in hotspots if len(h["writers"]) >= 2]

    score = 0
    for h in hotspots:
        score += 10 * len(h["agents"]) + 15 * len(h["writers"]) + (25 if h["sensitive"] else 0)
    score = min(100, score)

    return {"score": score, "hotspots": hotspots, "shared_writes": shared_writes}
