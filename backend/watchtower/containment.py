"""Containment actions owned by the backend (see docs/containment-policy.md).

The AI Engine agent only returns a risk_level; mapping it to an action happens
here. Fabric calls are simulated — the payload mirrors the Fabric v4 API so the
swap to a real call is one function.
"""

import json
import logging
import os
import time

import httpx

log = logging.getLogger("watchtower.containment")

FABRIC_VC_ID = os.getenv("FABRIC_VC_ID", "vc-ai-hub-llm-01")  # agents with no known owning team
# One Fabric VC per owning team: each team's workloads reach the AI Hub over their own connection.
# Override with FABRIC_VCS='{"team-docs": "vc-...", ...}'.
VC_BY_OWNER: dict[str, str] = json.loads(os.getenv("FABRIC_VCS", "{}"))
ACTION_BY_LEVEL = {"LOW": "MONITOR", "MEDIUM": "ALERT", "HIGH": "CONTAIN_AGENTS", "CRITICAL": "KILL_SWITCH"}


def decide(analysis: dict, signals: list[dict]) -> str:
    """Apply policy section 4: KILL_SWITCH only with 3+ agents and a sensitive write."""
    action = ACTION_BY_LEVEL.get(analysis.get("risk_level", "LOW"), "MONITOR")
    if action == "KILL_SWITCH":
        fan_in = next((s for s in signals if s["type"] == "resource_fan_in"), None)
        if len(analysis.get("involved_agents", [])) < 3 or not fan_in:
            action = "CONTAIN_AGENTS"
    return action


def vc_for(owner: str | None) -> str:
    if owner in VC_BY_OWNER:
        return VC_BY_OWNER[owner]
    if not owner or owner == "unknown":
        return FABRIC_VC_ID
    return f"vc-ai-hub-{owner.removeprefix('team-')}"


def plan(action: str, involved: list[str], agents_by_vc: dict[str, list[str]]) -> dict:
    """Pick the narrowest blast radius for an action (policy section 3).

    KILL_SWITCH cuts a VC only when every agent on it is involved; involved agents
    that share a VC with uninvolved ones are revoked at the AI Gateway instead, so
    the innocent agents keep working.
    """
    involved_set = set(involved)
    if action == "CONTAIN_AGENTS":
        return {"cut_vcs": [], "revoke_agents": sorted(involved_set)}
    if action == "KILL_SWITCH":
        cut = sorted(vc for vc, agents in agents_by_vc.items() if agents and set(agents) <= involved_set)
        on_cut = {a for vc in cut for a in agents_by_vc[vc]}
        return {"cut_vcs": cut, "revoke_agents": sorted(involved_set - on_cut)}
    return {"cut_vcs": [], "revoke_agents": []}


def delete_fabric_vc(vc_id: str = FABRIC_VC_ID) -> dict:
    """Simulated `DELETE /fabric/v4/connections/{id}`."""
    log.warning("SIMULATED Fabric API: DELETE /fabric/v4/connections/%s", vc_id)
    return {
        "request": {"method": "DELETE", "url": f"https://api.equinix.com/fabric/v4/connections/{vc_id}"},
        "response": {"uuid": vc_id, "state": "DEPROVISIONING", "operation": {"equinixStatus": "DEPROVISIONING"}},
        "simulated": True,
        "ts": time.time(),
    }


def notify(text: str) -> bool:
    """Post to Slack if SLACK_WEBHOOK_URL is set; otherwise just log."""
    url = os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        log.warning("NOTIFY (no Slack webhook configured): %s", text)
        return False
    try:
        httpx.post(url, json={"text": text}, timeout=10).raise_for_status()
        return True
    except httpx.HTTPError as e:
        log.warning("Slack notify failed: %s", e)
        return False
