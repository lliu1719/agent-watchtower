"""Report WatchTower's decisions to the agent factory's page (the teammate's demo on app-watchtower).

The factory's page treats WatchTower as its "external Watchtower": when we act on one of its agents
we tell it with POST /api/wt/tier (the tier decision, shown in its banner and decision list) and
POST /api/wt/feedback (the resulting state: an agent or department blocked, the zone cut or back up).
Its nginx admits only allow-listed addresses on these paths, and its backend checks the
x-watchtower-token header (WATCHTOWER_TOKEN here).

Only agents whose LiteLLM team starts with "wt-" belong to the factory; everything else is ignored.
Calls are fire-and-forget: a failure is logged and never blocks containment.
"""

import asyncio
import logging
import os

import httpx

log = logging.getLogger("watchtower.factory")

URL = os.getenv("FACTORY_URL", "https://app-watchtower.solutionvalidation.center").rstrip("/")
TOKEN = os.getenv("WATCHTOWER_TOKEN", "")
TEAM_PREFIX = "wt-"
_order = asyncio.Lock()
on_tier = None  # set by the app: called with each tier above 0 as it is reported  # reports reach the page in the order WatchTower acted (asyncio.Lock wakes waiters FIFO)


def department(owner: str | None) -> str | None:
    """wt-sec -> sec; None for agents that are not the factory's."""
    return owner.removeprefix(TEAM_PREFIX) if owner and owner.startswith(TEAM_PREFIX) else None


def enabled() -> bool:
    return bool(TOKEN)


async def _post(path: str, body: dict) -> bool:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(f"{URL}{path}", json=body, headers={"x-watchtower-token": TOKEN})
        if r.status_code >= 300:
            log.warning("factory %s %s -> HTTP %s %s", path, body, r.status_code, r.text[:120])
            return False
        return True
    except httpx.HTTPError as e:
        log.warning("factory %s unreachable: %s", path, type(e).__name__)
        return False


async def report(tier: int, text: str, feedback: dict | None = None, done: bool = True, **who) -> None:
    """One decision: the tier (agent= / department= / scope=) and, when the action ran, its resulting state."""
    if not enabled():
        return
    if tier > 0 and on_tier:
        on_tier(tier)
    async with _order:
        ok = await _post("/api/wt/tier", {"tier": tier, "text": text[:400], "status": "done" if done else "requested", **who})
        if feedback:
            ok = await _post("/api/wt/feedback", feedback) and ok
    log.info("factory report tier %s %s: %s", tier, who or "", "ok" if ok else "failed")


def send(tier: int, text: str, feedback: dict | None = None, done: bool = True, **who) -> None:
    """Schedule a report without waiting for it."""
    if enabled():
        asyncio.get_running_loop().create_task(report(tier, text, feedback, done, **who))


def restore(agents: list[str], departments: list[str], zone_was_cut: bool) -> None:
    """Tell the page that a reviewer released what WatchTower had blocked."""
    if not enabled():
        return

    async def run():
        async with _order:
            await _release(agents, departments, zone_was_cut)

    async def _release(agents, departments, zone_was_cut):
        for a in agents:
            await _post("/api/wt/feedback", {"agent": a, "state": "normal"})
        for d in departments:
            await _post("/api/wt/feedback", {"department": d, "state": "normal"})
        if zone_was_cut:
            await _post("/api/wt/feedback", {"zone": "up"})
        log.info("factory restore: %d agents, %d departments, zone %s", len(agents), len(departments), "up" if zone_was_cut else "unchanged")

    asyncio.get_running_loop().create_task(run())
