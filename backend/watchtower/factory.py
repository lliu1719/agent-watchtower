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
logging.getLogger("httpx").setLevel(logging.WARNING)  # the state poll runs every 2 s; each report logs its own line below

URL = os.getenv("FACTORY_URL", "https://app-watchtower.solutionvalidation.center").rstrip("/")
TOKEN = os.getenv("WATCHTOWER_TOKEN", "")
TEAM_PREFIX = "wt-"
_order = asyncio.Lock()
POLL_S = float(os.getenv("FACTORY_POLL_S", "2"))
running: bool | None = None  # the factory's story is playing (None: its state cannot be read)
auto = False  # the factory's Auto-run is on: nobody is at the controls, so WatchTower confirms by itself
short = False  # the factory plays its two-step story (Tier 1, then Tier 3): no Tier 0 or Tier 2 reports
on_reset = None  # set by the app: called when the factory's story is reset or restarted
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
    if running is False:  # the page is on standby after a Reset: a late decision would come back as a stale banner
        log.info("factory report tier %s %s: skipped, the factory is not running", tier, who or "")
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


async def follow() -> None:
    """Poll the factory's state (GET /api/wt/state) so WatchTower starts over with it: when its story is reset or
    restarted, pending confirmations and findings from the old run must not reach the new one."""
    global running, auto, short
    if not enabled():
        return
    was_running, last_step, warned = None, 0, False
    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            try:
                r = await client.get(f"{URL}/api/wt/state", headers={"x-watchtower-token": TOKEN})
                r.raise_for_status()
                snap = r.json()
                now, step = bool(snap.get("running")), int(snap.get("step") or 0)
                if was_running is not None and ((was_running and not now) or (now and step < last_step)):
                    log.info("factory reset seen (running %s -> %s, step %s -> %s): resetting WatchTower", was_running, now, last_step, step)
                    if on_reset:
                        await on_reset()
                running, was_running, last_step, warned = now, now, step, False
                auto = now and bool(snap.get("auto"))
                short = snap.get("last_step") == 2
            except (httpx.HTTPError, ValueError) as e:
                running, auto = None, False  # unknown: report as before, and leave confirmations to people
                if not warned:
                    log.warning("factory state unreadable (%s): reports are sent without checking it", getattr(getattr(e, "response", None), "status_code", type(e).__name__))
                    warned = True
            await asyncio.sleep(POLL_S)
