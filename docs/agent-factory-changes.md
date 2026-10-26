# Agent factory: changes so WatchTower takes every action

WatchTower (DAI-VM) decides the tiers and acts; the factory only shows what it is told.
Two small changes in `fred-hackathon`, both behind `WT_LOCAL_TIERS=0` so the current behaviour stays the default.

## 1. Stop deciding tiers locally (`backend/wt/detect.py`)

Today `flag()` broadcasts the factory's own tier decisions and sends its own alerts, so the page shows
both its decisions and WatchTower's. With `WT_LOCAL_TIERS=0` it only logs them.

```python
import os   # at the top of the file, if not there yet

    async def flag(self, tier, scope, agent, text, repo, issue, dept=None):
        if os.getenv("WT_LOCAL_TIERS", "1") == "0":   # WatchTower decides the tiers (POST /api/wt/tier)
            self.log("info", f"(local rule, not acted on) tier {tier}: {text}")
            return
        ...  # unchanged
```

Also skip the three `request_*` calls when the flag is off (they only log and wake agents), for example
at the top of `request_block_agent`, `request_block_dept` and `request_zone_cut` in `backend/wt/world.py`:

```python
        if os.getenv("WT_LOCAL_TIERS", "1") == "0":
            return
```

## 2. Make WatchTower's feedback stop the agents (`backend/wt/world.py`, `feedback()`)

The demo does not revoke real LiteLLM keys, so an agent never gets a refused call and keeps working
after WatchTower reports it blocked. Let the feedback set the agent's own state, which already ends its loop.

```python
        if body.get("zone") in ("cut", "up"):
            self.zone = body["zone"]
            for a in self.agents.values():                    # the zone is the brain of Security Research and DevOps
                if a.dept != "cs":
                    if self.zone == "cut" and a.state == "normal":
                        a.state = "braindead"
                        self.emit_evt(a, "brainless", text="Fabric VC to the models cut by WatchTower")
                    elif self.zone == "up" and a.state == "braindead":
                        a.state = "normal"
            ...  # unchanged

        if body.get("agent") in self.agents and st in ("blocked", "normal"):
            if st == "blocked":
                self.det.agent[body["agent"]] = "blocked"
                self.agents[body["agent"]].state = "blocked"   # WatchTower blocked its key: the agent stops
            ...  # unchanged

        if body.get("department") in C.DEPTS and st in ("blocked", "normal"):
            d = body["department"]
            if st == "blocked":
                self.det.dept[d] = "blocked"
                for a in self.agents.values():
                    if a.dept == d:
                        a.state = "blocked"
            ...  # unchanged
```

A stopped agent's loop has ended; `reset` already restarts the story, so nothing else is needed.

## Then

Add `WT_LOCAL_TIERS=0` to `.env` and restart the container (`docker compose up -d`).

What WatchTower sends, in order: `POST /api/wt/tier` (tier 0 to 3, `status` done, or requested while a
Fabric VC cut waits for a reviewer) and `POST /api/wt/feedback` (agent / department `blocked`, `zone` `cut`;
`normal` and `zone` `up` after a reviewer restores access). Calls come from 64.191.201.58 with
`x-watchtower-token`.
