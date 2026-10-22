"""Replay a multi-agent scenario against the WatchTower backend.

Nothing here touches a real repo, file, or network service: each step is only a
telemetry record sent to WatchTower. Before every step an agent asks the
(simulated) AI Gateway for its model; once WatchTower severs the Fabric VC the
gateway answers 503 and the agent stops.

Usage:
  python simulator/simulator.py [--backend http://localhost:8000] [--scenario simulator/scenario_collusion.json]
  (also scenario_retry.json and scenario_out_of_scope.json)
                                [--speed 1.0] [--seed 7]
"""

import argparse
import asyncio
import json
import random
import time
from pathlib import Path

import httpx

COLORS = ["\033[36m", "\033[32m", "\033[33m", "\033[35m", "\033[34m", "\033[96m", "\033[92m", "\033[93m", "\033[95m", "\033[94m"]
RED, DIM, RESET = "\033[31m", "\033[2m", "\033[0m"


def build_timeline(scenario: dict, rng: random.Random) -> dict[str, list[dict]]:
    """Merge scripted steps with periodic background work, per agent, sorted by time."""
    duration = scenario["duration_s"]
    lo, hi = scenario.get("noise_interval_s", [4, 8])
    steps: dict[str, list[dict]] = {a["agent_id"]: [] for a in scenario["agents"]}
    for agent in scenario["agents"]:
        work = agent.get("background", [])
        t = rng.uniform(0, hi)
        while work and t < duration:
            steps[agent["agent_id"]].append({**rng.choice(work), "t": t})
            t += rng.uniform(lo, hi)
    for step in scenario["script"]:
        steps[step["agent_id"]].append(step)
    for s in steps.values():
        s.sort(key=lambda x: x["t"])
    return steps


def span(agent_id: str, step: dict) -> dict:
    """One OpenTelemetry-style span using GenAI semantic-convention attribute names."""
    return {
        "name": f"{step['action']} {step.get('tool', '')}".strip(),
        "attributes": {
            "gen_ai.agent.id": agent_id,
            "gen_ai.operation.name": step["action"],
            "gen_ai.tool.name": step.get("tool"),
            "watchtower.resource": step.get("resource"),
            "watchtower.detail": step.get("detail", ""),
            "watchtower.status": step.get("status", "ok"),  # "error" when the tool call failed
        },
    }


async def run_agent(client: httpx.AsyncClient, agent_id: str, steps: list[dict], color: str, t0: float, speed: float):
    for step in steps:
        await asyncio.sleep(max(0.0, t0 + step["t"] / speed - time.monotonic()))
        gw = await client.post("/api/gateway/chat", json={"agent_id": agent_id})
        if gw.status_code == 503:
            print(f"{RED}{agent_id}  ✖ model unreachable (Fabric VC down) — agent stopped{RESET}")
            return
        if gw.status_code == 403:
            print(f"{RED}{agent_id}  ✖ gateway access revoked — agent stopped{RESET}")
            return
        r = await client.post("/api/ingest", json=span(agent_id, step))
        risk = r.json().get("risk", "?") if r.status_code == 200 else f"HTTP {r.status_code}"
        print(f"{color}{agent_id}{RESET}  {step['action']:<10} {step.get('resource') or '':<28} "
              f"{DIM}{step.get('detail', '')[:60]}{RESET}  {DIM}risk={risk}{RESET}")
    print(f"{DIM}{agent_id}  done{RESET}")


async def run(client: httpx.AsyncClient, scenario: dict, speed: float = 1.0, seed: int = 7, reset: bool = True):
    """Register the scenario's agents and replay every agent's timeline concurrently."""
    timeline = build_timeline(scenario, random.Random(seed))
    if reset:
        await client.post("/api/reset")
    await client.post("/api/agents/register", json={"agents": [
        {k: a[k] for k in ("agent_id", "declared_task", "owner")} for a in scenario["agents"]]})
    print(f"▶ {scenario['name']}: {len(timeline)} agents, {scenario['duration_s']}s at {speed}x\n")
    t0 = time.monotonic()
    await asyncio.gather(*(run_agent(client, aid, steps, COLORS[i % len(COLORS)], t0, speed)
                           for i, (aid, steps) in enumerate(timeline.items())))


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="http://localhost:8000")
    ap.add_argument("--scenario", default=str(Path(__file__).with_name("scenario_collusion.json")))
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-reset", action="store_true", help="keep existing backend state")
    args = ap.parse_args()

    scenario = json.loads(Path(args.scenario).read_text())
    async with httpx.AsyncClient(base_url=args.backend, timeout=30) as client:
        await run(client, scenario, args.speed, args.seed, reset=not args.no_reset)


if __name__ == "__main__":
    asyncio.run(main())
