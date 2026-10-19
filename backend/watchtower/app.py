"""WatchTower backend: ingest agent telemetry, detect, analyze, contain, stream.

Run:  .venv/bin/uvicorn watchtower.app:app --app-dir backend --port 8000
"""

import asyncio
import importlib.util
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import httpx

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from . import ai_engine, containment, detectors, guardrail  # noqa: E402  (needs env loaded)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("watchtower")

ANALYZE_THRESHOLD = int(os.getenv("ANALYZE_THRESHOLD", "80"))
REANALYZE_DELTA = int(os.getenv("REANALYZE_DELTA", "15"))
AUTO_CONTAIN = os.getenv("AUTO_CONTAIN", "true").lower() == "true"
WINDOW_EVENTS = int(os.getenv("WINDOW_EVENTS", "80"))

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "simulator" / "scenario_dependency.json"

# Load the CLI simulator as a module so the dashboard's "Run scenario" replays the exact same timeline.
_spec = importlib.util.spec_from_file_location("simulator", ROOT / "simulator" / "simulator.py")
simulator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(simulator)

app = FastAPI(title="Equinix Agent WatchTower")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class State:
    def __init__(self):
        self.agents: dict[str, dict] = {}
        self.events: list[dict] = []
        self.risk_history: list[dict] = []
        self.signals: list[dict] = []
        self.hotspots: list[dict] = []
        self.vcs: dict[str, dict] = {}
        self.analysis: dict | None = None
        self.analyzing = False
        self.last_analyzed_risk = -1
        self.incident: dict | None = None
        self.auto_contained = False

    def agents_by_vc(self) -> dict[str, list[str]]:
        out = {vc: [] for vc in self.vcs}
        for a in self.agents.values():
            out[a["vc_id"]].append(a["agent_id"])
        return out

    def vcs_view(self) -> list[dict]:
        by_vc = self.agents_by_vc()
        return [{**vc, "agents": sorted(by_vc[vc["vc_id"]])} for vc in self.vcs.values()]

    def snapshot(self) -> dict:
        return {
            "agents": list(self.agents.values()),
            "events": self.events[-200:],
            "risk_history": self.risk_history[-300:],
            "risk_score": self.risk_history[-1]["risk"] if self.risk_history else 0,
            "signals": self.signals,
            "hotspots": self.hotspots,
            "vcs": self.vcs_view(),
            "analysis": self.analysis,
            "analyzing": self.analyzing,
            "incident": self.incident,
            "ai_engine_mode": os.getenv("AI_ENGINE_MODE", "live"),
            "analyze_threshold": ANALYZE_THRESHOLD,
            "scenario_running": bool(scenario_task and not scenario_task.done()),
        }


scenario_task: asyncio.Task | None = None
state = State()
subscribers: set[asyncio.Queue] = set()


def publish(kind: str, data) -> None:
    msg = {"type": kind, "data": data, "ts": _now()}
    for q in list(subscribers):
        q.put_nowait(msg)


def _vc(vc_id: str, owner: str) -> dict:
    return state.vcs.setdefault(vc_id, {"vc_id": vc_id, "owner": owner, "state": "UP"})


def _agent(agent_id: str) -> dict:
    if agent_id not in state.agents:
        vc_id = _vc(containment.vc_for(None), "shared")["vc_id"]
        state.agents[agent_id] = {
            "agent_id": agent_id, "declared_task": "unknown", "owner": "unknown", "vc_id": vc_id,
            "status": "active", "llm_calls": 0, "last_action": None,
        }
    return state.agents[agent_id]


# OpenTelemetry GenAI semantic-convention keys -> internal event fields.
OTEL_KEYS = {
    "gen_ai.agent.id": "agent_id", "gen_ai.operation.name": "action", "gen_ai.tool.name": "tool",
    "watchtower.resource": "resource", "watchtower.detail": "detail",
}


def normalize(raw: dict) -> dict:
    if "attributes" in raw:  # OTEL span
        attrs = raw["attributes"]
        raw = {OTEL_KEYS[k]: v for k, v in attrs.items() if k in OTEL_KEYS}
    event = {
        "event_id": f"e-{len(state.events) + 1:03d}",
        "ts": raw.get("ts") or _now(),
        "agent_id": raw["agent_id"],
        "action": raw.get("action", "tool_call"),
        "tool": raw.get("tool"),
        "resource": raw.get("resource"),
        "detail": raw.get("detail", ""),
    }
    event["guardrail_verdict"] = guardrail.check(event)
    return event


def build_window() -> dict:
    events = state.events[-WINDOW_EVENTS:]
    involved = {e["agent_id"] for e in events}
    return {
        "window": {"start": events[0]["ts"] if events else _now(), "end": _now()},
        "agents": [{k: a[k] for k in ("agent_id", "declared_task", "owner")} for a in state.agents.values() if a["agent_id"] in involved],
        "events": events,
        "detector_signals": [{k: s[k] for k in ("type", "score", "detail")} for s in state.signals],
        "risk_score": state.risk_history[-1]["risk"] if state.risk_history else 0,
        "hotspots": state.hotspots,  # used by mock mode only; stripped before AI Engine
    }


async def run_analysis() -> None:
    state.analyzing = True
    publish("analyzing", True)
    window = build_window()
    state.last_analyzed_risk = window["risk_score"]
    started = time.monotonic()
    try:
        analysis = await asyncio.to_thread(ai_engine.analyze, window)
    finally:
        state.analyzing = False
    analysis["_latency_s"] = round(time.monotonic() - started, 1)
    state.analysis = analysis
    publish("analysis", analysis)
    log.info("analysis: %s / %s via %s", analysis.get("verdict"), analysis.get("risk_level"), analysis.get("_source"))

    action = containment.decide(analysis, state.signals)
    if action != "MONITOR" and AUTO_CONTAIN and not state.auto_contained:
        await contain(action, analysis)


def _incident() -> dict:
    """The open incident, or a new one. Every containment step is appended to its action log."""
    if not state.incident or state.incident["status"] == "resolved":
        state.incident = {"status": "pending_review", "opened_at": _now(), "trigger": None,
                          "involved_agents": [], "actions": [], "notified": False}
    return state.incident


def _isolate(agent_id: str, by: str, reason: str | None = None) -> bool:
    agent = state.agents.get(agent_id)
    if not agent or agent["status"] in ("contained", "severed"):
        return False
    agent["status"] = "contained"
    _incident()["actions"].append({"type": "isolate_agent", "target": agent_id, "by": by, "ts": _now(), "reason": reason})
    return True


def _cut(vc_id: str, by: str) -> bool:
    vc = state.vcs.get(vc_id)
    if not vc or vc["state"] == "DOWN":
        return False
    fabric = containment.delete_fabric_vc(vc_id)
    vc["state"] = "DOWN"
    for a in state.agents.values():
        if a["vc_id"] == vc_id:
            a["status"] = "severed"
    _incident()["actions"].append({"type": "cut_vc", "target": vc_id, "by": by, "ts": _now(), "fabric": fabric})
    return True


async def _announce(text: str) -> None:
    incident = _incident()
    incident["notified"] = await asyncio.to_thread(containment.notify, text) or incident["notified"]
    publish("incident", incident)
    publish("agents", list(state.agents.values()))
    publish("vcs", state.vcs_view())


async def _contain_late_joiner(event: dict) -> None:
    """While an incident is open, an agent that writes to one of its targets is isolated on that first write.

    Analysis is not re-run once containment has started, so without this an agent
    that joins the pattern afterwards would go unanswered.
    """
    incident = state.incident
    if not incident or incident["status"] != "pending_review" or not state.analysis:
        return
    targets = set(state.analysis.get("target_resources") or [])
    if event["resource"] in targets and event["action"] == "data_write":
        reason = f"wrote {event['resource']} after containment"
        if _isolate(event["agent_id"], "auto", reason):
            incident["involved_agents"] = sorted(set(incident["involved_agents"]) | {event["agent_id"]})
            await _announce(f":lock: WatchTower: isolated {event['agent_id']} at the AI Gateway; it {reason}.")


async def contain(action: str, analysis: dict | None) -> None:
    """Automatic response to an analysis, following policy sections 3 and 4."""
    analysis = analysis or {}
    involved = analysis.get("involved_agents", [])
    steps = containment.plan(action, involved, state.agents_by_vc())
    if not (steps["cut_vcs"] or steps["revoke_agents"]):
        await asyncio.to_thread(containment.notify, f":warning: WatchTower {action}: {analysis.get('summary', '')}")
        return
    incident = _incident()
    incident["trigger"] = incident["trigger"] or action
    incident["involved_agents"] = sorted(set(incident["involved_agents"]) | set(involved))
    for vc_id in steps["cut_vcs"]:
        _cut(vc_id, "auto")
    for agent_id in steps["revoke_agents"]:
        _isolate(agent_id, "auto")
    state.auto_contained = True
    await _announce(
        f":rotating_light: WatchTower {action}: {analysis.get('summary', '')} "
        f"Cut VCs: {', '.join(steps['cut_vcs']) or 'none'}. Revoked agents: {', '.join(steps['revoke_agents']) or 'none'}. "
        "Human review required to restore.")


@app.post("/api/agents/register")
async def register(body: dict):
    for a in body.get("agents", []):
        owner = a.get("owner", "unknown")
        vc_id = _vc(containment.vc_for(owner), owner)["vc_id"]
        _agent(a["agent_id"]).update({"declared_task": a.get("declared_task", "unknown"), "owner": owner, "vc_id": vc_id})
    # Drop the shared fallback VC if every agent turned out to have a team VC.
    by_vc = state.agents_by_vc()
    for vc_id in [v for v, agents in by_vc.items() if not agents]:
        del state.vcs[vc_id]
    publish("agents", list(state.agents.values()))
    publish("vcs", state.vcs_view())
    return {"registered": len(body.get("agents", []))}


@app.post("/api/gateway/chat")
async def gateway_chat(body: dict):
    """Simulated AI Gateway: every agent step needs the LLM behind its team's Fabric VC."""
    agent = _agent(body["agent_id"])
    if state.vcs[agent["vc_id"]]["state"] == "DOWN":
        if agent["status"] != "severed":
            agent["status"] = "severed"
            publish("agent", agent)
        return JSONResponse({"error": "llm_endpoint_unreachable", "vc_id": agent["vc_id"]}, status_code=503)
    if agent["status"] == "contained":
        return JSONResponse({"error": "agent_access_revoked"}, status_code=403)
    agent["llm_calls"] += 1
    return {"ok": True, "model": "claude-sonnet-5-5"}


@app.post("/api/ingest")
async def ingest(request: Request):
    body = await request.json()
    raws = body if isinstance(body, list) else body.get("spans", [body])
    accepted = []
    for raw in raws:
        event = normalize(raw)
        if state.agents.get(event["agent_id"], {}).get("status") in ("severed", "contained"):
            continue
        state.events.append(event)
        agent = _agent(event["agent_id"])
        agent["last_action"] = f"{event['tool'] or event['action']} {event['resource'] or ''}".strip()
        publish("event", event)
        accepted.append(event["event_id"])
        await _contain_late_joiner(event)

    result = detectors.evaluate(state.events[-WINDOW_EVENTS:])
    state.signals, state.hotspots = result["signals"], result["hotspots"]
    state.risk_history.append({"ts": _now(), "risk": result["risk_score"]})
    publish("risk", {"risk": result["risk_score"], "signals": state.signals, "hotspots": state.hotspots})

    risk = result["risk_score"]
    if (risk >= ANALYZE_THRESHOLD and not state.analyzing
            and not state.auto_contained and (state.last_analyzed_risk < 0 or risk - state.last_analyzed_risk >= REANALYZE_DELTA)):
        asyncio.create_task(run_analysis())
    return {"accepted": accepted, "risk": risk}


@app.post("/api/analyze")
async def analyze_now():
    if not state.analyzing:
        asyncio.create_task(run_analysis())
    return {"started": True}


@app.post("/api/agents/{agent_id}/isolate")
async def isolate_agent(agent_id: str):
    """Operator: revoke one agent's AI Gateway token; its VC stays up for the rest of the team."""
    if agent_id not in state.agents:
        return JSONResponse({"error": "unknown_agent"}, status_code=404)
    if _isolate(agent_id, "operator"):
        await _announce(f":lock: WatchTower: operator isolated {agent_id} at the AI Gateway.")
    return state.incident


@app.post("/api/vcs/{vc_id}/cut")
async def cut_vc(vc_id: str):
    """Operator: delete one team's Fabric VC; every agent behind it loses the model."""
    if vc_id not in state.vcs:
        return JSONResponse({"error": "unknown_vc"}, status_code=404)
    if _cut(vc_id, "operator"):
        await _announce(f":scissors: WatchTower: operator cut Fabric VC {vc_id}.")
    return state.incident


@app.post("/api/killswitch")
async def killswitch():
    """Operator, last resort: delete every Fabric VC to the AI Hub."""
    cut = [vc_id for vc_id in list(state.vcs) if _cut(vc_id, "operator")]
    if cut:
        _incident()["trigger"] = "KILL_ALL"
        await _announce(f":rotating_light: WatchTower global kill switch: cut {', '.join(cut)}.")
    return state.incident


@app.post("/api/review/approve")
async def approve_restore():
    """Human reviewer restores access after investigating."""
    for vc in state.vcs.values():
        vc["state"] = "UP"
    for a in state.agents.values():
        if a["status"] in ("severed", "contained"):
            a["status"] = "quarantined_review_done"
    state.auto_contained = False
    if state.incident:
        state.incident.update(status="resolved", resolved_at=_now())
        publish("incident", state.incident)
    publish("vcs", state.vcs_view())
    publish("agents", list(state.agents.values()))
    return {"vcs": state.vcs_view()}


def _stop_scenario() -> None:
    if scenario_task and not scenario_task.done():
        scenario_task.cancel()


@app.post("/api/reset")
async def reset():
    global state
    _stop_scenario()
    state = State()
    publish("reset", state.snapshot())
    return {"reset": True}


@app.post("/api/scenario/run")
async def run_scenario(body: dict | None = None):
    """Director control: reset, then replay the demo scenario in-process (no port assumptions)."""
    global scenario_task
    speed = float((body or {}).get("speed", 1.0))
    await reset()
    scenario = json.loads(SCENARIO.read_text())

    async def replay():
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://watchtower", timeout=30) as client:
                await simulator.run(client, scenario, speed=speed, reset=False)
        except asyncio.CancelledError:
            log.info("scenario cancelled")
            raise
        except Exception:
            log.exception("scenario failed")
        finally:
            publish("scenario", {"running": False})

    scenario_task = asyncio.create_task(replay())
    publish("scenario", {"running": True, "name": scenario["name"], "speed": speed})
    return {"started": scenario["name"], "speed": speed}


@app.get("/api/state")
async def get_state():
    return state.snapshot()


@app.get("/api/stream")
async def stream(request: Request):
    q: asyncio.Queue = asyncio.Queue()
    subscribers.add(q)

    async def gen():
        try:
            yield f"data: {json.dumps({'type': 'snapshot', 'data': state.snapshot()})}\n\n"
            while not await request.is_disconnected():
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            subscribers.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.middleware("http")
async def no_stale_dashboard(request: Request, call_next):
    """Make browsers revalidate dashboard files so a redeploy never mixes old CSS/JS with new HTML."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


# Dashboard last, so /api/* routes take precedence over static files.
app.mount("/", StaticFiles(directory=ROOT / "dashboard", html=True), name="dashboard")
