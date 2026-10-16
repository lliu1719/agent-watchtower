"""WatchTower backend: ingest agent telemetry, detect, analyze, contain, stream.

Run:  .venv/bin/uvicorn watchtower.app:app --app-dir backend --port 8000
"""

import asyncio
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

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from . import ai_engine, containment, detectors, guardrail  # noqa: E402  (needs env loaded)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("watchtower")

ANALYZE_THRESHOLD = int(os.getenv("ANALYZE_THRESHOLD", "80"))
REANALYZE_DELTA = int(os.getenv("REANALYZE_DELTA", "15"))
AUTO_CONTAIN = os.getenv("AUTO_CONTAIN", "true").lower() == "true"
WINDOW_EVENTS = int(os.getenv("WINDOW_EVENTS", "80"))

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
        self.vc_state = "UP"
        self.analysis: dict | None = None
        self.analyzing = False
        self.last_analyzed_risk = -1
        self.incident: dict | None = None

    def snapshot(self) -> dict:
        return {
            "agents": list(self.agents.values()),
            "events": self.events[-200:],
            "risk_history": self.risk_history[-300:],
            "risk_score": self.risk_history[-1]["risk"] if self.risk_history else 0,
            "signals": self.signals,
            "hotspots": self.hotspots,
            "vc_state": self.vc_state,
            "vc_id": containment.FABRIC_VC_ID,
            "analysis": self.analysis,
            "analyzing": self.analyzing,
            "incident": self.incident,
            "ai_engine_mode": os.getenv("AI_ENGINE_MODE", "live"),
        }


state = State()
subscribers: set[asyncio.Queue] = set()


def publish(kind: str, data) -> None:
    msg = {"type": kind, "data": data, "ts": _now()}
    for q in list(subscribers):
        q.put_nowait(msg)


def _agent(agent_id: str) -> dict:
    return state.agents.setdefault(agent_id, {
        "agent_id": agent_id, "declared_task": "unknown", "owner": "unknown",
        "status": "active", "llm_calls": 0, "last_action": None,
    })


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
    if action != "MONITOR" and AUTO_CONTAIN and not state.incident:
        await contain(action, analysis)


async def contain(action: str, analysis: dict | None) -> None:
    analysis = analysis or {}
    incident = {"action": action, "status": "pending_review", "opened_at": _now(),
                "involved_agents": analysis.get("involved_agents", []), "fabric": None, "notified": False}
    if action == "KILL_SWITCH":
        incident["fabric"] = containment.delete_fabric_vc()
        state.vc_state = "DOWN"
    elif action == "CONTAIN_AGENTS":
        for a in incident["involved_agents"]:
            _agent(a)["status"] = "contained"
    state.incident = incident
    text = (f":rotating_light: WatchTower {action}: {analysis.get('summary', 'manual containment')} "
            f"Agents: {', '.join(incident['involved_agents']) or 'all'}. Human review required to restore.")
    incident["notified"] = await asyncio.to_thread(containment.notify, text)
    publish("incident", incident)
    publish("agents", list(state.agents.values()))
    publish("vc", state.vc_state)


@app.post("/api/agents/register")
async def register(body: dict):
    for a in body.get("agents", []):
        _agent(a["agent_id"]).update({"declared_task": a.get("declared_task", "unknown"), "owner": a.get("owner", "unknown")})
    publish("agents", list(state.agents.values()))
    return {"registered": len(body.get("agents", []))}


@app.post("/api/gateway/chat")
async def gateway_chat(body: dict):
    """Simulated AI Gateway: every agent step needs the LLM behind the Fabric VC."""
    agent = _agent(body["agent_id"])
    if state.vc_state == "DOWN":
        if agent["status"] != "severed":
            agent["status"] = "severed"
            publish("agent", agent)
        return JSONResponse({"error": "llm_endpoint_unreachable", "vc_id": containment.FABRIC_VC_ID}, status_code=503)
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

    result = detectors.evaluate(state.events[-WINDOW_EVENTS:])
    state.signals, state.hotspots = result["signals"], result["hotspots"]
    state.risk_history.append({"ts": _now(), "risk": result["risk_score"]})
    publish("risk", {"risk": result["risk_score"], "signals": state.signals, "hotspots": state.hotspots})

    risk = result["risk_score"]
    if (risk >= ANALYZE_THRESHOLD and not state.analyzing and not state.incident
            and (state.last_analyzed_risk < 0 or risk - state.last_analyzed_risk >= REANALYZE_DELTA)):
        asyncio.create_task(run_analysis())
    return {"accepted": accepted, "risk": risk}


@app.post("/api/analyze")
async def analyze_now():
    if not state.analyzing:
        asyncio.create_task(run_analysis())
    return {"started": True}


@app.post("/api/killswitch")
async def killswitch():
    if not state.incident:
        await contain("KILL_SWITCH", state.analysis)
    return state.incident


@app.post("/api/review/approve")
async def approve_restore():
    """Human reviewer restores access after investigating."""
    state.vc_state = "UP"
    for a in state.agents.values():
        if a["status"] in ("severed", "contained"):
            a["status"] = "quarantined_review_done"
    if state.incident:
        state.incident.update(status="resolved", resolved_at=_now())
        publish("incident", state.incident)
    publish("vc", state.vc_state)
    publish("agents", list(state.agents.values()))
    return {"vc_state": state.vc_state}


@app.post("/api/reset")
async def reset():
    global state
    state = State()
    publish("reset", state.snapshot())
    return {"reset": True}


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
