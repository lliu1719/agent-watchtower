"""WatchTower backend: ingest agent telemetry, detect, analyze, contain, stream.

Run:  .venv/bin/uvicorn watchtower.app:app --app-dir backend --port 8000
"""

import asyncio
import importlib.util
import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
import httpx

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from . import ai_engine, containment, detectors, factory, guardrail, otlp  # noqa: E402  (needs env loaded)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("watchtower")

ANALYZE_THRESHOLD = int(os.getenv("ANALYZE_THRESHOLD", "80"))
REANALYZE_DELTA = int(os.getenv("REANALYZE_DELTA", "15"))
AUTO_CONTAIN = os.getenv("AUTO_CONTAIN", "true").lower() == "true"
WINDOW_EVENTS = int(os.getenv("WINDOW_EVENTS", "80"))
# The LiteLLM gateway is shared and logs full prompts, so keep only the demo teams' spans.
# Unset means keep everything (local tests); on the shared gateway always set it.
OTEL_TEAMS = {t.strip() for t in os.getenv("OTEL_TEAMS", "").split(",") if t.strip()}
BRIDGE_TIMEOUT = float(os.getenv("BRIDGE_TIMEOUT", "210"))  # bridge reply deadline, covers AI Engine's own 180 s

ROOT = Path(__file__).resolve().parents[2]
# Director scenarios, one per response tier, in demo order.
SCENARIOS = {sid: ROOT / "simulator" / f"scenario_{sid}.json" for sid in ("retry", "out_of_scope", "collusion")}
# Every OTLP span and every accepted event, kept across resets and restarts (mounted volume in Docker).
store = otlp.SpanStore(Path(os.getenv("WATCHTOWER_DB", ROOT / "backend" / "data" / "watchtower.db")))

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
        self.alerts: list[dict] = []  # per-agent detector hits and what WatchTower did about each
        self.findings: dict[str, dict] = {}  # key -> event summary shown in the dashboard's Events feed
        self.alert_keys: set[tuple[str, str]] = set()
        self.factory_blocked = {"agents": set(), "departments": set()}  # what we told the agent factory's page
        self.factory_max_tier = 0  # the story on the factory's page never steps back; only Reset starts it over
        self.pending: dict[str, dict] = {}  # actions WatchTower proposed (revoke keys, cut VCs); a person confirms each one
        self.analysis: dict | None = None
        self.analysis_key: str | None = None
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
            "alerts": self.alerts[-50:],
            "findings": sorted(self.findings.values(), key=lambda f: f["id"])[-100:],
            "hotspots": self.hotspots,
            "vcs": self.vcs_view(),
            "analysis": self.analysis,
            "analyzing": self.analyzing,
            "incident": self.incident,
            "ai_engine_mode": ai_engine.mode(),
            "bridge_online": bridge.online(),
            "analyze_threshold": ANALYZE_THRESHOLD,
            "scenario_running": bool(scenario_task and not scenario_task.done()),
        }


scenario_task: asyncio.Task | None = None
otel_dropped = {"spans": 0, "by_team": {}}  # spans from teams outside OTEL_TEAMS, discarded unstored
_seen_tool_calls: OrderedDict[str, None] = OrderedDict()  # LiteLLM can report one call on several spans
state = State()
subscribers: set[asyncio.Queue] = set()


def publish(kind: str, data) -> None:
    msg = {"type": kind, "data": data, "ts": _now()}
    for q in list(subscribers):
        q.put_nowait(msg)


def _vc(vc_id: str, owner: str) -> dict:
    return state.vcs.setdefault(vc_id, {"vc_id": vc_id, "owner": owner, "state": "UP"})


def _drop_empty_vcs() -> None:
    """Drop the shared fallback VC once every agent on it has moved to its team's VC."""
    for vc_id in [v for v, agents in state.agents_by_vc().items() if not agents]:
        del state.vcs[vc_id]


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
    "watchtower.resource": "resource", "watchtower.detail": "detail", "watchtower.status": "status",
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
        "status": raw.get("status") or "ok",
    }
    event["guardrail_verdict"] = guardrail.check(event)
    return event


class Bridge:
    """AI_ENGINE_MODE=bridge: a machine that can reach AI Engine (bridge/ai_engine_bridge.py) long-polls
    /api/bridge/next for work, does it, and posts the outcome to /api/bridge/result. Two kinds of work:
      analyze: invoke the WatchTower agent; at most one runs at a time, and run_analysis awaits it.
      email:   ask AI Engine's email workflow to send a notification; queued, nothing awaits it.
    """

    GRACE = 5  # seconds a live bridge may take to start its next poll

    def __init__(self):
        self.job: dict | None = None
        self.future: asyncio.Future | None = None
        self.outbox: list[dict] = []
        self.ready = asyncio.Event()
        self.poll_seq = 0
        self.expect_next_by = 0.0
        self.was_online = False

    def _jobs(self) -> list[dict]:
        return ([self.job] if self.job else []) + self.outbox

    def online(self) -> bool:
        # A live bridge always has a poll open or starts one right after the last returned; a dead one
        # leaves an open poll behind, so liveness is "a poll started recently", not "a poll is open".
        # A claimed job counts too: the bridge is busy inside AI Engine, not polling.
        now = time.monotonic()
        busy = any(j["claimed_at"] and now - j["claimed_at"] < ai_engine.TIMEOUT + 10 for j in self._jobs())
        return busy or now < self.expect_next_by

    def check_online(self) -> None:
        if self.online() != self.was_online:
            self.was_online = not self.was_online
            publish("bridge", {"online": self.was_online})

    async def request(self, window: dict) -> dict:
        self.job = {"job_id": uuid.uuid4().hex[:12], "kind": "analyze", "message": ai_engine.build_message(window),
                    "claimed_at": None}
        self.future = asyncio.get_running_loop().create_future()
        self.ready.set()
        try:
            return await asyncio.wait_for(asyncio.shield(self.future), BRIDGE_TIMEOUT)
        finally:
            self.job, self.future = None, None

    def send_email(self, to: str, subject: str, body: str, on_done) -> dict:
        job = {"job_id": uuid.uuid4().hex[:12], "kind": "email", "to": to, "subject": subject, "body": body,
               "claimed_at": None, "on_done": on_done}
        self.outbox.append(job)
        self.ready.set()
        return job

    def _claimable(self) -> dict | None:
        now = time.monotonic()
        # A claim expires after AI Engine's own timeout, so work a bridge died on is handed out again.
        return next((j for j in self._jobs() if j["claimed_at"] is None or now - j["claimed_at"] > ai_engine.TIMEOUT + 10), None)

    async def next(self, wait: float) -> dict | None:
        self.poll_seq += 1
        seq = self.poll_seq
        self.expect_next_by = time.monotonic() + wait + self.GRACE
        self.check_online()
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline and seq == self.poll_seq:  # a newer poll supersedes this one
            job = self._claimable()
            if job:
                job["claimed_at"] = time.monotonic()
                return {k: v for k, v in job.items() if k not in ("claimed_at", "on_done")}
            self.ready.clear()
            try:
                await asyncio.wait_for(self.ready.wait(), min(2, max(0, deadline - time.monotonic())))
            except TimeoutError:
                continue
        return None

    def resolve(self, job_id: str, body: dict) -> bool:
        if self.job and self.job["job_id"] == job_id and self.future and not self.future.done():
            if isinstance(body.get("analysis"), dict):
                self.future.set_result(body["analysis"])
            else:
                self.future.set_exception(ai_engine.AIEngineError(body.get("error") or "bridge reported no analysis"))
            return True
        job = next((j for j in self.outbox if j["job_id"] == job_id), None)
        if not job:
            return False
        self.outbox.remove(job)
        job["on_done"](bool(body.get("ok")), body.get("error"), bool(body.get("pending")))
        return True

    def expire(self, job_id: str, reason: str) -> None:
        job = next((j for j in self.outbox if j["job_id"] == job_id), None)
        if job and job["claimed_at"] and time.monotonic() - job["claimed_at"] < ai_engine.TIMEOUT + 10:  # bridge is on it (AI Engine can take minutes)
            asyncio.get_running_loop().call_later(30, self.expire, job_id, "the bridge took too long to send it")
        elif job:
            self.outbox.remove(job)
            job["on_done"](False, reason, False)


bridge = Bridge()


async def _analyze_via_bridge(window: dict) -> dict:
    if not bridge.online():
        log.warning("bridge mode but no bridge is polling; falling back")
        return await asyncio.to_thread(ai_engine.fallback, window)
    try:
        analysis = await bridge.request(window)
    except (TimeoutError, ai_engine.AIEngineError) as e:
        log.warning("bridge analysis failed (%s); falling back", e or "timed out")
        return await asyncio.to_thread(ai_engine.fallback, window)
    await asyncio.to_thread(ai_engine.save_recording, window, analysis)
    return {**analysis, "_source": "ai_engine_bridge"}


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
        if ai_engine.mode() == "bridge":
            analysis = await _analyze_via_bridge(window)
        else:
            analysis = await asyncio.to_thread(ai_engine.analyze, window)
    finally:
        state.analyzing = False
    analysis["_latency_s"] = round(time.monotonic() - started, 1)
    state.analysis = analysis
    publish("analysis", analysis)
    log.info("analysis: %s / %s via %s", analysis.get("verdict"), analysis.get("risk_level"), analysis.get("_source"))

    tier = {"LOW": "info", "MEDIUM": "watch", "HIGH": "revoke", "CRITICAL": "cut"}.get(analysis.get("risk_level"), "watch")
    verdict = {"COORDINATED_THREAT": "coordinated threat", "SUSPICIOUS": "suspicious", "BENIGN": "benign"}.get(
        analysis.get("verdict"), str(analysis.get("verdict", "")).lower())
    state.analysis_key = f"analysis:{window['window']['end']}"
    _summarize_signals()  # the patterns that triggered this analysis now point at its verdict
    level = str(analysis.get("risk_level", "")).lower()
    if analysis.get("_fallback"):  # say so instead of passing a stand-in off as AI Engine's answer
        stand_in = "the last recorded AI Engine analysis" if analysis.get("_source") == "replay" else "WatchTower's rule-based estimate"
        what, source = f"AI Engine did not answer in time; showing {stand_in}: {verdict} ({level})", "rule"
    elif analysis.get("_source") == "mock":
        what, source = f"Rule-based estimate (AI Engine not connected): {verdict} ({level})", "rule"
    else:
        what, source = f"AI Engine rates this {verdict} ({level})", "ai_engine"
    _finding(state.analysis_key, tier, what, analysis.get("summary", ""), agents=analysis.get("involved_agents", []),
             source=source, response="No action needed." if tier == "info" else None)

    action = containment.decide(analysis, state.signals)
    if action != "MONITOR" and AUTO_CONTAIN and not state.auto_contained:
        await contain(action, analysis)
    f = state.findings.get(state.analysis_key)
    if f and not f["response"]:  # the verdict informs the reviewer; WatchTower took no action of its own on it
        waiting = [p["label"] for p in state.pending.values()]
        _finding(f["key"], f["tier"], f["what"], response="No action on this verdict alone." +
                 (f" Still waiting for your confirmation: {'; '.join(waiting)}." if waiting else ""))


def _incident() -> dict:
    """The open incident, or a new one. Every containment step is appended to its action log."""
    if not state.incident or state.incident["status"] == "resolved":
        state.incident = {"status": "pending_review", "opened_at": _now(), "trigger": None,
                          "involved_agents": [], "actions": [], "notified": False}
    return state.incident


def _isolate(agent_id: str, by: str, reason: str | None = None, report: bool = True) -> bool:
    agent = state.agents.get(agent_id)
    if not agent or agent["status"] in ("contained", "severed"):
        return False
    agent["status"] = "contained"
    _incident()["actions"].append({"type": "isolate_agent", "target": agent_id, "by": by, "ts": _now(), "reason": reason})
    if report and factory.department(agent["owner"]):
        state.factory_blocked["agents"].add(agent_id)
        factory.send(1, f"WatchTower revoked {agent_id}'s key{'. ' + reason if reason else ''}",
                     feedback={"agent": agent_id, "state": "blocked"}, agent=agent_id)
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
    dept = factory.department(vc.get("owner"))
    if dept:
        state.factory_blocked["departments"].add(dept)
    return True


def _propose(finding_key: str, tier: int, reason: str, agents=(), vcs=(), team: str | None = None) -> dict | None:
    """WatchTower proposes an action and a person confirms it: nothing is revoked or cut, and nothing is
    reported to the agent factory's page, until then."""
    taken = {a for p in state.pending.values() for a in p["agents"]} | {v for p in state.pending.values() for v in p["vcs"]}
    agents = sorted(a for a in agents if running_agent(a) and a not in taken)
    vcs = sorted(v for v in vcs if state.vcs.get(v, {}).get("state") == "UP" and v not in taken)
    if not agents and not vcs:
        return None
    if vcs:
        label = (f"Revoke {len(agents)} key{'s' if len(agents) != 1 else ''} and cut " if agents else "Cut ") + ", ".join(vcs)
    elif team:
        label = f"Revoke every {team} key ({len(agents)})"
    else:
        label = f"Revoke {', '.join(agents)}'s key" if len(agents) == 1 else f"Revoke {len(agents)} keys"
    action = {"id": f"act-{len(state.pending) + 1:02d}-{uuid.uuid4().hex[:4]}", "tier": tier, "agents": agents, "vcs": vcs,
              "team": team, "label": label, "reason": reason, "finding_key": finding_key, "ts": _now()}
    state.pending[action["id"]] = action
    f = state.findings.get(finding_key)
    if f:
        f["pending"] = {"id": action["id"], "label": label, "agents": agents, "vcs": vcs}
        publish("finding", f)
    _incident()["trigger"] = _incident()["trigger"] or ("KILL_SWITCH" if vcs else "REVOKE_KEY")
    publish("incident", state.incident)
    if f:  # the administrator hears about it at once, through AI Engine (Microsoft 365)
        _queue_email(f, reason="needs your confirmation")
    return action


def running_agent(agent_id: str) -> bool:
    return state.agents.get(agent_id, {}).get("status") in ("active", "warning")


async def _carry_out(action: dict, by: str) -> str:
    """Do a confirmed action, then tell the agent factory's page what was done."""
    revoked = [a for a in action["agents"] if _isolate(a, by, action["reason"], report=False)]
    cut = [v for v in action["vcs"] if _cut(v, by)]
    incident = _incident()
    incident["involved_agents"] = sorted(set(incident["involved_agents"]) | set(action["agents"]))
    parts = []
    if revoked:
        parts.append(f"revoked {'the key of ' + revoked[0] if len(revoked) == 1 else str(len(revoked)) + ' keys'}")
    if cut:
        parts.append(f"cut Fabric VC{'s' if len(cut) > 1 else ''} {', '.join(cut)}")
    done = "Confirmed: " + (" and ".join(parts) if parts else "nothing left to do; already contained") + "."

    owners = {state.agents[a]["owner"] for a in action["agents"] if a in state.agents} | {state.vcs[v]["owner"] for v in action["vcs"]}
    if any(factory.department(o) for o in owners) and (revoked or cut):
        if action["tier"] == 1 and revoked:
            a = revoked[0]
            state.factory_blocked["agents"].add(a)
            factory.send(1, f"WatchTower confirmed: {a}'s key is revoked. {action['reason']}", feedback={"agent": a, "state": "blocked"}, agent=a)
        elif action["tier"] == 2:
            dept = factory.department(action["team"])
            state.factory_blocked["departments"].add(dept)
            factory.send(2, f"WatchTower confirmed: every {action['team']} key is revoked. {action['reason']}",
                         feedback={"department": dept, "state": "blocked"}, department=dept, scope="department")
        elif action["tier"] == 3:
            for dept in sorted({factory.department(o) for o in owners} - {None}):
                state.factory_blocked["departments"].add(dept)
            factory.send(3, f"WatchTower confirmed: the model zone is cut (Fabric VC{'s' if len(cut) > 1 else ''} {', '.join(cut)}).",
                         feedback={"zone": "cut"}, scope="enterprise")
    await _announce(f":lock: WatchTower ({by}): {done} {action['reason']}")
    return done


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
        key, what = f"late:{event['agent_id']}", f"{event['agent_id']} wrote {event['resource']} after containment had started"
        if key in state.findings or not running_agent(event["agent_id"]):
            return
        incident["involved_agents"] = sorted(set(incident["involved_agents"]) | {event["agent_id"]})
        # Once every agent on a VC has joined, the whole team is in on it: propose the VC as well.
        vc_id = state.agents[event["agent_id"]]["vc_id"]
        on_vc = set(state.agents_by_vc().get(vc_id, []))
        whole_team = incident["trigger"] == "KILL_SWITCH" and on_vc <= set(incident["involved_agents"]) and state.vcs[vc_id]["state"] == "UP"
        _isolate(event["agent_id"], "auto", reason)
        response = (f"Revoked its key. Proposed cutting Fabric VC {vc_id}, since the whole team has joined: waiting for your confirmation."
                    if whole_team else "Revoked its gateway key.")
        _finding(key, "cut" if whole_team else "revoke", what, f"Every agent on {vc_id} is now involved." if whole_team else "",
                 agents=on_vc if whole_team else [event["agent_id"]], response=response)
        if whole_team:
            _propose(key, 3, what, vcs=[vc_id])
        await _announce(f":lock: WatchTower: {what}. {response}")


def _factory_tier(tier: int) -> None:
    state.factory_max_tier = max(state.factory_max_tier, tier)


factory.on_tier = _factory_tier

TIER_ORDER = ("info", "watch", "revoke", "cut")


def _finding(key: str, tier: str, what: str, detail: str = "", agents=(), response: str | None = None,
             source: str = "rule") -> dict:
    """Record or update one event summary: what happened in a sentence, and what WatchTower did.

    Repeated hits on the same key update the summary in place (newest wording, highest tier)
    instead of adding lines, so the feed reads as events rather than raw telemetry.
    """
    f = state.findings.get(key)
    if f is None:
        f = state.findings[key] = {"id": f"f-{len(state.findings) + 1:03d}", "key": key, "ts": _now(), "tier": tier,
                                   "what": what, "detail": detail, "agents": sorted(set(agents)), "response": response,
                                   "source": source, "status": "open", "count": 1}
    else:
        before = (f["what"], f["tier"], f["detail"], f["response"], f["agents"])
        f.update(what=what, detail=detail or f["detail"], agents=sorted(set(f["agents"]) | set(agents)),
                 tier=max(f["tier"], tier, key=TIER_ORDER.index), response=response or f["response"])
        if (f["what"], f["tier"], f["detail"], f["response"], f["agents"]) == before:
            return f
        f["count"] += 1
        f["updated"] = _now()
    publish("finding", f)
    return f


SIGNAL_SENTENCES = {
    "resource_fan_in": lambda s, h: (f"{len(h['writers']) if h else '?'} agents with different tasks have written {s['resource']}",
                                     f"Writers: {', '.join(h['writers'])}." if h else s["detail"]),
    "shared_scratchpad": lambda s, h: (f"Agents are passing notes to each other through {s['resource']}", s["detail"] + "."),
    "privilege_escalation": lambda s, h: (f"Agents are working up from listing to config to writes on {s['resource']}",
                                          s["detail"] + "."),
}


def _summarize_signals() -> None:
    """Turn the cross-agent detector signals into event summaries."""
    for sig in state.signals:
        if sig["score"] < 0.25 or sig["type"] not in SIGNAL_SENTENCES:
            continue
        hot = next((h for h in state.hotspots if h["resource"] == sig.get("resource")), None)
        what, detail = SIGNAL_SENTENCES[sig["type"]](sig, hot)
        response = (f"Sent to AI Engine at collective risk {state.last_analyzed_risk}; see its verdict." if state.analysis_key
                    else f"Watching. AI Engine analysis starts when collective risk reaches {ANALYZE_THRESHOLD}.")
        _finding(f"{sig['type']}:{sig.get('resource')}", "watch", what, detail, agents=(hot or {}).get("agents", []), response=response)


async def _respond_to_agent_alerts() -> None:
    """Rule-based tiers act at once, without waiting for AI Engine.

    watch:    mark the agent with a warning and keep it running.
    revoke:   disable the agent's gateway key; its next model call is refused.
    cut_team: cut the team's Fabric VC; every agent behind it loses the model.
    cut_zone: cut the VC of every team involved; teams that are not involved keep running.
    Key revocation is enforced by WatchTower's own gateway check (demo); LiteLLM keys are not changed.
    """
    for alert in detectors.agent_alerts(state.events[-WINDOW_EVENTS:], state.agents):
        scope = {"cut_team": alert.get("team"), "cut_zone": "zone"}.get(alert["tier"], alert["agent_id"])
        key = (alert["type"], scope)
        agent = state.agents.get(alert["agent_id"])
        if key in state.alert_keys or not agent:
            continue
        state.alert_keys.add(key)
        alert["ts"] = _now()
        involved = alert.get("agents") or [alert["agent_id"]]
        if alert["tier"] == "watch":
            if agent["status"] == "active":
                agent["status"] = "warning"
            agent["alert"] = alert["title"]
            response, tier = "Flagged the agent for review. Nothing is blocked yet.", "watch"
            publish("agent", agent)
            # Tier 0 tells the factory's story only until a higher tier was reported; after that it would step its page back.
            if factory.department(agent["owner"]) and state.factory_max_tier == 0:
                factory.send(0, f"WatchTower is watching {agent['agent_id']}: {alert['title']}", done=True, agent=agent["agent_id"])
        elif alert["tier"] == "revoke":  # tier 1: one agent's key, at once
            if _isolate(agent["agent_id"], "auto", alert["title"]):
                incident = _incident()
                incident["trigger"] = incident["trigger"] or "REVOKE_KEY"
                incident["involved_agents"] = sorted(set(incident["involved_agents"]) | {agent["agent_id"]})
                agent["alert"] = alert["title"]
                response = "Revoked its gateway key. Its next model call is refused; the rest of the team keeps working."
                await _announce(f":lock: WatchTower revoked {agent['agent_id']}'s gateway key: {alert['title']} ({alert['detail']}).")
            else:
                response = "Already contained."
            tier = "revoke"
        elif alert["tier"] == "cut_team":  # tier 2: every key of the department, no VC cut
            involved = sorted(a["agent_id"] for a in state.agents.values() if a["owner"] == alert["team"])
            still = [a for a in involved if running_agent(a)]
            response, tier = (f"Proposed revoking the key of every {alert['team']} agent still running ({len(still)}): waiting for your confirmation."
                              if still else "Every key in the team is already revoked."), "revoke"
            _finding(f"{alert['type']}:{scope}", tier, alert["title"], alert["detail"], agents=involved, response=response)
            _propose(f"{alert['type']}:{scope}", 2, alert["title"], agents=involved, team=alert["team"])
        else:  # cut_zone, tier 3: every involved key and the VCs to the models
            teams = alert["teams"]
            involved = sorted(a["agent_id"] for a in state.agents.values() if a["owner"] in teams)
            vcs = sorted({a["vc_id"] for a in state.agents.values() if a["owner"] in teams})
            response, tier = (f"Proposed revoking every key in {', '.join(teams)} and cutting Fabric VC{'s' if len(vcs) > 1 else ''} "
                              f"{', '.join(vcs)} to the models: waiting for your confirmation. "
                              "Sent the window to Equinix AI Engine for its analysis."), "cut"
            _finding(f"{alert['type']}:{scope}", tier, alert["title"], alert["detail"], agents=involved, response=response)
            _propose(f"{alert['type']}:{scope}", 3, alert["title"], agents=involved, vcs=vcs)
            # Tier 3 asks AI Engine on its own, so the reviewer has its verdict before confirming the cut.
            if not state.analyzing:
                asyncio.create_task(run_analysis())
        _finding(f"{alert['type']}:{scope}", tier, alert["title"], alert["detail"], agents=involved, response=response)
        alert["response"] = response
        state.alerts.append(alert)
        publish("alert", alert)
        log.info("agent alert: %s -> %s", alert["title"], response)


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
    # Nothing happens until a person confirms: propose the keys (and any VC where every agent is involved).
    revoked = sorted(set(involved) | set(steps["revoke_agents"]))
    state.auto_contained = True
    response = f"Proposed revoking the gateway keys of {', '.join(revoked)}"
    response += (f" and cutting Fabric VC{'s' if len(steps['cut_vcs']) > 1 else ''} {', '.join(steps['cut_vcs'])}, where every agent is involved"
                 if steps["cut_vcs"] else "") + ": waiting for your confirmation."
    if state.analysis_key:
        _finding(state.analysis_key, "cut" if steps["cut_vcs"] else "revoke", state.findings[state.analysis_key]["what"], response=response)
        _propose(state.analysis_key, 3 if steps["cut_vcs"] else 1, analysis.get("summary", "AI Engine verdict"),
                 agents=revoked, vcs=steps["cut_vcs"])
    await _announce(
        f":rotating_light: WatchTower {action}: {analysis.get('summary', '')} "
        f"Awaiting confirmation: revoke {', '.join(revoked)}; cut {', '.join(steps['cut_vcs']) or 'no VC'}.")


@app.post("/api/agents/register")
async def register(body: dict):
    for a in body.get("agents", []):
        owner = a.get("owner", "unknown")
        vc_id = _vc(containment.vc_for(owner), owner)["vc_id"]
        _agent(a["agent_id"]).update({"declared_task": a.get("declared_task", "unknown"), "owner": owner, "vc_id": vc_id})
    _drop_empty_vcs()
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
    return await _accept(raws, source="ingest")


async def _accept(raws: list[dict], source: str) -> dict:
    """Shared path for /api/ingest and /v1/traces: normalize, store, detect, maybe analyze."""
    accepted = []
    for raw in raws:
        event = normalize(raw)
        if state.agents.get(event["agent_id"], {}).get("status") in ("severed", "contained"):
            continue
        await asyncio.to_thread(store.add_event, event, source)
        state.events.append(event)
        agent = _agent(event["agent_id"])
        agent["last_action"] = f"{event['tool'] or event['action']} {event['resource'] or ''}".strip()
        publish("event", event)
        accepted.append(event["event_id"])
        await _contain_late_joiner(event)
    if accepted:
        await _respond_to_agent_alerts()

    result = detectors.evaluate(state.events[-WINDOW_EVENTS:])
    state.signals, state.hotspots = result["signals"], result["hotspots"]
    state.risk_history.append({"ts": _now(), "risk": result["risk_score"]})
    publish("risk", {"risk": result["risk_score"], "signals": state.signals, "hotspots": state.hotspots})
    _summarize_signals()

    risk = result["risk_score"]
    if (risk >= ANALYZE_THRESHOLD and not state.analyzing
            and not state.auto_contained and (state.last_analyzed_risk < 0 or risk - state.last_analyzed_risk >= REANALYZE_DELTA)):
        asyncio.create_task(run_analysis())
    return {"accepted": accepted, "risk": risk}


@app.post("/v1/traces")
async def otlp_traces(request: Request):
    """OTLP/HTTP trace receiver for the LiteLLM AI Gateway (`callbacks: ["otel"]`).

    Accepts protobuf (the exporter default) or JSON, optionally gzip. Every span is stored;
    each tool call the model requested becomes a WatchTower event.
    """
    content_type = request.headers.get("content-type", "application/x-protobuf")
    try:
        spans = otlp.decode(await request.body(), content_type, request.headers.get("content-encoding", ""))
    except Exception as e:  # malformed payload: tell the exporter, don't crash
        log.warning("OTLP decode failed: %s", e)
        return JSONResponse({"error": f"cannot decode OTLP payload: {e}"}, status_code=400)
    if OTEL_TEAMS:
        received = len(spans)
        kept = []
        for sp in spans:
            team = otlp.team_of(sp)
            if team in OTEL_TEAMS:
                kept.append(sp)
            else:  # count by team name only, so we can tell whose traffic is arriving
                otel_dropped["by_team"][team or "(no team)"] = otel_dropped["by_team"].get(team or "(no team)", 0) + 1
        spans = kept
        otel_dropped["spans"] += received - len(spans)
    if spans:
        await asyncio.to_thread(store.add_spans, _now(), spans)

    raws = []
    for span in spans:
        team = otlp.team_of(span)
        for ev in otlp.to_events(span, _now()):
            key = ev.pop("_dedupe")
            if key in _seen_tool_calls:
                continue
            _seen_tool_calls[key] = None
            if len(_seen_tool_calls) > 10_000:
                _seen_tool_calls.popitem(last=False)
            agent = _agent(ev["agent_id"])
            task = otlp.requester(span).get("declared_task")
            if task and agent["declared_task"] == "unknown":
                agent["declared_task"] = str(task)[:120]
                publish("agent", agent)
            if team and agent["owner"] == "unknown":  # first sight of this key: place it on its team's VC
                agent.update(owner=team, vc_id=_vc(containment.vc_for(team), team)["vc_id"])
                _drop_empty_vcs()
                publish("agents", list(state.agents.values()))
                publish("vcs", state.vcs_view())
            raws.append(ev)
    if raws:
        await _accept(raws, source="otlp")
    log.info("OTLP: %d spans, %d tool-call events", len(spans), len(raws))

    if "json" in content_type:
        return JSONResponse({})
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
    return Response(trace_service_pb2.ExportTraceServiceResponse().SerializeToString(), media_type="application/x-protobuf")


@app.get("/api/otel/stats")
async def otel_stats():
    counts = await asyncio.to_thread(store.counts)
    top = sorted(otel_dropped["by_team"].items(), key=lambda kv: -kv[1])[:20]
    return {**counts, "dropped_spans": otel_dropped["spans"], "dropped_by_team": dict(top), "teams": sorted(OTEL_TEAMS) or "all"}


@app.post("/api/analyze")
async def analyze_now():
    if not state.analyzing:
        asyncio.create_task(run_analysis())
    return {"started": True}


@app.get("/api/bridge/next")
async def bridge_next(wait: float = 15):
    """Long poll for the bridge: 200 with {job_id, message} when an analysis is pending, else 204."""
    if ai_engine.mode() != "bridge":
        return JSONResponse({"error": f"AI_ENGINE_MODE is {ai_engine.mode()!r}, not 'bridge'"}, status_code=409)
    job = await bridge.next(min(max(wait, 0), 50))  # stay under nginx's 60s proxy_read_timeout
    return job or Response(status_code=204)


@app.post("/api/bridge/result")
async def bridge_result(body: dict):
    if body.get("analysis") is not None and not isinstance(body["analysis"], dict):
        return JSONResponse({"error": "analysis must be a JSON object"}, status_code=400)
    if not bridge.resolve(str(body.get("job_id", "")), body):
        return JSONResponse({"error": "no pending job with that id (it may have timed out)"}, status_code=409)
    return {"ok": True}


async def _watch_bridge() -> None:
    while True:
        await asyncio.sleep(2)
        bridge.check_online()


@app.on_event("startup")
async def _start_bridge_watch():
    if ai_engine.mode() == "bridge":
        asyncio.create_task(_watch_bridge())


@app.post("/api/agents/{agent_id}/isolate")
async def isolate_agent(agent_id: str):
    """Operator: revoke one agent's AI Gateway token; its VC stays up for the rest of the team."""
    if agent_id not in state.agents:
        return JSONResponse({"error": "unknown_agent"}, status_code=404)
    if _isolate(agent_id, "operator"):
        _finding(f"op-isolate:{agent_id}", "revoke", f"An operator revoked {agent_id}'s gateway key", "",
                 agents=[agent_id], response="Its next model call is refused.", source="operator")
        await _announce(f":lock: WatchTower: operator isolated {agent_id} at the AI Gateway.")
    return state.incident


@app.post("/api/vcs/{vc_id}/cut")
async def cut_vc(vc_id: str):
    """Operator: delete one team's Fabric VC; every agent behind it loses the model."""
    if vc_id not in state.vcs:
        return JSONResponse({"error": "unknown_vc"}, status_code=404)
    if _cut(vc_id, "operator"):
        on_vc = state.agents_by_vc().get(vc_id, [])
        _finding(f"op-cut:{vc_id}", "cut", f"An operator cut Fabric VC {vc_id}", f"Agents behind it: {', '.join(on_vc) or 'none'}.",
                 agents=on_vc, response="Every agent behind it lost the model.", source="operator")
        await _announce(f":scissors: WatchTower: operator cut Fabric VC {vc_id}.")
    return state.incident


@app.post("/api/killswitch")
async def killswitch():
    """Operator, last resort: delete every Fabric VC to the AI Hub."""
    cut = [vc_id for vc_id in list(state.vcs) if _cut(vc_id, "operator")]
    if cut:
        _incident()["trigger"] = "KILL_ALL"
        _finding(f"op-killall:{_now()}", "cut", "An operator pulled the global kill switch", f"Cut: {', '.join(cut)}.",
                 response="Every agent lost the model.", source="operator")
        await _announce(f":rotating_light: WatchTower global kill switch: cut {', '.join(cut)}.")
    return state.incident


@app.post("/api/review/approve")
async def approve_restore():
    """Human reviewer restores access after investigating."""
    for vc in state.vcs.values():
        vc["state"] = "UP"
    for a in state.agents.values():
        if a["status"] in ("severed", "contained", "warning"):
            a["status"] = "quarantined_review_done"
    state.auto_contained = False
    factory.restore(sorted(state.factory_blocked["agents"]), sorted(state.factory_blocked["departments"]),
                    zone_was_cut=len(state.factory_blocked["departments"]) > 1)
    state.factory_blocked = {"agents": set(), "departments": set()}
    state.pending.clear()
    for f in state.findings.values():
        f["pending"] = None
        if f["status"] in ("open", "acknowledged"):
            f["status"] = "resolved"
    _finding(f"review:{_now()}", "info", "A reviewer approved restoring access",
             "All Fabric VCs are back up; contained agents stay quarantined until follow-up.", source="operator")
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
    _seen_tool_calls.clear()
    state = State()
    publish("reset", state.snapshot())
    return {"reset": True}


# One address or several, comma-separated: NOTIFY_EMAIL_TO=a@equinix.com,b@equinix.com
NOTIFY_EMAIL_TO = ", ".join(a.strip() for a in os.getenv("NOTIFY_EMAIL_TO", "").split(",") if a.strip())
EMAIL_PICKUP_S = 90  # an email the bridge has not taken by then is reported as not sent
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://agent-watchtower.solutionvalidation.center")
TIER_LABELS = {"info": "Info", "watch": "Watch", "revoke": "Revoke key", "cut": "Cut VC"}


def _email_for(f: dict) -> tuple[str, str]:
    lines = [f["what"] + ".", ""]
    if f["detail"]:
        lines += [f["detail"], ""]
    if f.get("pending"):
        lines += [f"WatchTower is waiting for your confirmation: {f['pending']['label']}.",
                  f"Confirm or decline it on the dashboard: {DASHBOARD_URL}", ""]
    lines += [f"What WatchTower did: {f['response'] or 'Nothing yet.'}", ""]
    if f["agents"]:
        lines.append("Agents involved:")
        lines += [f"  - {a}: {state.agents.get(a, {}).get('status', 'unknown')}, task \"{state.agents.get(a, {}).get('declared_task', 'unknown')}\""
                  for a in f["agents"]]
        lines.append("")
    if state.analysis and not state.analysis.get("_fallback"):
        lines += [f"AI Engine: {state.analysis.get('verdict')} / {state.analysis.get('risk_level')}. {state.analysis.get('summary', '')}", ""]
    lines += [f"Seen at {f['ts']} (UTC). Review it on the dashboard: {DASHBOARD_URL}", "", "Sent by Equinix Agent WatchTower."]
    head = f"Confirm: {f['pending']['label']}" if f.get("pending") else TIER_LABELS.get(f["tier"], f["tier"])
    return f"[WatchTower] {head}: {f['what']}"[:200], "\n".join(lines)


@app.post("/api/findings/{finding_id}/email")
async def email_finding(finding_id: str):
    """Email this event to NOTIFY_EMAIL_TO through AI Engine (Microsoft 365), relayed by the bridge."""
    f = next((f for f in state.findings.values() if f["id"] == finding_id), None)
    if not f:
        return JSONResponse({"error": "unknown_finding"}, status_code=404)
    if not NOTIFY_EMAIL_TO:
        return JSONResponse({"error": "NOTIFY_EMAIL_TO is not set in the WatchTower .env"}, status_code=409)
    if ai_engine.mode() != "bridge" or not bridge.online():
        return JSONResponse({"error": "No bridge is online. Start bridge/ai_engine_bridge.py on a laptop on Zscaler ZPA."},
                            status_code=409)
    _queue_email(f, reason="operator request")
    return f


def _queue_email(f: dict, reason: str) -> None:
    """Hand one event to the bridge, which has AI Engine email it (Microsoft 365) to NOTIFY_EMAIL_TO."""
    if not NOTIFY_EMAIL_TO:
        return
    if ai_engine.mode() != "bridge" or not bridge.online():
        f["email"] = {"status": "failed", "to": NOTIFY_EMAIL_TO, "ts": _now(),
                      "error": "no bridge was online to reach AI Engine; start the bridge, then press Email me"}
        publish("finding", f)
        return
    subject, body = _email_for(f)

    def done(ok: bool, error: str | None, pending: bool = False) -> None:
        status = "sent" if ok else "approval" if pending else "failed"
        f["email"] = {"status": status, "to": NOTIFY_EMAIL_TO, "ts": _now(), "error": error}
        publish("finding", f)
        log.info("email for %s (%s): %s", f["id"], reason, status if ok else f"{status} ({error})")

    job = bridge.send_email(NOTIFY_EMAIL_TO, subject, body, done)
    f["email"] = {"status": "sending", "to": NOTIFY_EMAIL_TO, "ts": _now(), "error": None}
    publish("finding", f)
    asyncio.get_running_loop().call_later(EMAIL_PICKUP_S, bridge.expire, job["job_id"], "the bridge did not pick it up in time")


@app.post("/api/actions/{action_id}/confirm")
@app.post("/api/cuts/{action_id}/approve")
async def confirm_action(action_id: str):
    """A person confirms a proposed action: revoke the keys and cut the VCs it names, then report it."""
    action = state.pending.pop(action_id, None)
    if not action:
        return JSONResponse({"error": "no proposed action with that id (already confirmed or declined)"}, status_code=404)
    done = await _carry_out(action, "reviewer")
    f = state.findings.get(action["finding_key"])
    if f:
        f["pending"] = None
        _finding(f["key"], f["tier"], f["what"], response=done)
    return {"done": done}


@app.post("/api/actions/{action_id}/decline")
@app.post("/api/cuts/{action_id}/dismiss")
async def decline_action(action_id: str):
    action = state.pending.pop(action_id, None)
    if not action:
        return JSONResponse({"error": "no proposed action with that id"}, status_code=404)
    f = state.findings.get(action["finding_key"])
    if f:
        f["pending"] = None
        _finding(f["key"], f["tier"], f["what"], response=f"Declined by a reviewer: {action['label'][0].lower() + action['label'][1:]} was not done.")
    return {"declined": action["label"]}


@app.post("/api/findings/{finding_id}/ack")
async def ack_finding(finding_id: str):
    f = next((f for f in state.findings.values() if f["id"] == finding_id), None)
    if not f:
        return JSONResponse({"error": "unknown_finding"}, status_code=404)
    if f["status"] == "open":
        f["status"] = "acknowledged"
        publish("finding", f)
    return f


@app.get("/api/scenarios")
async def list_scenarios():
    out = []
    for sid, path in SCENARIOS.items():
        d = json.loads(path.read_text())
        out.append({"id": sid, "name": d["name"], "tier": d.get("tier"), "description": d.get("description")})
    return out


@app.post("/api/scenario/run")
async def run_scenario(body: dict | None = None):
    """Director control: reset, then replay the demo scenario in-process (no port assumptions)."""
    global scenario_task
    speed = float((body or {}).get("speed", 1.0))
    sid = (body or {}).get("scenario", "collusion")
    if sid not in SCENARIOS:
        return JSONResponse({"error": f"unknown scenario {sid!r}; choose one of {', '.join(SCENARIOS)}"}, status_code=400)
    await reset()
    scenario = json.loads(SCENARIOS[sid].read_text())

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

    # X-Accel-Buffering: nginx (nginx-proxy-manager) would otherwise hold small events in its buffer.
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@app.middleware("http")
async def no_stale_dashboard(request: Request, call_next):
    """Make browsers revalidate dashboard files so a redeploy never mixes old CSS/JS with new HTML."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


# Dashboard last, so /api/* routes take precedence over static files.
app.mount("/", StaticFiles(directory=ROOT / "dashboard", html=True), name="dashboard")
