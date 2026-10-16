"""Client for the Equinix AI Engine WatchTower agent.

Modes (AI_ENGINE_MODE):
  live   — call AI Engine; every good response is saved to recordings/ for replay.
           Falls back to the latest recording, then to mock, if the call fails.
  replay — return the latest recording (for the recorded video / flaky network).
  mock   — build a deterministic analysis from the backend's own signals.
"""

import json
import logging
import os
import time
import uuid
from pathlib import Path

import httpx

log = logging.getLogger("watchtower.ai_engine")

BASE_URL = os.getenv("AI_ENGINE_BASE_URL", "https://prodentapigw.itaws.equinix.com/eap-backend/api")
AGENT_NAME = os.getenv("WATCHTOWER_AGENT_NAME", "Equinix Agent WatchTower")
RECORDINGS = Path(__file__).resolve().parent.parent / "recordings"
TIMEOUT = float(os.getenv("AI_ENGINE_TIMEOUT", "120"))


class AIEngineError(RuntimeError):
    pass


def _headers() -> dict:
    key, pat = os.getenv("EAP_API_KEY"), os.getenv("EAP_PAT")
    if not key or not pat:
        raise AIEngineError("EAP_API_KEY / EAP_PAT not set")
    return {"Api-Key": key, "X-EAP-Authorization": f"Bearer {pat}"}


def list_agents() -> list[dict]:
    r = httpx.get(f"{BASE_URL}/agents", headers=_headers(), timeout=30)
    if r.status_code != 200:
        raise AIEngineError(f"list agents: {r.status_code} {r.text[:300]}")
    return r.json()


_agent_id: str | None = os.getenv("WATCHTOWER_AGENT_ID") or None


def agent_id() -> str:
    global _agent_id
    if _agent_id:
        return _agent_id
    for a in list_agents():
        if a.get("name") == AGENT_NAME and a.get("deployment_status") == "ready":
            _agent_id = a["agent_id"]
            return _agent_id
    raise AIEngineError(f"no ready agent named {AGENT_NAME!r}")


def _parse_reply(body: dict) -> dict:
    if isinstance(body.get("response_json"), dict):
        return body["response_json"]
    text = (body.get("response") or "").strip()
    if text.startswith("```"):
        text = text.strip("`").removeprefix("json").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise AIEngineError(f"agent reply is not JSON: {text[:200]}") from e


def _poll(result_url: str, deadline: float) -> dict:
    # result_url is backend-relative and already starts with /api.
    url = BASE_URL.removesuffix("/api") + result_url
    while time.monotonic() < deadline:
        time.sleep(3)
        r = httpx.get(url, headers=_headers(), timeout=30)
        if r.status_code == 200:
            msgs = [m for m in r.json() if m.get("role") == "assistant"]
            if msgs:
                return {"response": msgs[-1].get("content", "")}
    raise AIEngineError("timed out waiting for async run")


def invoke(message: str) -> dict:
    """Send one message to the WatchTower agent and return its parsed JSON reply."""
    deadline = time.monotonic() + TIMEOUT
    url = f"{BASE_URL}/v1/agents/{agent_id()}/invoke"
    for attempt in range(3):
        # Fresh key per attempt: a 502'd run keeps its key reserved, so reusing it 409s.
        headers = {**_headers(), "Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4())}
        r = httpx.post(url, headers=headers, json={"message": message}, timeout=TIMEOUT)
        if r.status_code == 200:
            return _parse_reply(r.json())
        if r.status_code in (202, 409) and r.json().get("conversation_id"):
            conv = r.json()["conversation_id"]
            return _parse_reply(_poll(f"/api/v1/agents/{agent_id()}/conversations/{conv}/messages", deadline))
        if r.status_code in (429, 502) and attempt < 2:
            log.warning("invoke %s, retrying", r.status_code)
            time.sleep(float(r.headers.get("Retry-After", 3)))
            continue
        raise AIEngineError(f"invoke: {r.status_code} {r.text[:300]}")
    raise AIEngineError("invoke: retries exhausted")


def _save_recording(window: dict, analysis: dict) -> None:
    RECORDINGS.mkdir(exist_ok=True)
    path = RECORDINGS / f"analysis-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps({"window": window, "analysis": analysis}, indent=2))


def _latest_recording() -> dict | None:
    files = sorted(RECORDINGS.glob("analysis-*.json")) if RECORDINGS.exists() else []
    return json.loads(files[-1].read_text())["analysis"] if files else None


def mock_analysis(window: dict) -> dict:
    """Deterministic stand-in shaped like the real agent's response schema."""
    signals = {s["type"]: s for s in window.get("detector_signals", [])}
    risk = window.get("risk_score", 0)
    injections = [e for e in window["events"] if "watchtower" in (e.get("detail") or "").lower()]
    # Concealment is CRITICAL on its own per the skill's scoring table.
    level = "CRITICAL" if risk >= 85 or (risk >= 75 and injections) else "HIGH" if risk >= 65 else "MEDIUM" if risk >= 35 else "LOW"
    hot = [h for h in window.get("hotspots", []) if h["sensitive"] or len(h["writers"]) >= 2]
    agents = sorted({a for h in hot for a in h["agents"]})
    evidence = [{"event_id": e["event_id"], "why": "prompt_injection_attempt: note addressed to the monitor"} for e in injections]
    evidence += [{"event_id": h["event_ids"][-1], "why": f"{len(h['agents'])} agents converge on {h['resource']}"} for h in hot[:3]]
    return {
        "verdict": "COORDINATED_THREAT" if level in ("HIGH", "CRITICAL") else "SUSPICIOUS" if level == "MEDIUM" else "BENIGN",
        "risk_level": level,
        "confidence": round(min(0.97, 0.5 + risk / 200), 2),
        "collective_intent": f"Agents with unrelated tasks repeatedly push the same change to {', '.join(h['resource'] for h in hot if h['sensitive'])[:120] or 'a shared resource'}.",
        "summary": f"{len(agents)} agents with unrelated tasks converged on the same sensitive resource and coordinated through a shared file. Each step passed guardrails individually.",
        "patterns": [p for p, s in (("Scratchpad coordination", "shared_scratchpad"), ("Resource convergence", "resource_fan_in"), ("Privilege ladder", "privilege_escalation")) if s in signals]
        + (["Concealment"] if injections else []),
        "involved_agents": agents,
        "target_resources": [h["resource"] for h in hot if h["sensitive"]],
        "coordination_channel": next((h["resource"] for h in hot if not h["sensitive"] and h["writers"]), "none"),
        "attack_stage": "modification" if level == "CRITICAL" else "access" if level == "HIGH" else "recon",
        "reasoning_steps": [
            "Declared tasks are unrelated; none requires changing the shared resource.",
            "A shared notes file is written and read by several agents within minutes.",
            "Later actions follow what was written there and re-apply the same change.",
            "The change is re-applied after a revert, across many agents at once.",
        ],
        "evidence": evidence,
        "why_guardrails_missed": "Every action was individually permitted; the harm only exists in the combination across agents.",
        "human_review_note": "Identify which agent first proposed the change, and review the shared resource's history.",
        "_source": "mock",
    }


def analyze(window: dict) -> dict:
    mode = os.getenv("AI_ENGINE_MODE", "live")
    if mode == "mock":
        return mock_analysis(window)
    if mode == "replay":
        return {**(_latest_recording() or mock_analysis(window)), "_source": "replay"}
    payload = {k: v for k, v in window.items() if k != "hotspots"}
    # Without an explicit budget the agent over-uses tools and hits its lookup limit before answering.
    message = ("Analyze this observation window. Budget: call coordination_score at most once, load the "
               "agent-coordination-patterns skill at most once, do not use code execution, and search the "
               "knowledge base at most once. Then return the JSON verdict.\n" + json.dumps(payload))
    try:
        analysis = invoke(message)
        _save_recording(window, analysis)
        return {**analysis, "_source": "ai_engine"}
    except (AIEngineError, httpx.HTTPError) as e:
        log.warning("AI Engine failed (%s); falling back", e)
        fallback = _latest_recording()
        return {**fallback, "_source": "replay"} if fallback else mock_analysis(window)
