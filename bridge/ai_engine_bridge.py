"""Relay WatchTower's analysis requests to Equinix AI Engine from a machine that can reach it.

DAI-VM cannot reach the AI Engine gateway (Zscaler ZPA only), and AI Engine's HTTPS Request node
may not call WatchTower (host not on its allowlist). A laptop on ZPA can reach both, so this runs
there: long-poll WatchTower for a pending analysis, invoke AI Engine, post the reply back.

  WatchTower (VM, AI_ENGINE_MODE=bridge) <-- HTTPS + Basic Auth -- this script --> AI Engine

Run from the repo root on the Mac:   .venv/bin/python bridge/ai_engine_bridge.py
Reads .env: EAP_API_KEY, EAP_PAT, WATCHTOWER_USERNAME, WATCHTOWER_PASSWORD,
            WATCHTOWER_URL (default https://agent-watchtower.solutionvalidation.center),
            Email: by default the bridge asks an AI Engine agent that has the Microsoft 365 connector to send
            it (AI_ENGINE_NOTIFY_AGENT, the agent's name; defaults to the WatchTower agent). Optionally
            AI_ENGINE_EMAIL_WEBHOOK (+ AI_ENGINE_EMAIL_WEBHOOK_TOKEN) sends it through a workflow webhook instead.
Logs job ids, timings and verdicts only, never the telemetry or the agent's reply.
"""

import logging
import os
import platform
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT / "backend"))
from watchtower import ai_engine  # noqa: E402  (needs env loaded)

logging.basicConfig(level=logging.INFO, format="%(asctime)s bridge %(message)s")
log = logging.getLogger("bridge")
logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per long poll is noise

URL = os.getenv("WATCHTOWER_URL", "https://agent-watchtower.solutionvalidation.center").rstrip("/")
EMAIL_WEBHOOK = os.getenv("AI_ENGINE_EMAIL_WEBHOOK", "")
EMAIL_TOKEN = os.getenv("AI_ENGINE_EMAIL_WEBHOOK_TOKEN", "")
NOTIFY_AGENT = os.getenv("AI_ENGINE_NOTIFY_AGENT", ai_engine.AGENT_NAME)
EMAIL_PROMPT = """Send an email with Microsoft 365.
To: {to}
Subject: {subject}
Body (plain text; send it exactly as written, do not add to it):
---
{body}
---
Then reply with one line only: SENT, or NOT SENT: <the reason>."""
POLL_WAIT = 15  # seconds WatchTower holds an idle poll; WatchTower marks the bridge offline ~5s after one is missed


def tls_context() -> ssl.SSLContext:
    """Zscaler re-signs public HTTPS on the Mac, so trust the system keychain (it holds the Zscaler root)."""
    if os.getenv("SSL_CERT_FILE") or platform.system() != "Darwin":
        return ssl.create_default_context()
    pem = subprocess.run(
        ["security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain",
         "/System/Library/Keychains/SystemRootCertificates.keychain"],
        capture_output=True, text=True, check=True).stdout
    bundle = Path(tempfile.gettempdir()) / "watchtower-bridge-ca.pem"
    bundle.write_text(pem)
    return ssl.create_default_context(cafile=str(bundle))


def send_email(wt: httpx.Client, job: dict) -> None:
    """Have AI Engine send one notification (Microsoft 365) and report back to WatchTower."""
    jid = job["job_id"]
    try:
        if EMAIL_WEBHOOK:  # workflow route
            r = httpx.post(EMAIL_WEBHOOK, json={"to": job["to"], "subject": job["subject"], "body": job["body"]},
                           headers={"X-WatchTower-Token": EMAIL_TOKEN} if EMAIL_TOKEN else {}, verify=tls_context(), timeout=60)
            ok = 200 <= r.status_code < 300
            result = {"job_id": jid, "ok": True} if ok else {"job_id": jid, "error": f"email workflow answered HTTP {r.status_code}"}
        else:  # agent route: the agent's Microsoft 365 connector sends it
            reply = (ai_engine.invoke(EMAIL_PROMPT.format(**job), agent=NOTIFY_AGENT, raw=True) or "").strip()
            line = reply.splitlines()[0] if reply else "no reply"
            if line.upper().startswith("SENT"):
                result = {"job_id": jid, "ok": True}
            elif reply.startswith("{"):  # an analysis agent answered with its verdict JSON instead of sending
                result = {"job_id": jid, "error": f"agent {NOTIFY_AGENT!r} treated the email as an analysis request and sent nothing; "
                                                  "set AI_ENGINE_NOTIFY_AGENT to an agent that only has the Microsoft 365 connector"}
            elif "approv" in reply.lower():  # Microsoft 365 holds the send until someone approves it in AI Engine
                result = {"job_id": jid, "pending": True, "error": f"AI Engine: {' '.join(reply.split())[:400]}"}
            else:
                result = {"job_id": jid, "error": f"AI Engine: {' '.join(reply.split())[:400]}"}
    except (ai_engine.AIEngineError, httpx.HTTPError) as e:
        result = {"job_id": jid, "error": f"AI Engine could not send it ({str(e)[:160]})"}
    log.info("email job %s: %s", jid, "sent" if result.get("ok") else ("awaiting approval: " if result.get("pending") else "") + result["error"])
    try:
        wt.post("/api/bridge/result", json=result)
    except httpx.HTTPError as e:
        log.warning("email job %s: could not report back (%s)", jid, type(e).__name__)


def main() -> None:
    user, password = os.getenv("WATCHTOWER_USERNAME"), os.getenv("WATCHTOWER_PASSWORD")
    wt = httpx.Client(base_url=URL, auth=(user, password) if user else None,
                      verify=tls_context(), timeout=POLL_WAIT + 20)

    try:
        log.info("AI Engine agent %s ready", ai_engine.agent_id())
    except (ai_engine.AIEngineError, httpx.HTTPError) as e:
        sys.exit(f"cannot reach AI Engine from here: {e}\n(is Zscaler ZPA connected? are EAP_API_KEY / EAP_PAT set?)")
    log.info("polling %s; email via %s", URL, "workflow webhook" if EMAIL_WEBHOOK else f"AI Engine agent {NOTIFY_AGENT!r} (Microsoft 365)")

    backoff = 2
    while True:
        try:
            r = wt.get("/api/bridge/next", params={"wait": POLL_WAIT})
        except httpx.HTTPError as e:
            log.warning("WatchTower unreachable (%s); retrying in %ss", type(e).__name__, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue
        backoff = 2
        if r.status_code == 204:
            continue
        if r.status_code == 401:
            sys.exit("WatchTower answered 401: check WATCHTOWER_USERNAME / WATCHTOWER_PASSWORD in .env")
        if r.status_code == 409:
            log.warning("%s; waiting", r.json().get("error"))
            time.sleep(15)
            continue
        if r.status_code != 200:
            log.warning("unexpected HTTP %s from WatchTower; retrying", r.status_code)
            time.sleep(5)
            continue

        job = r.json()
        if job.get("kind") == "email":
            send_email(wt, job)
            continue
        started = time.monotonic()
        log.info("job %s: invoking AI Engine", job["job_id"])
        try:
            analysis = ai_engine.invoke(job["message"])
            result = {"job_id": job["job_id"], "analysis": analysis}
            log.info("job %s: %s / %s in %.1fs", job["job_id"], analysis.get("verdict"),
                     analysis.get("risk_level"), time.monotonic() - started)
        except (ai_engine.AIEngineError, httpx.HTTPError) as e:
            result = {"job_id": job["job_id"], "error": str(e)[:300]}
            log.warning("job %s: AI Engine failed: %s", job["job_id"], e)
        try:
            p = wt.post("/api/bridge/result", json=result)
            if p.status_code != 200:
                log.warning("job %s: WatchTower rejected the result (HTTP %s, likely timed out)", job["job_id"], p.status_code)
        except httpx.HTTPError as e:
            log.warning("job %s: could not post the result (%s)", job["job_id"], type(e).__name__)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
