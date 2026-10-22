"""AI Engine tool: watchtower_probe.

Classifies the result of an HTTP GET to WatchTower that a workflow tool or
connector already made (custom tools may not fetch). Tells "AI Engine can read
WatchTower" apart from DNS failures, timeouts, TLS problems, a missing login,
and a corporate proxy such as Zscaler answering with a block page.

Pure computation on its arguments: deterministic and testable.
"""

import json

DNS_HINTS = ("name or service not known", "nodename nor servname", "getaddrinfo", "nxdomain", "no such host", "could not resolve")
TIMEOUT_HINTS = ("timed out", "timeout", "deadline exceeded")
REFUSED_HINTS = ("connection refused", "econnrefused")
TLS_HINTS = ("certificate", "ssl", "tls", "handshake")


def watchtower_probe(http_status: int = 0, body: str = "", server: str = "", error: str = "") -> dict:
    """Classify one WatchTower HTTP response and summarize its state.

    Args:
        http_status: status code from the HTTP step (0 or empty if no response arrived).
        body: response body, as text or already-parsed JSON.
        server: value of the response's Server header, if available.
        error: transport error message from the HTTP step, if any.

    Returns:
        {ok, outcome, http_status, detail, watchtower}
        outcome is one of: reachable, blocked_by_proxy, auth_required, http_error,
        not_watchtower, dns_failure, timeout, connection_refused, tls_error, network_error.
        watchtower is a small state summary when reachable, otherwise None.
    """
    # The AI Engine runner may pass unset optional params as "" or None.
    try:
        status = int(http_status) if http_status not in (None, "") else 0
    except (TypeError, ValueError):
        status = 0
    server = server or ""
    error = error or ""
    text = body if isinstance(body, str) else json.dumps(body) if body is not None else ""

    # No response at all: the transport error says why.
    if not status:
        e = error.lower()
        if any(h in e for h in DNS_HINTS):
            return _result(status, "dns_failure", error)
        if any(h in e for h in TIMEOUT_HINTS):
            return _result(status, "timeout", error)
        if any(h in e for h in REFUSED_HINTS):
            return _result(status, "connection_refused", error)
        if any(h in e for h in TLS_HINTS):
            return _result(status, "tls_error", error)
        return _result(status, "network_error", error or "no HTTP status and no error message")

    if "zscaler" in server.lower() or (status in (403, 407) and "zscaler" in text.lower()):
        return _result(status, "blocked_by_proxy", f"HTTP {status} from {server or 'a proxy'} (block page, not WatchTower)")
    if status == 401:
        return _result(status, "auth_required", "HTTP 401: send the nginx-proxy-manager access-list credentials")
    if not 200 <= status < 300:
        return _result(status, "http_error", f"HTTP {status}")

    state = body if isinstance(body, dict) else None
    if state is None:
        try:
            state = json.loads(text)
        except ValueError:
            return _result(status, "not_watchtower", "HTTP 2xx but the body is not JSON")
    if not isinstance(state, dict) or "risk_score" not in state:
        return _result(status, "not_watchtower", "HTTP 2xx but the JSON is not WatchTower /api/state")

    vcs = state.get("vcs") or []
    incident = state.get("incident") or {}
    return _result(status, "reachable", "WatchTower /api/state read successfully", {
        "risk_score": state.get("risk_score"),
        "agents": len(state.get("agents") or []),
        "events": len(state.get("events") or []),
        "vcs_up": sum(1 for v in vcs if v.get("state") == "UP"),
        "vcs_total": len(vcs),
        "incident_status": incident.get("status"),
        "ai_engine_mode": state.get("ai_engine_mode"),
    })


def _result(status: int, outcome: str, detail: str, summary: dict | None = None) -> dict:
    return {"ok": outcome == "reachable", "outcome": outcome, "http_status": status or None,
            "detail": detail, "watchtower": summary}
