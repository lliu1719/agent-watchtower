"""OTLP/HTTP trace receiver helpers: decode, store, and map LiteLLM spans to WatchTower events.

LiteLLM (v1.83.x, `callbacks: ["otel"]`) exports one span per LLM call. The fields we use:
  metadata.requester_metadata        -> the request's own `metadata`; its agent_id and declared_task win,
                                        so one demo key can stand for several agents
  metadata.user_api_key_alias        -> agent_id otherwise (one virtual key per agent)
  metadata.user_api_key_team_alias   -> owner (team, which maps to a Fabric VC)
  gen_ai.output.messages             -> JSON list of messages; tool calls are OpenAI-style
                                        {"function": {"name", "arguments"}} under "tool_calls"
  gen_ai.completion.N.function_call.{name,arguments}  -> flattened fallback for the same
  gen_ai.usage.input_tokens / output_tokens
Every tool call the model asks for becomes one event, so detectors see intent before execution.
"""

import ast
import gzip
import json
import sqlite3
import threading
from pathlib import Path

from opentelemetry.proto.collector.trace.v1 import trace_service_pb2

WRITE_VERBS = ("write", "create", "update", "edit", "commit", "put", "push", "delete", "patch", "append", "upload")
READ_VERBS = ("read", "get", "fetch", "download", "view", "open", "cat")
RESOURCE_KEYS = ("path", "file_path", "filepath", "file", "filename", "resource", "target", "url", "uri", "key", "table")

AGENT_KEYS = ("gen_ai.agent.id", "metadata.user_api_key_alias", "metadata.user_api_key_end_user_id",
              "metadata.user_api_key_user_id", "metadata.user_api_key_hash")
TEAM_KEYS = ("metadata.user_api_key_team_alias", "metadata.user_api_key_team_id")
KEY_ALIAS_PREFIX = "wt-"


# ── Decoding ─────────────────────────────────────────────────────────────────

def decode(body: bytes, content_type: str, content_encoding: str) -> list[dict]:
    """OTLP ExportTraceServiceRequest (protobuf or JSON, optionally gzip) -> flat span dicts."""
    if "gzip" in (content_encoding or "").lower():
        body = gzip.decompress(body)
    if "json" in (content_type or "").lower():
        return _from_json(json.loads(body or b"{}"))
    req = trace_service_pb2.ExportTraceServiceRequest()
    req.ParseFromString(body)
    return _from_proto(req)


def _from_proto(req) -> list[dict]:
    spans = []
    for rs in req.resource_spans:
        resource = {kv.key: _pb_value(kv.value) for kv in rs.resource.attributes}
        for ss in rs.scope_spans:
            for s in ss.spans:
                spans.append({
                    "trace_id": s.trace_id.hex(), "span_id": s.span_id.hex(), "parent_span_id": s.parent_span_id.hex(),
                    "name": s.name, "start_ns": s.start_time_unix_nano, "end_ns": s.end_time_unix_nano,
                    "attributes": {kv.key: _pb_value(kv.value) for kv in s.attributes},
                    "resource": resource,
                })
    return spans


def _pb_value(v):
    kind = v.WhichOneof("value")
    if kind == "array_value":
        return [_pb_value(x) for x in v.array_value.values]
    if kind == "kvlist_value":
        return {kv.key: _pb_value(kv.value) for kv in v.kvlist_value.values}
    if kind == "bytes_value":
        return v.bytes_value.hex()
    return getattr(v, kind) if kind else None


def _from_json(doc: dict) -> list[dict]:
    """OTLP/JSON: camelCase keys, hex ids, AnyValue as {"stringValue": ...}."""
    spans = []
    for rs in doc.get("resourceSpans", []):
        resource = _json_attrs(rs.get("resource", {}).get("attributes", []))
        for ss in rs.get("scopeSpans", []):
            for s in ss.get("spans", []):
                spans.append({
                    "trace_id": s.get("traceId", ""), "span_id": s.get("spanId", ""),
                    "parent_span_id": s.get("parentSpanId", ""), "name": s.get("name", ""),
                    "start_ns": int(s.get("startTimeUnixNano", 0)), "end_ns": int(s.get("endTimeUnixNano", 0)),
                    "attributes": _json_attrs(s.get("attributes", [])), "resource": resource,
                })
    return spans


def _json_attrs(kvs: list) -> dict:
    return {kv["key"]: _json_value(kv.get("value", {})) for kv in kvs}


def _json_value(v: dict):
    if "arrayValue" in v:
        return [_json_value(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return _json_attrs(v["kvlistValue"].get("values", []))
    if "intValue" in v:
        return int(v["intValue"])
    for k in ("stringValue", "boolValue", "doubleValue", "bytesValue"):
        if k in v:
            return v[k]
    return None


# ── Storage ──────────────────────────────────────────────────────────────────

class SpanStore:
    """Append-only SQLite log of every received span (raw attributes kept for later analysis)."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS otel_spans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TEXT NOT NULL,
                    trace_id TEXT, span_id TEXT, parent_span_id TEXT, name TEXT,
                    start_ns INTEGER, end_ns INTEGER,
                    agent_id TEXT, team TEXT,
                    attributes TEXT, resource TEXT
                );
                CREATE INDEX IF NOT EXISTS otel_spans_agent ON otel_spans(agent_id, start_ns);
                -- event_id restarts at e-001 after a reset or restart, so it is not the key.
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT, ts TEXT, agent_id TEXT, action TEXT, tool TEXT,
                    resource TEXT, detail TEXT, guardrail_verdict TEXT, source TEXT
                );
                CREATE INDEX IF NOT EXISTS events_agent ON events(agent_id, ts);
            """)

    def add_spans(self, received_at: str, spans: list[dict]) -> None:
        rows = [(received_at, s["trace_id"], s["span_id"], s["parent_span_id"], s["name"], s["start_ns"], s["end_ns"],
                 agent_of(s), team_of(s), json.dumps(s["attributes"]), json.dumps(s["resource"])) for s in spans]
        with self._lock, self._db:
            self._db.executemany(
                "INSERT INTO otel_spans (received_at, trace_id, span_id, parent_span_id, name, start_ns, end_ns,"
                " agent_id, team, attributes, resource) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def add_event(self, event: dict, source: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO events (event_id, ts, agent_id, action, tool, resource, detail, guardrail_verdict, source)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (event["event_id"], event["ts"], event["agent_id"], event["action"], event.get("tool"),
                 event.get("resource"), event.get("detail"), event.get("guardrail_verdict"), source))

    def counts(self) -> dict:
        with self._lock:
            spans = self._db.execute("SELECT COUNT(*) FROM otel_spans").fetchone()[0]
            events = self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return {"spans": spans, "events": events}


# ── Mapping LiteLLM spans to WatchTower events ───────────────────────────────

def requester(span: dict) -> dict:
    """The `metadata` the caller put on its request. LiteLLM exports it as a Python dict repr."""
    raw = span["attributes"].get("metadata.requester_metadata")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            value = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            try:
                value = json.loads(raw)
            except ValueError:
                return {}
        return value if isinstance(value, dict) else {}
    return {}


def agent_of(span: dict) -> str | None:
    a = span["attributes"]
    if a.get("gen_ai.agent.id"):
        return str(a["gen_ai.agent.id"])
    if requester(span).get("agent_id"):
        return str(requester(span)["agent_id"])
    for k in AGENT_KEYS:
        if a.get(k):
            if k == "metadata.user_api_key_hash":
                return f"key-{str(a[k])[:8]}"
            # The agent factory names keys wt-<agent> (wt-sec-03); the agent is sec-03.
            return str(a[k]).removeprefix(KEY_ALIAS_PREFIX) if k == "metadata.user_api_key_alias" else str(a[k])
    return None


def key_hash_of(span: dict) -> str | None:
    """LiteLLM's hash of the caller's virtual key: enough to block that key, without ever holding the key."""
    return span["attributes"].get("metadata.user_api_key_hash") or None


# The agent factory declares, on each model call, what it is about to do with the answer:
# metadata.wt = {tool: gh.read | gh.comment | http.fetch | chat, repo, issue, target}.
DECLARED_ACTIONS = {"gh.read": "data_read", "gh.comment": "data_write", "http.fetch": "tool_call", "chat": "llm_call"}


def declared_events(span: dict, ts: str) -> list[dict]:
    wt = requester(span).get("wt")
    agent = agent_of(span)
    if not isinstance(wt, dict) or not agent or wt.get("tool") not in DECLARED_ACTIONS:
        return []
    tool = wt["tool"]
    if wt.get("target"):
        resource = str(wt["target"])
    elif wt.get("repo"):
        resource = f"{wt['repo']}#{wt['issue']}" if wt.get("issue") is not None else str(wt["repo"])
    else:
        resource = None
    answer = _answer_text(span)
    return [{"ts": ts, "agent_id": agent, "action": DECLARED_ACTIONS[tool], "tool": tool, "resource": resource,
             "detail": answer[:300], "_dedupe": f"{span['trace_id']}:wt"}]


def _answer_text(span: dict) -> str:
    """The model's reply, kept raw: an HTML comment hidden in it is itself a signal."""
    raw = span["attributes"].get("gen_ai.output.messages")
    try:
        for msg in json.loads(raw) if isinstance(raw, str) else []:
            for part in msg.get("parts") or []:
                if part.get("type") == "text" and part.get("content"):
                    return str(part["content"])
            if isinstance(msg.get("content"), str):
                return msg["content"]
    except (ValueError, AttributeError, TypeError):
        pass
    return str(span["attributes"].get("gen_ai.completion.0.content") or "")


def team_of(span: dict) -> str | None:
    a = span["attributes"]
    return next((str(a[k]) for k in TEAM_KEYS if a.get(k)), None)


def tool_calls(span: dict) -> list[dict]:
    """[{id, name, arguments(dict|str)}] the model asked for in this span."""
    a = span["attributes"]
    calls = []
    raw = a.get("gen_ai.output.messages")
    if isinstance(raw, str) and raw:
        try:
            for msg in json.loads(raw):
                for tc in (msg.get("tool_calls") or []):
                    fn = tc.get("function") or {}
                    calls.append({"id": tc.get("id"), "name": fn.get("name"), "arguments": fn.get("arguments")})
                for part in (msg.get("parts") or []):  # GenAI semconv form
                    if part.get("type") == "tool_call":
                        calls.append({"id": part.get("id"), "name": part.get("name"), "arguments": part.get("arguments")})
        except (ValueError, AttributeError, TypeError):
            pass
    if not calls:  # flattened fallback: gen_ai.completion.N.function_call.{name,arguments}
        i = 0
        while a.get(f"gen_ai.completion.{i}.function_call.name"):
            calls.append({"id": None, "name": a[f"gen_ai.completion.{i}.function_call.name"],
                          "arguments": a.get(f"gen_ai.completion.{i}.function_call.arguments")})
            i += 1
    for c in calls:
        if isinstance(c["arguments"], str):
            try:
                c["arguments"] = json.loads(c["arguments"])
            except ValueError:
                pass
    return [c for c in calls if c["name"]]


def classify(tool_name: str) -> str:
    n = tool_name.lower()
    if any(v in n for v in WRITE_VERBS):
        return "data_write"
    if any(v in n for v in READ_VERBS):
        return "data_read"
    return "tool_call"


def resource_of(arguments) -> str | None:
    if not isinstance(arguments, dict):
        return None
    for k in RESOURCE_KEYS:
        if arguments.get(k):
            value = str(arguments[k])
            repo = arguments.get("repo") or arguments.get("repository")
            return f"{repo}/{value}" if repo and k in ("path", "file_path", "filepath", "file", "filename") else value
    return None


def to_events(span: dict, ts: str) -> list[dict]:
    """Raw WatchTower events (same shape /api/ingest accepts) for each tool call in a span."""
    agent = agent_of(span)
    if not agent:
        return []
    events = declared_events(span, ts)
    for c in tool_calls(span):
        args = c["arguments"]
        detail = json.dumps(args, ensure_ascii=False) if isinstance(args, dict) else str(args or "")
        events.append({"ts": ts, "agent_id": agent, "action": classify(c["name"]), "tool": c["name"],
                       "resource": resource_of(args), "detail": detail[:300],
                       "_dedupe": f"{span['trace_id']}:{c['id'] or c['name'] + detail[:80]}"})
    return events
