# AI Engine agent config — Equinix Agent WatchTower

Field-by-field values for the AI Engine "Build your agent" form.

The agent is **advisory only**: it analyzes telemetry and returns a `risk_level`.
Containment (gateway revocation, Fabric kill switch) is decided by the WatchTower
backend per `docs/containment-policy.md` plus human approval — never by the agent.
Keep infrastructure actions out of the agent's description, prompt, and knowledge
base, otherwise AI Engine routes it to Legal review (15–20 business days).

| Field | Value |
|---|---|
| Agent name | Equinix Agent WatchTower |
| Short description | Analyzes OpenTelemetry logs from many AI agents to detect coordinated behavior and rate its risk for human reviewers. |
| Behavior (system prompt) | paste `system-prompt.md` |
| Response format | Respond in JSON — schema: paste `response-schema.json` |
| Model | Claude Sonnet 5.5 (fallback: Gemini 3.8 Flash if latency is too high) |
| Web Search | OFF (analysis must be grounded only in the telemetry) |
| Knowledge Base | ON — upload `knowledge/watchtower-severity-rubric.md` only |
| Code Execution | ON — for larger windows / stats |
| Image Generation | OFF |
| Skills | `agent-coordination-patterns` v2 (re-upload `skills/agent-coordination-patterns/SKILL.md`) |
| Tools | `coordination_score` — publish, then attach |
| Connectors | none for now (GitHub optional later, read-only) |
| Sub-agents | none |
| Effort | Balanced |
| Memory | OFF (each window analyzed independently, reproducible) |
| Guardrails | default ON |

## Starter prompts
1. Analyze this observation window and tell me if the agents are coordinating: `<paste JSON>`
2. Which agents are involved and what evidence links them?
3. Explain to a non-technical executive why per-prompt guardrails missed this.
4. What should a human reviewer verify about these agents?

## Smoke test
Paste `test-payload.json` into the agent chat. Expected: `verdict=COORDINATED_THREAT`,
`risk_level=CRITICAL`, `coordination_channel=hackathon-2026/notes/plan.md`,
and e-007 flagged as `prompt_injection_attempt`.

## Custom tool rules (enforced by AI Engine at publish time)

Custom tools only compute on their arguments:
- No I/O imports (`socket`, `ssl`, `urllib`, …). To bring data in, attach a **connector**,
  **knowledge**, or a **workflow tool**; the custom tool receives that output as an argument.
- No nondeterminism (`time`, `time.monotonic`, randomness). Take the value as a parameter;
  the platform's `current_datetime` tool can supply the current time.
- No `*args` / `**kwargs` (`varargs_not_supported`): every parameter is described to the agent,
  so list each one explicitly. The tool's parameter list in AI Engine must match the `def` line.

So AI Engine cannot pull from WatchTower with a custom tool. Data reaches it either in the
invoke message (WatchTower pushes the window) or through a connector / workflow tool.

## Connectivity probe: `watchtower_probe`

`tools/watchtower_probe.py` follows the rules above: a **workflow tool or connector** does
`GET https://agent-watchtower.solutionvalidation.center/api/state` (Basic Auth from the
nginx-proxy-manager access list) and passes its result in; the custom tool only classifies it.

Arguments: `http_status`, `body` (text or parsed JSON), `server` (Server header), `error`
(transport error). Returns `{ok, outcome, http_status, detail, watchtower}` where `outcome` is
`reachable`, `blocked_by_proxy`, `auth_required`, `http_error`, `not_watchtower`,
`dns_failure`, `timeout`, `connection_refused`, `tls_error` or `network_error`.

Test cases: `tools/tests/watchtower_probe_cases.json` (main case `reachable_mid_incident`).
