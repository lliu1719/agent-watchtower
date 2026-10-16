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
