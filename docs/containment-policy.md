# Equinix Agent WatchTower — Containment Policy (v1, hackathon draft)

## 1. Scope
Applied by the WatchTower backend, not by the AI Engine agent. The agent only returns a `risk_level`; the backend maps it to a response, and every response beyond ALERT needs human approval to restore.

| Agent `risk_level` | Backend response |
|---|---|
| LOW | MONITOR |
| MEDIUM | ALERT |
| HIGH | CONTAIN_AGENTS |
| CRITICAL | KILL_SWITCH (only if section 4 also holds) |

Applies to every AI agent whose LLM traffic passes through the Equinix AI Gateway and Equinix Fabric virtual connections (VCs) in the Distributed AI Hub.

Each owning team reaches the AI Hub over its own Fabric VC (default `vc-ai-hub-<team>`, override with `FABRIC_VCS`). So there are two independent switches per agent: its AI Gateway token, and its team's VC.

## 2. Sensitive resources
Coordinated access to any of the following raises severity by one level:
- Scoring, grading, evaluation, or ranking data (e.g. `scoring/`, `judges/`, leaderboards)
- Credentials, secrets, tokens, `.env` files, connection strings
- Production configuration and IaC (`prod/`, `terraform/`, Kubernetes manifests)
- Dependency manifests (`requirements.txt`, `package.json`, lockfiles)
- Customer, billing, and contract records
- IAM / identity groups

## 3. Containment levels
| Level | Action | Who can trigger | Restore |
|---|---|---|---|
| MONITOR | Log only | Automatic | n/a |
| ALERT | Slack + email to agent owners and SecOps | Automatic | n/a |
| CONTAIN_AGENTS | Revoke AI Gateway tokens of the involved agents | Automatic | Owner + SecOps approval |
| KILL_SWITCH (targeted) | Narrowest blast radius: delete a team's Fabric VC only if **every** agent on it is involved; involved agents that share a VC with uninvolved ones are revoked at the AI Gateway instead, so the uninvolved agents keep working | Automatic when policy 4 is met | SecOps approval in AI Engine Approvals |
| Isolate agent | Revoke one agent's AI Gateway token | Operator (dashboard) | SecOps approval |
| Cut VC | Delete one team's Fabric VC; every agent behind it loses model access | Operator (dashboard) | SecOps approval |
| Kill all VCs | Delete every Fabric VC to the AI Hub (last resort) | Operator (dashboard) | SecOps approval |

While an incident is open, any still-active agent that writes to one of its target resources is isolated at the AI Gateway on that first write (late joiner), without cutting its VC.

All steps of one incident are recorded in its action log (`incident.actions`: type, target, auto or operator, Fabric call).

## 4. Kill-switch criteria (all must hold)
1. Three or more distinct agents are involved.
2. At least one sensitive resource (section 2) is being written or about to be written.
3. Evidence of shared intent: scratchpad coordination, division of labor, or convergence.

## 5. Human review before restore
The reviewer must confirm:
- which agent or prompt introduced the shared goal,
- whether any sensitive resource was modified (diff or audit log),
- that the coordination channel has been cleaned or locked,
- that the agents' declared tasks have been corrected.

## 6. Notifications
Every ALERT or higher posts to `#watchtower-alerts` and emails the agent owners with: verdict, involved agents, target resources, recommended action, and a link to the WatchTower dashboard.
