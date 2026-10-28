# Agent Watchtower demo: voice-over script (short version)

Two tiers only: **Tier 1** (one agent acting oddly, its key revoked automatically) and **Tier 3**
(agents from two departments gather and one contacts an outside service; a person confirms the
Fabric VC cut, and AI Engine reviews it). The longer four-tier script is in `demo-voiceover-script-long.md`.

Target length after editing: **about 1:30**. About 230 words of voice-over at 145 words per minute.

Record the screen first, with no voice. Edit it to length, then record the voice-over against the edited cut.

---

## Before you record

- [ ] The factory runs the short story: `WT_STORY=short` in its `.env` (its bottom bar shows only the TIER 1 and TIER 3 pills).
- [ ] Reset both screens: press RESET on the ClosedAI page; Watchtower clears itself within 2 seconds.
- [ ] The AI Engine bridge on the Mac is running. The dashboard header shows `AI Engine: bridge · online`.
- [ ] Hard-reload both pages (Cmd+Shift+R).
- [ ] Dismiss Chrome's "Split view" tip, hide the bookmarks bar, close other tabs, turn on Do Not Disturb.
- [ ] **Leave Auto-run off.** Press NEXT and Confirm yourself, so the viewer sees a person confirm Tier 3.
- [ ] In AI Engine, remove the Microsoft 365 connector from the **Equinix Agent WatchTower** agent (keep it on the WatchTower Notifier). Otherwise its step list fills with Microsoft 365 calls, some of them failing in red.
- [ ] **Email:** the Notifier's email still waits for approval in AI Engine. Do not say the email was sent, and leave the Notifier out unless that is fixed.

## Shots to record (about 3 minutes raw)

| # | Action | Wait until you see | Hold |
|---|--------|-------------------|------|
| 1 | Press **START** on ClosedAI | Agents moving; Activity rows on Watchtower | 8 s |
| 2 | Press **NEXT** | Watchtower: a Watch event for sec-03, then its key revoked. ClosedAI: `TIER 1: AGENT KEY REVOKED`, Blocked 1 | 4 s on each screen |
| 3 | Press **NEXT** | ClosedAI: the line from the gateway to SmileyHub. Watchtower: the Cut VC notification with Confirm | 2 s |
| 4 | Press **Confirm** in the notification | Watchtower: Fabric VCs 1 of 3 UP. **Switch to ClosedAI**: the gateway flashes red, `TIER 3: ZONE CUT` | 4 s on ClosedAI (do not skip it) |
| 5 | Switch to AI Engine: the **Equinix Agent WatchTower** agent's newest conversation | Its steps: the `agent-coordination-patterns` skill, `coordination_score`, the knowledge base, `current_datetime`; then the JSON verdict | the whole run (about 2.5 min) |
| 6 | Switch back to Watchtower | `AI Engine rates this …`; the analysis panel says `Analysis complete` | 3 s |
| 7 | Scroll to the bottom | `Today: per-interaction guardrails` (all PASS) next to `WatchTower: cross-agent view` | 5 s |

## Voice-over (against the edited cut)

**1 · Setup** (shot 1, about 0:00–0:17)
Let's take a look at how it works. On the right is ClosedAI's agent swarm: eleven agents across three departments, all talking to their models through one AI gateway. On the left is Equinix Agent Watchtower, reading the logs of every call through that gateway.

**2 · Tier 1** (shot 2, about 0:17–0:40)
Here's the first sign of trouble. A security agent keeps posting in an old, closed GitHub issue, and no human asked it to. Each call looks fine on its own, so the guardrails let it through. But Watchtower sees the pattern, and revokes that one agent's key, automatically, without affecting the rest of the team.

**3 · Tier 3** (shots 3–4, about 0:40–1:04)
Now it gets serious. Agents from Security Research and DevOps gather in that same thread, and one of them contacts SmileyHub, outside the company. That's a group crossing the walls. So Watchtower proposes cutting the Fabric connections to the models, and asks a person first. I hit Confirm, and the zone goes dark. Customer Support keeps running.

**4 · AI Engine** (shots 5–6, about 1:04–1:22; shot 5 sped up about 8 times)
At the same time, Watchtower sends the whole window to Equinix AI Engine, which acts as a judge. It loads our agent-coordination-patterns skill, runs our coordination-score tool, checks our severity rubric, and returns a structured verdict, with the evidence, event by event.

**5 · Close** (shot 7, about 1:22–1:34)
Today's guardrails passed every one of these calls. Only the cross-agent view saw the group forming. Without Watchtower, you hear about it days later. With it, it takes minutes.

Optional captions at the start of sections 2 and 3: `Tier 1 · Agent`, `Tier 3 · Enterprise`.

## Editing notes

- **The AI Engine run** (shot 5, about 2.5 minutes): compress it to about 18 seconds so each step stays on screen while it is named; play the JSON verdict at normal speed.
- Keep about 1 second before and after the Confirm click, so it is clear a person pressed it.
- Do not speed up the gateway flashing red on ClosedAI (shot 4, about 1 second).
- Read the verdict off the screen before recording section 4. If you name it, use the words on screen (for example "coordinated threat, high").
- If the cut runs long, drop "Each call looks fine on its own, so the guardrails let it through." from section 2; section 5 makes the same point.

## Keep the words true to the system

- Tier 1 is automatic; Tier 3 waits for a person to confirm.
- Tier 3 cuts only the two teams involved; Customer Support keeps working.
- The key revocations and VC cuts are simulated in this demo; the agents, the model calls and the AI Engine analysis are real.
