# Agent Watchtower demo: voice-over script

Target length after editing: **about 2:10**. About 320 words of spoken voice-over at 140 to 150 words per minute.
Screen: Agent Watchtower dashboard on the left, ClosedAI Agent Swarm on the right.

Record the screen first, with no voice. Edit it to length, then record the voice-over against the edited cut, so each line can match its shot.

---

## Before you record

- [ ] Reset both screens: press RESET on the ClosedAI page; Watchtower clears itself within 2 seconds.
- [ ] The AI Engine bridge on the Mac is running. The dashboard header shows `AI Engine: bridge · online`.
- [ ] Hard-reload both pages (Cmd+Shift+R) to get the new Watchtower logo and the SmileyHub box.
- [ ] Dismiss Chrome's "Split view" tip, hide the bookmarks bar, close other tabs, turn on Do Not Disturb.
- [ ] **Leave Auto-run off.** Press NEXT and Confirm yourself, so the viewer sees a person confirm Tier 2 and Tier 3. With Auto-run on, Watchtower confirms by itself after 8 seconds, which is meant for unattended runs.
- [ ] **Email:** AI Engine currently holds the email at "awaiting your approval", so it is not sent on its own. Before recording, set the WatchTower Notifier agent's Microsoft 365 send action so that it needs no approval. If that is not possible, skip section 7 and shot 8c.
- [ ] Keep Watchtower scrolled to the top. Use the Confirm button in the notification on the right so the page does not jump.

## Shots to record (about 4 minutes raw)

| # | Action | Wait until you see | Hold |
|---|--------|-------------------|------|
| 1 | Press **START** on ClosedAI | Agents moving; Activity rows on Watchtower | 8 s |
| 2 | Press **NEXT** | Yellow Watch event on the left; `TIER 0: WATCH ONLY` on the right | 4 s |
| 3 | Press **NEXT** | Red banner; `TIER 1: AGENT KEY REVOKED` on the right | 4 s |
| 4 | Press **NEXT** | The Confirm button (Revoke every wt-sec key) | 2 s, then press **Confirm** |
| 5 | Wait | `TIER 2: DEPARTMENT BLOCKED`; Security Research turns red | 4 s |
| 6 | Press **NEXT** (**do not press End incident before this**) | dev-02 reaches SmileyHub; the Cut VC Confirm appears | 2 s, then press **Confirm** |
| 7 | Wait | The gateway flashes red; `TIER 3: ZONE CUT` | 4 s |
| 8a | While AI Engine works, switch to the AI Engine tab: the **Equinix Agent WatchTower** agent's newest conversation | Its steps appear one by one: loading the `agent-coordination-patterns` skill, `coordination_score`, searching the knowledge base, `current_datetime` | the whole run (about 2.5 min) |
| 8b | Scroll to the end of that conversation | The JSON verdict: `SUSPICIOUS`, involved agents, evidence by event | 5 s |
| 8c | Optional, only if the email no longer waits for approval: open the **WatchTower Notifier** conversation | The email it sent to the reviewers | 3 s |
| 8d | Switch back to Watchtower | `AI Engine rates this suspicious (medium)`; the analysis panel says `Analysis complete` | 3 s |
| 9 | Open the AI Engine analysis and scroll to the bottom | `Today: per-interaction guardrails` (all PASS) next to `WatchTower: cross-agent view` | 5 s |
| 10 | Scroll back to the top and press **End incident: restore access** | Both screens back to normal | 4 s |

## Voice-over (against the edited cut)

Spoken, first person: the presenter is the one pressing Confirm. About 320 words, so the cut runs about 2:10 at 150 words per minute.

**1 · Setup** (shot 1)
Let's take a look at how it works. On the right is ClosedAI's agent swarm: eleven agents across three departments, all talking to their models through one AI gateway. On the left is Equinix Agent Watchtower, reading the logs of every call that goes through that gateway.

**2 · Tier 0** (shot 2)
Here's the first sign of trouble. A security agent starts posting in an old, closed GitHub issue, and no human asked it to. Each call looks fine on its own, so the guardrails let it through. Watchtower flags it because the pattern is unusual, but it doesn't block anything yet.

**3 · Tier 1** (shot 3)
Then it does it again, and leaves a message for the others. Now Watchtower revokes that one agent's key, automatically and in real time, without affecting the rest of the team.

**4 · Tier 2** (shots 4–5)
But it doesn't stop there. Other security agents pick up the thread and start working together. That's not a single agent anymore; that's a group. Blocking a whole department is a big call, so Watchtower asks a person to confirm before it acts. I hit Confirm, and the department is blocked.

**5 · Tier 3** (shots 6–7)
Now it gets even more serious. DevOps joins in, and one of its agents tries to break into SmileyHub. Its key is revoked right away, and Watchtower proposes cutting the Fabric connections to the models. I confirm, and the zone goes dark. Customer Support keeps running.

**6 · AI Engine** (shots 8a–8b, 8a sped up about 7 times)
Meanwhile, Watchtower hands the whole window to Equinix AI Engine, which acts as a judge. You can see it working: it loads our agent-coordination-patterns skill, runs our custom coordination-score tool, and checks our severity rubric in its knowledge base. It comes back with a structured verdict: suspicious, which agents were involved, and the evidence, event by event.

**7 · Notifier** (shot 8c, only if the email no longer waits for approval)
A second AI Engine agent, the Watchtower Notifier, uses the Microsoft 365 connector to email the reviewers whenever a person has to confirm.

**8 · Back on the dashboard** (shots 8d–9)
Back on the dashboard, the verdict sits right next to what Watchtower already did. And this is the part that matters: today's guardrails passed every one of these calls. Only the cross-agent view saw the group forming.

**9 · Close** (shot 10)
Once a reviewer is satisfied, they end the incident, and access comes back. Without Watchtower, you'd hear about it days later, from someone else. With it, it takes minutes.

Optional captions at the start of each section: `Tier 0 · Watch`, `Tier 1 · Agent`, `Tier 2 · Department`, `Tier 3 · Enterprise`.

## Editing notes

- **The AI Engine run** (shot 8a, about 2.5 minutes): compress it to about 20 seconds, so each step (skill, tool, knowledge base) stays on screen while it is named in section 6. Slow down to normal speed for the verdict (8b).
- The first seconds of shot 1, while the agents start, can run at 2 times speed.
- Keep about 1 second before and after each Confirm click, so it is clear a person pressed it.
- Do not speed up the gateway flashing red in shot 7 (about 1 second). It is the most visual moment of the demo.
- If the cut runs long, drop section 7 (the Notifier), then "Each call looks fine on its own, so the guardrails let it through." from section 2, since section 8 makes the same point. Together that saves about 12 seconds.
- If it runs short, add after line 5: "The key revocations and Fabric cuts in this demo are simulated; the agents and model calls are live." (18 words)

## Keep the words true to the system

- Tier 1 is automatic; Tier 2 and Tier 3 wait for a person to confirm. Do not say "Watchtower blocks the department" without the person.
- Tier 3 cuts only the two teams involved; Customer Support keeps working. Not "every model path".
- The key revocations and VC cuts are simulated in this demo; the agents, the model calls and the AI Engine analysis are real.
