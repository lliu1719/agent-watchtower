"""Agent factory page: brand it as the customer's agent fleet, not as WatchTower.

In the demo story this page is ClosedAI's own agent swarm, and Equinix Agent WatchTower is the separate
product that watches it. The top-left title and the browser tab now say so.

Run on the factory host (backs up each file first; writes nothing unless every edit matches):
    sudo python3 agent-factory-title-patch.py \
        /home/fred/fred-hackathon/frontend/hackathon-app/index.html \
        /home/fred/fred-litellm-gateway/frontend/hackathon-app/index.html
Reload the page. No restart is needed.
"""

import shutil
import sys
import time

EDITS = [
    ("<title>Watchtower for AI Agents</title>", "<title>ClosedAI Agent Swarm</title>"),
    ('  <div class="name">WATCHTOWER</div>\n  <div class="sub">AI AGENT KILL SWITCH</div>',
     '  <div class="name">CLOSEDAI</div>\n  <div class="sub">AGENT SWARM · SIMULATED</div>'),
]


def patch(path: str) -> None:
    src = open(path, encoding="utf8").read()
    if "<title>ClosedAI Agent Swarm</title>" in src:
        print(f"{path}: already patched")
        return
    out = src
    for old, new in EDITS:
        if out.count(old) != 1:
            raise SystemExit(f"{path}: expected one match for:\n{old}\nNothing was written.")
        out = out.replace(old, new, 1)
    backup = f"{path}.bak-watchtower-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf8") as f:
        f.write(out)
    print(f"{path}: patched (backup {backup})")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        patch(p)
