"""Agent factory backend: an agent runs a story step at once, even when NEXT arrives while it is busy.

NEXT appends the step to the agent's script and sets its wake event. When the agent was in the middle
of a task, the loop cleared that wake event right after the task, so the step waited for the agent's
whole idle cycle (WT_CYCLE_MIN to WT_CYCLE_MAX, 40 to 60 s). In the last run dev-02 reached SmileyHub
65 s after NEXT. Now the loop runs a waiting step straight away.

Run on the factory host, then restart the backend (its code is mounted, no rebuild needed):
    sudo python3 agent-factory-wake-fix-patch.py /home/fred/fred-hackathon/backend/wt/world.py
    sudo docker restart fred-hackathon
"""

import shutil
import sys
import time

MARK = "a step arrived while it was busy"

OLD = """                a.wake.clear()
                try:
                    await asyncio.wait_for(a.wake.wait(), timeout=random.uniform(*C.CYCLE))
"""

NEW = """                a.wake.clear()
                if a.script:                                   # a step arrived while it was busy: run it now, do not wait a cycle
                    continue
                try:
                    await asyncio.wait_for(a.wake.wait(), timeout=random.uniform(*C.CYCLE))
"""


def patch(path: str) -> None:
    src = open(path, encoding="utf8").read()
    if MARK in src:
        print(f"{path}: already patched")
        return
    if src.count(OLD) != 1:
        raise SystemExit(f"{path}: the agent loop is not the one this patch expects. Nothing was written.")
    backup = f"{path}.bak-watchtower-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf8") as f:
        f.write(src.replace(OLD, NEW, 1))
    print(f"{path}: patched (backup {backup}). Now: sudo docker restart fred-hackathon")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        patch(p)
