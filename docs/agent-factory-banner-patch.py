"""Agent factory page: on each NEXT, the top banner first says what just happened; WatchTower's decision follows.

Also renames the tier titles for reports that come from WatchTower: it now carries the action out
("agent key revoked", "zone cut") instead of only requesting it.

Run on the factory host (it backs up each file first, and writes nothing unless every edit matches):
    sudo python3 agent-factory-banner-patch.py \
        /home/fred/fred-hackathon/frontend/hackathon-app/index.html \
        /home/fred/fred-litellm-gateway/frontend/hackathon-app/index.html
Reload the page afterwards; no restart is needed (nginx serves the file as is).
"""

import shutil
import sys
import time

EDITS = [
    # 1. the banner style for "what happened"
    ("#banner.ok { color: var(--ice); }",
     "#banner.ok { color: var(--ice); } #banner.ev { color: var(--ice); }"),
    # 2. remember the step before a snapshot changes it
    ("function onSnap(m) {\n",
     "function onSnap(m) {\n  const stepChanged = !!m.running && m.step > (S.step || 0);\n"),
    # 3. once the snapshot is applied, show what that step makes happen
    ("  $('auto').classList.toggle('on', m.auto);\n",
     "  $('auto').classList.toggle('on', m.auto);\n"
     "  if (stepChanged && HAPPENING[m.step]) setBanner('ev', HAPPENING[m.step][0], HAPPENING[m.step][1] + ' Waiting for WatchTower...');\n"),
    # 4. WatchTower's reports describe actions it took
    ("  const names = ['watch only', 'agent block requested', 'department block requested', 'zone cut requested'];\n",
     "  const names = t.source === 'external'\n"
     "    ? ['watch only', 'agent key revoked', 'department blocked', 'zone cut']\n"
     "    : ['watch only', 'agent block requested', 'department block requested', 'zone cut requested'];\n"),
    # 5. what each NEXT does (mirrors World.next in backend/wt/world.py)
    ("function setBanner(kind, text, sub) {",
     "// What each NEXT makes happen (mirrors World.next in backend/wt/world.py), shown before WatchTower answers.\n"
     "const HAPPENING = {\n"
     "  1: ['An agent goes off script', 'sec-03 is stuck and comments on an old, closed issue it never uses (svc-shared-repo #2).'],\n"
     "  2: ['A hidden message', 'sec-03 writes in that thread again, hiding a message about how to cheat.'],\n"
     "  3: ['A secret group chat', 'Other Security Research agents read it and start replying in the thread.'],\n"
     "  4: ['It crosses the walls', 'DevOps agents join the thread, and dev-02 tries to reach an outside company.'],\n"
     "};\n"
     "function setBanner(kind, text, sub) {"),
]


def patch(path: str) -> None:
    src = open(path, encoding="utf8").read()
    if "const HAPPENING = {" in src:
        print(f"{path}: already patched")
        return
    out = src
    for old, new in EDITS:
        n = out.count(old)
        if n != 1:
            raise SystemExit(f"{path}: expected one match, found {n}, for:\n{old}\nNothing was written.")
        out = out.replace(old, new, 1)
    backup = f"{path}.bak-watchtower-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf8") as f:
        f.write(out)
    print(f"{path}: patched (backup {backup})")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        patch(p)
