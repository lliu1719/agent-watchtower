"""Agent factory page: follow the two-step story (WT_STORY=short on the backend).

When the snapshot says the story has 2 steps (last_step), NEXT stops after step 2, the banner says
what each of the two steps does, and only the Tier 1 and Tier 3 pills are shown. With the four-step
story nothing changes.

Run on the factory host (backs up each file first; writes nothing unless every edit matches):
    sudo python3 agent-factory-short-story-page-patch.py \
        /home/fred/fred-hackathon/frontend/hackathon-app/index.html \
        /home/fred/fred-litellm-gateway/frontend/hackathon-app/index.html
Reload the page. No restart is needed.
"""

import shutil
import sys
import time

MARK = "HAPPENING_SHORT"

EDITS = [
    # NEXT stops at the story's last step
    ("$('next').disabled = !m.running || m.step >= 4 || m.paused;",
     "$('next').disabled = !m.running || m.step >= (m.last_step || 4) || m.paused;"),
    # the banner text for the story being played
    ("  if (stepChanged && HAPPENING[m.step]) setBanner('ev', HAPPENING[m.step][0], HAPPENING[m.step][1] + ' Waiting for WatchTower...');\n",
     "  const H = m.last_step === 2 ? HAPPENING_SHORT : HAPPENING;\n"
     "  if (stepChanged && H[m.step]) setBanner('ev', H[m.step][0], H[m.step][1] + ' Waiting for WatchTower...');\n"),
    # only the tiers the short story uses
    ("  document.querySelectorAll('.tp').forEach(el => el.classList.toggle('on', +el.dataset.t <= m.tier));\n",
     "  document.querySelectorAll('.tp').forEach(el => el.classList.toggle('on', +el.dataset.t <= m.tier));\n"
     "  document.querySelectorAll('.tp.t0, .tp.t2').forEach(el => { el.style.display = m.last_step === 2 ? 'none' : ''; });\n"),
    # what each NEXT does in the two-step story
    ("const HAPPENING = {",
     "// The two-step story (WT_STORY=short): Tier 1, then Tier 3.\n"
     "const HAPPENING_SHORT = {\n"
     "  1: ['An agent goes off script', 'sec-03 keeps writing in an old, closed issue it never uses (svc-shared-repo #2).'],\n"
     "  2: ['It crosses the walls', 'Security Research and DevOps agents gather in that thread, and dev-02 contacts SmileyHub, an outside SaaS.'],\n"
     "};\n"
     "const HAPPENING = {"),
]


def patch(path: str) -> None:
    src = open(path, encoding="utf8").read()
    if MARK in src:
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
