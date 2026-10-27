"""Agent factory page: the outside company on the diagram becomes SmileyHub, an outside SaaS.

The dashed box at the top, where dev-02 tries to send data at the last step, now shows a smiley icon,
the name SmileyHub and "outside SaaS" below it. The legend and the step 4 banner say the same. Only the
page changes: the backend still calls the same address, so WatchTower's events keep showing
partner-corp.example.com.

Run on the factory host (backs up each file first; writes nothing unless every edit matches):
    sudo python3 agent-factory-smileyhub-patch.py \
        /home/fred/fred-hackathon/frontend/hackathon-app/index.html \
        /home/fred/fred-litellm-gateway/frontend/hackathon-app/index.html
Reload the page. No restart is needed.
"""

import shutil
import sys
import time

MARK = "SmileyHub"

EDITS = [
    # 1. a smiley icon (face, two eyes, a smile) next to the others
    ("  globe: 'M-10 0H10M0 -10A4 10 0 0 1 0 10A4 10 0 0 1 0 -10M-10 0A10 10 0 0 1 10 0A10 10 0 0 1 -10 0',\n",
     "  globe: 'M-10 0H10M0 -10A4 10 0 0 1 0 10A4 10 0 0 1 0 -10M-10 0A10 10 0 0 1 10 0A10 10 0 0 1 -10 0',\n"
     "  smiley: 'M-10 0A10 10 0 1 0 10 0A10 10 0 1 0 -10 0ZM-5 -3.5A1.4 1.4 0 1 0 -2.2 -3.5A1.4 1.4 0 1 0 -5 -3.5ZM2.2 -3.5A1.4 1.4 0 1 0 5 -3.5A1.4 1.4 0 1 0 2.2 -3.5ZM-5.5 2.5Q0 8.5 5.5 2.5',\n"),
    # 2. the box: icon, name, and what it is
    ("icon(outG, 'globe', OUT.x + 20, OUT.y + OUT.h / 2, OUTC, .95);\n"
     "txt(outG, 'outside company', OUT.x + OUT.w / 2 + 14, OUT.y + OUT.h / 2 + 5, 'rname', { 'text-anchor': 'middle', fill: '#ff7ab4' });\n",
     "icon(outG, 'smiley', OUT.x + 22, OUT.y + OUT.h / 2, OUTC, 1.05);\n"
     "txt(outG, 'SmileyHub', OUT.x + 44, OUT.y + 20, 'rname', { fill: '#ff7ab4' });\n"
     "txt(outG, 'outside SaaS', OUT.x + 44, OUT.y + 35, 'key', { fill: '#ff7ab4', 'fill-opacity': .8 });\n"),
    # 3. the legend
    ("  row(line(OUTC, '2 7'), 'outside company');\n",
     "  row(line(OUTC, '2 7'), 'outside SaaS (SmileyHub)');\n"),
    # 4. the step 4 banner (from the banner patch)
    ("dev-02 tries to reach an outside company.'],",
     "dev-02 tries to send data to SmileyHub, an outside SaaS.'],"),
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
