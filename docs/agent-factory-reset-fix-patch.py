"""Agent factory page: after Reset the top banner is empty again.

The split-screen layout keeps the last banner on screen, dimmed, until the next one. Reset only hid it,
so "TIER 3: ZONE CUT" stayed there over a page on standby. Now Reset, and any snapshot of a story that
is not running, clear its text. A snapshot without the "seen" counters no longer stops the rest of the
page from updating either.

Run on the factory host (backs up each file first; writes nothing unless every edit matches):
    sudo python3 agent-factory-reset-fix-patch.py \
        /home/fred/fred-hackathon/frontend/hackathon-app/index.html \
        /home/fred/fred-litellm-gateway/frontend/hackathon-app/index.html
Reload the page. No restart is needed.
"""

import shutil
import sys
import time

MARK = "clearBanner()"

EDITS = [
    # 1. one place that empties the banner (hiding it is not enough with the dimmed layout)
    ("function setBanner(kind, text, sub) {",
     "function clearBanner() { setBanner(null); $('bannerText').textContent = ''; $('bannerSub').textContent = ''; }\n"
     "function setBanner(kind, text, sub) {"),
    # 2. Reset
    ("$('report').classList.remove('show'); setBanner(null);",
     "$('report').classList.remove('show'); clearBanner();"),
    # 3. a story on standby shows no decision
    ("if (!m.running) { st.textContent = 'STANDBY'; st.className = ''; }",
     "if (!m.running) { st.textContent = 'STANDBY'; st.className = ''; clearBanner(); }"),
    # 4. m.seen may be missing; S.seen already defaults it
    ("${m.seen.logs || 0} logs / ${m.seen.github || 0} GitHub",
     "${S.seen.logs || 0} logs / ${S.seen.github || 0} GitHub"),
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
