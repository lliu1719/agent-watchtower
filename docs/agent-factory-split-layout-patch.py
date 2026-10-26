"""Agent factory page: a layout for recording side by side with WatchTower.

The big diagram takes the middle, the event banner sits on top (it stays, dimmed, until the next one),
and the story controls become one bar along the bottom. The side panels that repeat what WatchTower
shows (story steps, departments, decisions, log, report, gateways) are hidden. Only CSS and DOM moves:
the page's own logic is untouched.

Run on the factory host (it backs up each file first, and writes nothing unless the anchors match):
    sudo python3 agent-factory-split-layout-patch.py \
        /home/fred/fred-hackathon/frontend/hackathon-app/index.html \
        /home/fred/fred-litellm-gateway/frontend/hackathon-app/index.html
Reload the page; add ?classic to the URL to see the original layout. No restart is needed.
"""

import shutil
import sys
import time

MARK = "wt-split-layout"

CSS = f"""
<style id="{MARK}">
  /* Split-screen recording layout (WatchTower). Remove this block and the script below to undo. */
  html:not(.classic) #left,
  html:not(.classic) #linkp, html:not(.classic) #tlp, html:not(.classic) #report, html:not(.classic) #log {{ display: none !important; }}
  html:not(.classic) #brand {{ top: 14px; left: 16px; }}
  html:not(.classic) #right {{ top: 14px; right: 16px; width: auto; max-height: none; }}
  html:not(.classic) #right .kpis {{ margin: 0; padding: 8px 12px; gap: 18px; }}
  html:not(.classic) #banner {{
    top: 14px; left: 50%; transform: translateX(-50%); width: calc(100% - 640px); min-width: 300px; max-width: none;
    white-space: normal; font-size: 22px; letter-spacing: .14em; line-height: 1.25; opacity: .5;
  }}
  html:not(.classic) #banner.show {{ opacity: 1; }}
  html:not(.classic) #banner small {{ font-size: 14px; line-height: 1.4; letter-spacing: .02em; margin-top: 8px; }}
  html:not(.classic) #map {{ left: 16px; right: 16px; top: 130px; bottom: 104px; }}
  html:not(.classic) #bottom {{
    left: 16px; right: 16px; bottom: 12px; width: auto; min-width: 0; transform: none;
    display: flex; align-items: center; gap: 20px; text-align: left; padding: 12px 16px;
  }}
  html:not(.classic) #bottom .btns {{ display: flex; gap: 8px; flex: none; margin: 0; }}
  html:not(.classic) #bottom .btns .b {{ width: auto; padding: 8px 14px; }}
  html:not(.classic) #bottom #auto {{ flex: none; margin: 0; white-space: nowrap; }}
  html:not(.classic) #bottom .storytext {{ flex: 1; min-width: 0; }}
  html:not(.classic) #bottom #narr {{ min-height: 0; font-size: 15px; }}
  html:not(.classic) #bottom #tiers {{ flex: none; margin: 0; }}
  @media (max-width: 1100px) {{
    html:not(.classic) #banner {{ top: 92px; width: calc(100% - 32px); font-size: 18px; }}
    html:not(.classic) #map {{ top: 190px; bottom: 150px; }}
    html:not(.classic) #bottom {{ flex-wrap: wrap; gap: 10px 16px; }}
    html:not(.classic) #bottom .storytext {{ flex-basis: 100%; order: 3; }}
  }}
</style>
"""

JS = f"""
<script id="{MARK}-js">
  // Split-screen recording layout (WatchTower): move the story controls into the bottom bar.
  (() => {{
    if (new URLSearchParams(location.search).has('classic')) {{ document.documentElement.classList.add('classic'); return; }}
    const bottom = document.getElementById('bottom');
    const text = document.createElement('div');
    text.className = 'storytext';
    text.append(document.getElementById('stepname'), document.getElementById('narr'));
    bottom.prepend(document.querySelector('#left .btns'), document.getElementById('auto'), text);
  }})();
</script>
"""


def patch(path: str) -> None:
    src = open(path, encoding="utf8").read()
    if MARK in src:
        print(f"{path}: already patched")
        return
    if src.count("</head>") != 1 or src.count("</body>") != 1:
        raise SystemExit(f"{path}: expected one </head> and one </body>. Nothing was written.")
    for anchor in ('id="left"', 'class="btns"', 'id="auto"', 'id="bottom"', 'id="stepname"', 'id="narr"', 'id="right"'):
        if anchor not in src:
            raise SystemExit(f"{path}: {anchor} not found; the page changed. Nothing was written.")
    out = src.replace("</head>", CSS + "</head>", 1).replace("</body>", JS + "</body>", 1)
    backup = f"{path}.bak-watchtower-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf8") as f:
        f.write(out)
    print(f"{path}: patched (backup {backup})")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        patch(p)
