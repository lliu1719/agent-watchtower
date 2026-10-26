"""Agent factory page: keep the gateway and model labels inside their boxes on the diagram.

Model names such as "Zone A: Gemini 2.5 Flash-Lite" are wider than their 200-unit box. They now break
after the colon onto two lines (the model name a little smaller), and any line still too wide is
condensed to fit. The gateway name is set a size smaller. Only CSS and a small script that adjusts the
labels after the page draws them; the page's own logic is untouched.

Run on the factory host (backs up each file first; writes nothing unless the anchors match):
    sudo python3 agent-factory-label-fit-patch.py \
        /home/fred/fred-hackathon/frontend/hackathon-app/index.html \
        /home/fred/fred-litellm-gateway/frontend/hackathon-app/index.html
Reload the page. No restart is needed.
"""

import shutil
import sys
import time

MARK = "wt-label-fit"

CSS = f"""
<style id="{MARK}">
  #svg text.gwn {{ font-size: 13px; letter-spacing: .02em; }}
  #svg text.cname {{ letter-spacing: 0; }}
  #svg text.cname tspan.model {{ font-size: 11.5px; font-weight: 400; }}
</style>
"""

JS = f"""
<script id="{MARK}-js">
  // Fit the diagram's labels to their boxes (WatchTower). The page redraws the gateways from each snapshot,
  // so this runs whenever new labels appear.
  (() => {{
    const svg = document.getElementById('svg');
    if (!svg) return;
    const NS = 'http://www.w3.org/2000/svg';
    const squeeze = (el, max) => {{
      el.removeAttribute('textLength');
      if (el.getComputedTextLength() > max) {{ el.setAttribute('textLength', max); el.setAttribute('lengthAdjust', 'spacingAndGlyphs'); }}
    }};
    const fit = () => {{
      svg.querySelectorAll('text.cname').forEach(t => {{
        if (!t.dataset.fit) {{
          const full = t.textContent, i = full.indexOf(': ');
          const y = parseFloat(t.getAttribute('y'));
          if (i > 0) {{
            t.textContent = '';
            const head = document.createElementNS(NS, 'tspan');
            head.setAttribute('x', t.getAttribute('x')); head.setAttribute('y', y - 7); head.textContent = full.slice(0, i);
            const model = document.createElementNS(NS, 'tspan');
            model.setAttribute('class', 'model'); model.setAttribute('x', t.getAttribute('x')); model.setAttribute('y', y + 9);
            model.textContent = full.slice(i + 2);
            t.append(head, model);
          }}
          t.dataset.fit = '1';
        }}
        t.querySelectorAll('tspan').forEach(s => squeeze(s, 148));
        if (!t.querySelector('tspan')) squeeze(t, 148);
      }});
      svg.querySelectorAll('text.gwn').forEach(t => squeeze(t, 128));
    }};
    let queued = false;
    new MutationObserver(() => {{ if (!queued) {{ queued = true; requestAnimationFrame(() => {{ queued = false; fit(); }}); }} }})
      .observe(svg, {{ childList: true, subtree: true }});
    fit();
  }})();
</script>
"""


def patch(path: str) -> None:
    src = open(path, encoding="utf8").read()
    if MARK in src:
        print(f"{path}: already patched")
        return
    if src.count("</head>") != 1 or src.count("</body>") != 1 or 'id="svg"' not in src or "'cname'" not in src:
        raise SystemExit(f"{path}: the page is not the one this patch expects. Nothing was written.")
    out = src.replace("</head>", CSS + "</head>", 1).replace("</body>", JS + "</body>", 1)
    backup = f"{path}.bak-watchtower-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf8") as f:
        f.write(out)
    print(f"{path}: patched (backup {backup})")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        patch(p)
