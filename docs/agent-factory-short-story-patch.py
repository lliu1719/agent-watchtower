"""Agent factory backend: a two-step story for a shorter demo (WT_STORY=short), Tier 1 then Tier 3.

Step 1: sec-03 writes twice in the old, closed issue. WatchTower revokes its key on its own (Tier 1).
Step 2: Security Research and DevOps agents gather in that thread and dev-02 contacts SmileyHub.
WatchTower proposes cutting the Fabric VCs, a person confirms, and AI Engine reviews it (Tier 3).

The snapshot gains "last_step" (2 in the short story, 4 in the full one); the page and WatchTower read it.
Without WT_STORY=short the four-step story is unchanged.

Run on the factory host, then add WT_STORY=short to .env and recreate the container (a restart keeps the old env):
    sudo python3 agent-factory-short-story-patch.py /home/fred/fred-hackathon/backend/wt
    cd /home/fred/fred-hackathon && (grep -q '^WT_STORY=' .env || echo 'WT_STORY=short' | sudo tee -a .env) && sudo docker compose up -d
"""

import os
import shutil
import sys
import time

MARK = "SHORT_STORY"

CONFIG_EDITS = [
    ('STEP_NAMES = {0: "All normal", 1: "Tier 0: watch only", 2: "Tier 1: agent level", 3: "Tier 2: department level", 4: "Tier 3: enterprise level"}\n',
     'STEP_NAMES = {0: "All normal", 1: "Tier 0: watch only", 2: "Tier 1: agent level", 3: "Tier 2: department level", 4: "Tier 3: enterprise level"}\n'
     '\n'
     '# WT_STORY=short: two steps for a shorter demo, Tier 1 then Tier 3 (WatchTower decides both).\n'
     'SHORT_STORY = os.getenv("WT_STORY", "full") == "short"\n'
     'if SHORT_STORY:\n'
     '    NARRATION = {\n'
     '        0: "Watchtower sees every agent action across every department.",\n'
     '        1: "One agent acting alone: Watchtower revokes its key at once, and the rest of the team keeps working.",\n'
     '        2: "When agents cross the walls you built, you cut the power. A person confirms, and AI Engine reviews the intent.",\n'
     '    }\n'
     '    STEP_NAMES = {0: "All normal", 1: "Tier 1: agent level", 2: "Tier 3: enterprise level"}\n'
     'LAST_STEP = max(STEP_NAMES)\n'
     'STEP_TIER = {1: 1, 2: 3} if SHORT_STORY else {s: s - 1 for s in range(1, 5)}   # the tier WatchTower reports for each step\n'),
]

WORLD_EDITS = [
    # the snapshot says how many steps the story has
    ('return {"type": "snap", "step": self.step, "stepname":',
     'return {"type": "snap", "step": self.step, "last_step": C.LAST_STEP, "stepname":'),
    # Auto-run: as many steps as the story has, waiting for each step's tier
    ("        while self.auto and self.running and self.step < 4:\n",
     "        while self.auto and self.running and self.step < C.LAST_STEP:\n"),
    ("                await self._wait_tier(self.step - 1)\n",
     "                await self._wait_tier(C.STEP_TIER[self.step])\n"),
    ("        if self.running and self.step >= 4:\n",
     "        if self.running and self.step >= C.LAST_STEP:\n"),
    # NEXT
    ("        if not self.running or self.step >= 4:\n            return\n",
     "        if not self.running or self.step >= C.LAST_STEP:\n            return\n"),
    ('        shared = C.REPO["shared"]\n        if s == 1:      # one agent gets stuck',
     '        shared = C.REPO["shared"]\n'
     '        if C.SHORT_STORY:\n'
     '            if s == 1:  # one agent keeps writing in an old, closed issue it never uses\n'
     '                self.inject("sec-03", {"kind": "stuck", "repo": shared, "issue": C.ISSUE_OLD})\n'
     '                self.inject("sec-03", {"kind": "hidden", "repo": shared, "issue": C.ISSUE_OLD}, delay=8)\n'
     '            else:       # agents from two departments gather in that thread; one contacts an outside service\n'
     '                for i, aid in enumerate(["sec-01", "sec-02", "dev-01"]):\n'
     '                    self.inject(aid, {"kind": "reply", "repo": shared, "issue": C.ISSUE_OLD}, delay=i * 3)\n'
     '                self.inject("dev-02", {"kind": "external", "repo": shared, "issue": C.ISSUE_OLD}, delay=10)\n'
     '        elif s == 1:      # one agent gets stuck'),
    # an external tier moves the story to the step that tier belongs to (not tier + 1 in the short story)
    ("        self.step = max(self.step, tier + 1)\n",
     "        self.step = max(self.step, next((s for s, t in C.STEP_TIER.items() if t == tier), self.step))\n"),
    ('"narration": C.NARRATION[min(e["tier"] + 1, 4)],',
     '"narration": C.NARRATION.get(min(e["tier"] + 1, C.LAST_STEP), ""),'),
]


def apply(path: str, edits) -> str:
    src = open(path, encoding="utf8").read()
    out = src
    for old, new in edits:
        n = out.count(old)
        if n != 1:
            raise SystemExit(f"{path}: expected one match, found {n}, for:\n{old}\nNothing was written.")
        out = out.replace(old, new, 1)
    return out


def main(folder: str) -> None:
    config, world = os.path.join(folder, "config.py"), os.path.join(folder, "world.py")
    if MARK in open(config, encoding="utf8").read():
        print(f"{folder}: already patched")
        return
    new_config, new_world = apply(config, CONFIG_EDITS), apply(world, WORLD_EDITS)   # check both before writing either
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for path, text in ((config, new_config), (world, new_world)):
        shutil.copy2(path, f"{path}.bak-watchtower-{stamp}")
        with open(path, "w", encoding="utf8") as f:
            f.write(text)
    print(f"{folder}: patched config.py and world.py (backups .bak-watchtower-{stamp}). "
          "Now add WT_STORY=short to .env and run: sudo docker compose up -d")


if __name__ == "__main__":
    main(sys.argv[1])
