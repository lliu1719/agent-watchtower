"""Agent factory backend: with WatchTower deciding (WT_LOCAL_TIERS=0), Auto-run waits for its answer to each step.

Auto-run used fixed gaps (8, 6, 5, 12 s). The agents act whenever their next model call returns, and
Tier 2 and Tier 3 wait for a reviewer on WatchTower, so the steps ran ahead of the decisions: all four in
about 15 seconds, reports out of order, and the Tier 2 and Tier 3 pills never lit. Now, after each step,
Auto-run waits until WatchTower has reported that step's tier (up to 90 s), holds 6 s so the banner can be
read, and then moves on. With WT_LOCAL_TIERS unset or 1 nothing changes.

Run on the factory host, then restart the backend (its code is mounted, no rebuild needed):
    sudo python3 agent-factory-autorun-patch.py /home/fred/fred-hackathon/backend/wt/world.py
    sudo docker restart fred-hackathon
"""

import shutil
import sys
import time

MARK = "async def _wait_tier("

OLD = """    async def auto_loop(self):
        gaps = {0: 8, 1: 6, 2: 5, 3: 12}           # seconds to wait before steps 1, 2, 3, 4 (short between Tier 0 and Tier 1)
        while self.auto and self.running and self.step < 4:
            await asyncio.sleep(gaps[self.step])
            await self.resume.wait()
"""

NEW = """    async def _wait_tier(self, tier, timeout=90):
        \"\"\"Wait until the external Watchtower has reported this tier (or Auto-run stops, or the timeout ends).\"\"\"
        end = time.time() + timeout
        while self.auto and self.running and self.det.tier_max < tier and time.time() < end:
            await asyncio.sleep(0.5)

    async def auto_loop(self):
        gaps = {0: 8, 1: 6, 2: 5, 3: 12}           # seconds to wait before steps 1, 2, 3, 4 (short between Tier 0 and Tier 1)
        external = os.getenv("WT_LOCAL_TIERS", "1") == "0"
        while self.auto and self.running and self.step < 4:
            if external and self.step >= 1:         # WatchTower decides: wait for its answer to this step (step n is tier n-1), then let it be read
                await self._wait_tier(self.step - 1)
                await asyncio.sleep(6)
            else:
                await asyncio.sleep(gaps[self.step])
            await self.resume.wait()
"""


def patch(path: str) -> None:
    src = open(path, encoding="utf8").read()
    if MARK in src:
        print(f"{path}: already patched")
        return
    if src.count(OLD) != 1 or "\nimport os" not in src or "\nimport time" not in src:
        raise SystemExit(f"{path}: the auto-run code is not the one this patch expects. Nothing was written.")
    backup = f"{path}.bak-watchtower-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf8") as f:
        f.write(src.replace(OLD, NEW, 1))
    print(f"{path}: patched (backup {backup}). Now: sudo docker restart fred-hackathon")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        patch(p)
