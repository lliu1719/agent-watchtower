"""Run a tool's test cases locally: python3 -I ai-engine/tools/tests/run_cases.py [tool_name]"""
import importlib.util
import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
name = sys.argv[1] if len(sys.argv) > 1 else "watchtower_probe"
spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fn = getattr(module, name)

failed = 0
for case, c in json.loads((TOOLS / "tests" / f"{name}_cases.json").read_text()).items():
    actual = fn(**c["input"])
    ok = actual == c["expected"]
    failed += not ok
    print("PASS" if ok else "FAIL", case)
    if not ok:
        print("  expected:", json.dumps(c["expected"], ensure_ascii=False))
        print("  actual:  ", json.dumps(actual, ensure_ascii=False))
sys.exit(1 if failed else 0)
