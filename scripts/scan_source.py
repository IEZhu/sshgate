#!/usr/bin/env python3
"""Run every official Python security rule and require complete source coverage."""
import json
from pathlib import Path
import subprocess
import sys

rules_root = Path(sys.argv[1]) / "python"
security_dirs = sorted(path for path in rules_root.rglob("security") if path.is_dir())
if not security_dirs:
    raise SystemExit("No Python security rules found; refusing an empty scan")
configs = []
for directory in security_dirs:
    configs.extend(["--config", str(directory)])
expected = set()
for target in map(Path, sys.argv[2:]):
    expected.update(path.resolve() for path in (target.rglob("*.py") if target.is_dir() else [target]) if path.is_file())
if not expected:
    raise SystemExit("No Python source targets found; refusing an empty scan")
result = subprocess.run(["semgrep", "scan", "--error", "--strict", "--disable-nosem", "--metrics", "off", "--no-git-ignore", "--json", *configs, *sys.argv[2:]], check=False, timeout=600, capture_output=True, text=True)
print(result.stderr, file=sys.stderr, end="")
report = json.loads(result.stdout)
scanned = {Path(path).resolve() for path in report.get("paths", {}).get("scanned", [])}
if result.returncode or report.get("errors") or expected - scanned:
    print(json.dumps(report, indent=2))
    raise SystemExit(f"Source scan failed or incomplete; missing: {sorted(map(str, expected - scanned))}")
print(f"Verified every Python source target was scanned ({len(expected)} files); no findings")
