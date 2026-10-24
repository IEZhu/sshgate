#!/usr/bin/env python3
"""Require Trivy to reject a generated, unissued token inside Markdown."""

import json
from pathlib import Path
import secrets
import string
import subprocess
import sys
import tempfile


def main():
    config = Path(sys.argv[1]).resolve()
    config.write_text("disable-allow-rules:\n  - markdown\n")
    with tempfile.TemporaryDirectory(prefix="trivy-secret-control-") as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        readme = source / "README.md"
        report = root / "report.json"
        # Random test data has never been issued by a service; never print it.
        token = "gh" + "p_" + "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(36)
        )
        for body, expected in (("# Clean control\n", 0), ("credential=" + token, 1)):
            readme.write_text(body)
            report.unlink(missing_ok=True)
            result = subprocess.run([
                "trivy", "--config", "", "fs", "--scanners", "secret",
                "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--ignorefile", "",
                "--ignore-policy", "", "--secret-config", str(config),
                "--exit-code", "1", "--no-progress", "--format", "json",
                "--output", str(report), str(source),
            ], capture_output=True, timeout=120)
            if result.returncode != expected or not report.is_file():
                raise RuntimeError("Secret scanner control failed")
            findings = [
                (item.get("Target", ""), secret.get("RuleID"))
                for item in json.loads(report.read_text()).get("Results", [])
                for secret in item.get("Secrets", [])
            ]
            detected = any(
                target.endswith("README.md") and rule == "github-pat"
                for target, rule in findings
            )
            if bool(findings) != bool(expected) or detected != bool(expected):
                raise RuntimeError("Markdown secret detection is incomplete")
    print("Secret scanner clean and Markdown positive controls passed")


if __name__ == "__main__":
    main()
