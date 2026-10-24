#!/usr/bin/env python3
"""Reject partial vulnerability results even when Trivy logs an error as WARN."""

from pathlib import Path
import sys


def check(text):
    if any(marker in text for marker in ("err.message=", "\tERROR\t", "\tFATAL\t")):
        raise ValueError("scanner reported an error or incomplete advisory details")


if __name__ == "__main__":
    for path in sys.argv[1:]:
        check(Path(path).read_text())
