#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check or apply the pinned OnePlus 13 memory patch, without network or phone access."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(source, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(source), *arguments], text=True, stderr=subprocess.STDOUT
    ).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", help="Apply after checking; otherwise check only")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    lock = json.loads((ROOT / "upstream.lock.json").read_text())
    if Path(git(source, "rev-parse", "--show-toplevel")).resolve() != source:
        raise ValueError("--source must be the root of the Mu-Silicium checkout")
    if git(source, "rev-parse", "HEAD") != lock["revision"]:
        raise ValueError("Upstream revision differs from upstream.lock.json")
    entry = lock["memory_patch"]
    patch = ROOT / entry["path"]
    if digest(patch) != entry["sha256"]:
        raise ValueError("Patch hash differs from upstream.lock.json")
    target = source / entry["target"]
    current = digest(target)
    if current == entry["after_sha256"]:
        git(source, "apply", "--reverse", "--check", str(patch))
        print("ALREADY_APPLIED: pinned memory patch is present; no files changed")
        return
    if current != entry["before_sha256"]:
        raise ValueError("Memory table has unknown contents; refusing to apply patch")
    git(source, "apply", "--check", str(patch))
    if args.apply:
        git(source, "apply", str(patch))
        if digest(target) != entry["after_sha256"]:
            raise ValueError("Patched memory table failed its expected hash check")
        print("APPLIED: pinned memory patch applied and verified")
    else:
        print("READY: pinned memory patch can be applied; no files changed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"ERROR: {error}")
