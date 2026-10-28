#!/usr/bin/env python3
"""Audit every advisory; distinguish inactive optional lockfile dependencies.
No advisory IDs are suppressed. Resolve --all-features for each supported target.
"""
import argparse
import json
import re
import subprocess
import sys


def run_json(command):
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr)
    try:
        return json.loads(result.stdout), result.returncode
    except json.JSONDecodeError as exc:
        raise RuntimeError(result.stderr or result.stdout) from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--no-fetch", action="store_true", help="use the already fetched advisory DB; record its revision")
    args = parser.parse_args()
    # cargo metadata over-approximates optional features (notably sqlx macros).
    # cargo tree uses the selected build features/target and is the build-scope evidence.
    tree = subprocess.run(["cargo", "tree", "--workspace", "--locked", "--all-features", "--target", args.target, "--prefix", "none", "--format", "{p}", "--edges", "normal,build,dev"], capture_output=True, text=True, check=False)
    if tree.returncode:
        raise RuntimeError(tree.stderr)
    active = set(re.findall(r"^([A-Za-z0-9_-]+) v([^\s]+)", tree.stdout, re.MULTILINE))
    if not active or not any(name.startswith("warpin-") for name, _ in active):
        raise RuntimeError("Cargo build dependency scope was empty")
    audit, status = run_json(["cargo", "audit", "--json"] + (["--no-fetch"] if args.no_fetch else []))
    if audit.get("error"):
        raise RuntimeError(str(audit["error"]))
    findings = audit["vulnerabilities"]["list"]
    failed = 0
    for item in findings:
        package = item["package"]
        selected = (package["name"], package["version"]) in active
        label = "ACTIVE VULNERABILITY" if selected else "INACTIVE OPTIONAL DEPENDENCY"
        print(label, package["name"], package["version"], item["advisory"]["id"])
        failed += int(selected)
    for kind, items in audit.get("warnings", {}).items():
        for item in items:
            package = item["package"]
            selected = (package["name"], package["version"]) in active
            advisory = item.get("advisory") or {}
            print("WARNING", kind, "active" if selected else "inactive", package["name"], package["version"], advisory.get("id", ""))
            failed += int(selected and kind in ("unsound", "yanked"))
    if status and not findings:
        raise RuntimeError("Audit failed without a classified vulnerability")
    print(f"target={args.target}; active packages={len(active)}; blockers={failed}; raw lockfile vulnerabilities={len(findings)}")
    return int(failed > 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, KeyError, OSError) as error:
        print(f"Security check failed: {error}", file=sys.stderr)
        sys.exit(2)
