"""Fail if the dependency graph reaches a package outside the IronSecurity stack.

Allowed: this workspace's own crates, the IronCrypto crates (`ic-*`,
`ironcrypto`) and the other IronSecurity projects. Cargo arguments may follow,
for example --all-features.
"""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1", *sys.argv[1:]],
    cwd=root, text=True))
stack = {"ironcrypto", "ironsocketlayer", "isl-ontology", "ironkeys", "ironpki", "ironevidence"}
members = set(metadata["workspace_members"])
violations = sorted(
    f'{p["name"]}@{p["version"]}' for p in metadata["packages"]
    if p["id"] not in members and not p["name"].startswith("ic-") and p["name"] not in stack)
print(json.dumps({"first_party_only": not violations,
                  "packages": len(metadata["packages"]),
                  "third_party_packages": violations}, indent=2))
raise SystemExit(bool(violations))
