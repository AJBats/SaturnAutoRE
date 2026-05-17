#!/usr/bin/env python3
"""eval_apply.py — write approved verdicts from a session back to the yaml.

Reads the session file produced by eval_server (alongside the yaml), looks at
which candidates were approved, and appends them as new code subsegments in
the yaml's `subsegments:` list.

Run from the project directory:
    python D:/Projects/SaturnAutoRE/eval_apply.py config/race.bin.yaml
    python D:/Projects/SaturnAutoRE/eval_apply.py config/race.bin.yaml --dry-run

`--project-root` defaults to the current working directory.

The session is found at <yaml_path>.session.json (e.g. race.bin.session.json
next to race.bin.yaml).
"""

import argparse
import json
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from oracle import find_bedrock_candidates


def _format_subseg_entry(start, end, type_, file_name):
    """Render a single subsegment block in the sotn-style multi-line format."""
    return (
        f"  - start: 0x{start:08X}\n"
        f"    type:  {type_}\n"
        f"    file:  {file_name}\n"
        f"    end:   0x{end:08X}\n"
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("yaml_path", help="path to the boundary yaml (e.g. config/race.bin.yaml)")
    p.add_argument("--project-root", default=None, help="project root (defaults to current working directory)")
    p.add_argument("--dry-run", action="store_true", help="print diff, don't write")
    args = p.parse_args()

    project_root = Path(args.project_root) if args.project_root else Path.cwd()
    yaml_path = Path(args.yaml_path)
    if not yaml_path.is_absolute():
        yaml_path = (project_root / yaml_path).resolve()

    session_path = yaml_path.parent / (yaml_path.stem + ".session.json")
    if not session_path.exists():
        print(f"No session file at {session_path}", file=sys.stderr)
        sys.exit(1)

    with open(yaml_path) as f:
        cfg = yaml.safe_load(f)
    with open(session_path) as f:
        session = json.load(f)
    verdicts = session.get("verdicts", {})

    binary = open(project_root / cfg["options"]["target_path"], "rb").read()

    # Re-derive the same candidate list the server used, in the same order.
    candidates = find_bedrock_candidates(cfg, binary)

    approved = []
    for cid, (tu, ev) in enumerate(candidates):
        v = verdicts.get(str(cid))
        if v == "approved":
            approved.append((tu, ev))

    if not approved:
        print("No approved candidates in session. Nothing to write.")
        return

    # Build the new yaml text by appending to the existing file (preserve
    # comments + key order; yaml.safe_dump would rewrite the file).
    text = open(yaml_path).read()
    appended = "".join(
        _format_subseg_entry(ev.start, ev.end, "code", tu["name"])
        for tu, ev in approved
    )

    if not text.endswith("\n"):
        text += "\n"
    new_text = text + appended

    print(f"Approved: {len(approved)} candidates")
    for tu, ev in approved:
        print(f"  + {tu['name']}: 0x{ev.start:08X} - 0x{ev.end:08X} ({ev.end - ev.start + 1} bytes)")

    if args.dry_run:
        print("\n--- Lines that would be appended ---")
        print(appended)
        return

    with open(yaml_path, "w") as f:
        f.write(new_text)
    print(f"\nWrote {len(approved)} new subsegments to {yaml_path}")
    print(f"(Session file preserved at {session_path} — delete to start a fresh review.)")


if __name__ == "__main__":
    main()
