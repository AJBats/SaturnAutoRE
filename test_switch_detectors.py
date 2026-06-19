#!/usr/bin/env python3
"""Regression guard for the SH-2 switch-dispatch detectors.

The analyzer recognizes several GCC switch idioms via a family of
"recipe" detectors (`_detect_braf_switch_targets`,
`_detect_mov_l_jmp_switch_targets`, `_detect_byte_indexed_jmp_switch_targets`)
tried in sequence by `BinaryModel._scan_all_switch_targets`.  Each recipe
is independently valid; adding a new one (or generalizing an old one)
must never silently change what a previously-recognized dispatcher
resolves to.

This test locks the *whole-pipeline* output (`model.switch_clusters`,
dispatcher_pc -> ordered case targets) against a committed golden, built
the same way eval_server builds the model so braf gets real pool_priors.

  python test_switch_detectors.py            # verify against golden
  python test_switch_detectors.py --update   # rewrite golden (deliberate)

Diffs are split into two buckets:
  * REGRESSION (a known dispatcher vanished or its targets changed) —
    always fails; this is the contract.
  * NEW (a dispatcher the old pipeline missed) — also fails, but
    separately, because new matches are expected when a recipe is added
    or generalized.  Audit them in the eval UI, then re-run --update to
    accept the new baseline (the forward, self-healing loop).

Fixtures point at sibling game projects.  A fixture whose project/binary
isn't present is skipped (so the test still runs on a checkout without
the game repos) — never reported as a regression.
"""

import sys
import json
import argparse
import hashlib
import importlib.util
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
GOLDEN_PATH = SCRIPT_DIR / "switch_detectors_golden.json"

# Each fixture is a project root + its eval config yaml, both relative to
# this repo root.  vram / target_path / pool_priors are read from the
# yaml exactly as eval_server._build_or_get_model does.
FIXTURES = [
    {"name": "APROG", "root": "../SaturnReverseTest", "config": "config/aprog.bin.yaml"},
    {"name": "RACE",  "root": "../DaytonaCCEReverse", "config": "config/race.bin.yaml"},
]


def _load_analyzer():
    """Import analyzer.py beside this script regardless of CWD.  Register
    in sys.modules before exec so dataclass decorators resolve."""
    path = SCRIPT_DIR / "analyzer.py"
    spec = importlib.util.spec_from_file_location("analyzer", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["analyzer"] = mod
    spec.loader.exec_module(mod)
    return mod


def _build_snapshot(analyzer, fixture):
    """Build the model for one fixture and return (snapshot, status).

    snapshot = {"vram": "0x...", "binary_sha256": "...",
                "dispatchers": {pc_hex: [target_hex, ...]}}
    status   = "ok" | "skip:<reason>"
    """
    root = (SCRIPT_DIR / fixture["root"]).resolve()
    cfg_path = root / fixture["config"]
    if not cfg_path.exists():
        return None, f"skip:no config ({cfg_path})"

    cfg = yaml.safe_load(cfg_path.read_text())
    options = (cfg or {}).get("options") or {}
    binary_path = root / options["target_path"]
    if not binary_path.exists():
        return None, f"skip:no binary ({binary_path})"

    binary = binary_path.read_bytes()
    vram = int(options["vram"])
    # eval_server convention: priors sidecar sits next to the yaml,
    # named "<yaml stem>.pool_priors.txt".
    priors_path = cfg_path.parent / (cfg_path.stem + ".pool_priors.txt")

    # reference_dir / runtime_hits don't affect switch detection (it reads
    # only binary + vram + pool words), so we omit them for speed.
    model = analyzer.BinaryModel(
        binary=binary,
        vram=vram,
        pool_priors_path=priors_path if priors_path.exists() else None,
    )

    dispatchers = {
        f"0x{pc:08X}": [f"0x{t:08X}" for t in targets]
        for pc, targets in sorted(model.switch_clusters.items())
    }
    snap = {
        "vram": f"0x{vram:08X}",
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "dispatchers": dispatchers,
    }
    return snap, "ok"


def _diff(golden, current):
    """Return (regressions, news) where each is a list of human strings."""
    g = golden.get("dispatchers", {})
    c = current.get("dispatchers", {})
    regressions, news = [], []
    for pc in sorted(set(g) | set(c)):
        if pc not in c:
            regressions.append(f"  REMOVED  {pc}  (was {len(g[pc])} targets)")
        elif pc not in g:
            news.append(f"  NEW      {pc}  -> {len(c[pc])} targets {c[pc][:6]}")
        elif g[pc] != c[pc]:
            regressions.append(
                f"  CHANGED  {pc}\n      golden: {g[pc]}\n      now:    {c[pc]}"
            )
    return regressions, news


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true",
                    help="rewrite the golden from the current analyzer")
    args = ap.parse_args()

    analyzer = _load_analyzer()
    golden = {}
    if GOLDEN_PATH.exists():
        golden = json.loads(GOLDEN_PATH.read_text())
    golden_fx = golden.get("fixtures", {})

    current_fx = {}
    any_regression = False
    any_new = False

    for fx in FIXTURES:
        name = fx["name"]
        snap, status = _build_snapshot(analyzer, fx)
        if status != "ok":
            print(f"[{name}] {status}")
            # Preserve any existing golden entry so --update doesn't drop a
            # fixture just because its repo is absent on this machine.
            if name in golden_fx and not args.update:
                current_fx[name] = golden_fx[name]
            elif name in golden_fx:
                current_fx[name] = golden_fx[name]
            continue

        current_fx[name] = snap
        n_disp = len(snap["dispatchers"])
        if args.update:
            print(f"[{name}] {n_disp} dispatchers (will write golden)")
            continue

        if name not in golden_fx:
            print(f"[{name}] NO GOLDEN yet — {n_disp} dispatchers found "
                  f"(run --update to record baseline)")
            any_new = True
            continue

        gsnap = golden_fx[name]
        if gsnap.get("binary_sha256") != snap["binary_sha256"]:
            print(f"[{name}] WARNING: binary changed since golden "
                  f"(sha mismatch) — diffs below may be expected")
        regressions, news = _diff(gsnap, snap)
        if not regressions and not news:
            print(f"[{name}] OK — {n_disp} dispatchers, identical to golden")
        if regressions:
            any_regression = True
            print(f"[{name}] REGRESSIONS ({len(regressions)}):")
            print("\n".join(regressions))
        if news:
            any_new = True
            print(f"[{name}] NEW dispatchers ({len(news)}) — audit in UI, "
                  f"then --update:")
            print("\n".join(news))

    if args.update:
        out = {"_meta": {"note": "Golden snapshot of BinaryModel.switch_clusters "
                                 "per fixture. Regression guard for switch detectors."},
               "fixtures": current_fx}
        GOLDEN_PATH.write_text(json.dumps(out, indent=2) + "\n")
        print(f"\nWrote golden: {GOLDEN_PATH}")
        return 0

    print()
    if any_regression:
        print("FAIL: switch-detector regression (a known dispatcher changed "
              "or vanished).")
        return 1
    if any_new:
        print("FAIL: new dispatchers detected. If intentional, audit them in "
              "the eval UI and re-run with --update.")
        return 1
    print("PASS: all present fixtures match golden.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
