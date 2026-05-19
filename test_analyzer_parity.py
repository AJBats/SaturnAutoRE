#!/usr/bin/env python3
"""test_analyzer_parity.py — regression harness for analyzer refactor.

Runs the current oracle.py (and, once landed, analyzer.py) against every
verified subseg in a yaml and reports per-function parity.  Stamps are
treated as ground truth: a human has approved them with the current oracle,
so the oracle's analysis SHOULD reproduce the stamped boundary and the
stamped subseg shouldn't fire LOW verdict / structural yellow flags.

Run:
    python test_analyzer_parity.py <yaml> --project-root <project>
    python test_analyzer_parity.py config/race.bin.yaml --project-root D:/Projects/DaytonaCCEReverse

Outputs:
    - Human-readable summary to stdout
    - <yaml_stem>.parity_baseline.json (full per-subseg detail) when --baseline is given
    - Diff against an existing baseline when --compare <path> is given

Phases this harness will run through:

  PHASE A (now) — current oracle.py only.  Establishes:
                  * Does oracle agree with its own stamped data?
                  * Where does oracle disagree (= known-bugs-in-stamps OR
                    bugs-the-stamps-papered-over)?

  PHASE B (later) — current oracle + new analyzer.py side by side.  Diffs
                    field-by-field.  Any new divergence is either:
                      * Intentional improvement (note + accept)
                      * Regression (fix before swap)

  PHASE C (later) — forward-sweep parity.  Remove subseg N from yaml, ask
                    sweep what's next.  Both implementations must propose
                    subseg N's start and compute its end correctly.
"""

import argparse
import json
import sys
from pathlib import Path

import yaml as yamllib

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR / "lib"))

# Importing eval_server gives us its cache-loading helpers (pool priors,
# binary pool targets, static/cross callers, reference starts, runtime hits)
# without needing to reimplement.  Flask app object gets created but never
# .run()'d.
#
# TODO(cutover): when oracle.py is finally deleted, this harness will
# break.  Before that delete happens, freeze oracle's per-subseg outputs
# into a JSON snapshot (e.g. baseline_oracle_<binary>.json), and refactor
# run_phase3_parity to diff analyzer.analyze_function output against the
# frozen snapshot instead of against a live oracle import.  Same goes for
# any phase-4+ comparison that currently uses oracle/eval_server helpers
# as the reference oracle.
import eval_server
import oracle
import analyzer


# ---------------------------------------------------------------------------
# Setup — populate eval_server.STATE so its loaders work, then capture
# the analytical state for harness use.
# ---------------------------------------------------------------------------

def _setup(yaml_path: Path, project_root: Path) -> dict:
    """Populate eval_server.STATE the same way main() does, but without
    starting Flask.  Returns a context dict the harness consumes."""
    eval_server.STATE["yaml_path"] = yaml_path
    eval_server.STATE["project_root"] = project_root
    eval_server.STATE["session_path"] = yaml_path.parent / (yaml_path.stem + ".session.json")
    eval_server._reload_caches()

    cfg = eval_server.STATE["cfg_cache"]
    binary = eval_server.STATE["binary_cache"]
    vram = eval_server.STATE["vram_cache"]

    # Union pool_priors + binary_pool_targets the same way _compute_current does.
    pool_priors = dict(eval_server.STATE.get("binary_pool_targets") or {})
    pool_priors.update(eval_server.STATE.get("pool_priors") or {})

    return {
        "cfg": cfg,
        "binary": binary,
        "vram": vram,
        "pool_priors": pool_priors,
        "reference_starts": set(eval_server.STATE.get("reference_starts") or []),
        "static_callers": eval_server.STATE.get("static_callers") or {},
        "cross_module_callers": eval_server.STATE.get("cross_module_callers") or {},
    }


# ---------------------------------------------------------------------------
# Per-subseg analysis under current oracle.  Captures every field that the
# new analyzer will need to reproduce.
# ---------------------------------------------------------------------------

def _analyze_with_current_oracle(ctx: dict, subseg: dict) -> dict:
    """Run oracle.analyze_candidate against a single verified subseg and
    pack its output into a flat dict suitable for diffing."""
    start = subseg["start"]
    yaml_end = subseg["end"]

    # Find the TU containing this subseg (matches eval_server's hint_end logic).
    tu = next((t for t in ctx["cfg"].get("tus", []) if t["start"] <= start <= t["end"]), None)
    hint_end = tu["end"] if tu else None

    ev = oracle.analyze_candidate(
        ctx["binary"], ctx["vram"], start,
        hint_end=hint_end,
        pool_priors=ctx["pool_priors"],
    )

    return {
        "start": start,
        "yaml_end": yaml_end,
        "oracle_end": ev.end,
        "end_match": ev.end == yaml_end,
        "end_delta": ev.end - yaml_end,
        "prologue_range": list(ev.prologue_range),
        "prologue_saved": list(ev.prologue_saved),
        "prologue_stack": ev.prologue_stack,
        "epilogue_range": list(ev.epilogue_range) if ev.epilogue_range[0] is not None else None,
        "final_rts": ev.final_rts,
        "delay_slot": ev.delay_slot,
        "branch_count": len(ev.branches),
        "internal_branch_count": sum(1 for b in ev.branches if b.internal),
        "external_branch_count": sum(1 for b in ev.branches if not b.internal and b.target is not None),
        "indirect_branch_count": sum(1 for b in ev.branches if b.target is None),
        "conditional_rts_count": len(ev.conditional_rts),
        "pool_target_count": len(ev.pool_targets),
        "reachable_count": len(ev.reachable),
        "verdict": ev.verdict,
        "yellow_flags": list(ev.yellow_flags),
        "tu_name": tu["name"] if tu else None,
    }


# ---------------------------------------------------------------------------
# Harness — iterate every verified subseg, build a report.
# ---------------------------------------------------------------------------

def _classify_subseg(result: dict) -> str:
    """Categorize one subseg's parity result.

    The categories help triage the report: stamps the oracle disagrees with
    are the ones worth eyeballing — either the stamp's wrong (rare), the
    oracle's wrong (= bugs to fix), or there's a known limitation we can
    document.
    """
    if not result["end_match"]:
        return "END_DISAGREE"
    if result["verdict"] == "LOW":
        return "LOW_VERDICT"
    if result["verdict"] == "MEDIUM" and result["yellow_flags"]:
        return "MEDIUM_VERDICT"
    if result["yellow_flags"]:
        return "HIGH_WITH_FLAGS"
    return "CLEAN"


def run_baseline(yaml_path: Path, project_root: Path) -> dict:
    """Run current oracle against every verified code subseg.  Returns the
    full report dict (also written to disk by main() when --baseline is
    passed)."""
    ctx = _setup(yaml_path, project_root)
    subsegs = [s for s in ctx["cfg"].get("subsegments", []) if s.get("type") == "code"]
    subsegs.sort(key=lambda s: s["start"])

    results = []
    for s in subsegs:
        try:
            r = _analyze_with_current_oracle(ctx, s)
        except Exception as e:
            r = {
                "start": s["start"],
                "yaml_end": s["end"],
                "error": f"{type(e).__name__}: {e}",
            }
        r["category"] = _classify_subseg(r) if "error" not in r else "ERROR"
        results.append(r)

    by_category = {}
    for r in results:
        by_category.setdefault(r["category"], []).append(r)

    return {
        "yaml_path": str(yaml_path),
        "project_root": str(project_root),
        "subseg_count": len(results),
        "category_counts": {k: len(v) for k, v in sorted(by_category.items())},
        "results": results,
    }


def _format_subseg_short(r: dict) -> str:
    if "error" in r:
        return f"  0x{r['start']:08X}  ERROR: {r['error']}"
    delta = r["end_delta"]
    delta_str = f"{delta:+d}b" if delta != 0 else "    "
    flags = f"  flags: {len(r['yellow_flags'])}" if r["yellow_flags"] else ""
    return (
        f"  0x{r['start']:08X} -> oracle 0x{r['oracle_end']:08X}  "
        f"yaml 0x{r['yaml_end']:08X}  {delta_str}  "
        f"{r['verdict']}{flags}"
    )


def _print_summary(report: dict, show_categories: list, verbose: bool):
    print()
    print(f"PARITY BASELINE — current oracle.py")
    print(f"  Yaml:         {report['yaml_path']}")
    print(f"  Project:      {report['project_root']}")
    print(f"  Subsegs:      {report['subseg_count']} verified code")
    print()
    print(f"By category:")
    for cat, count in sorted(report["category_counts"].items()):
        print(f"  {cat:20s} {count:4d}")
    print()
    if not verbose and not show_categories:
        print(f"(use --verbose to see all rows, or --show CATEGORY to filter)")
        return

    by_cat = {}
    for r in report["results"]:
        by_cat.setdefault(r["category"], []).append(r)

    target_cats = show_categories or list(by_cat.keys())
    for cat in sorted(target_cats):
        rows = by_cat.get(cat, [])
        if not rows:
            continue
        print(f"--- {cat} ({len(rows)}) ---")
        for r in rows[: 200 if verbose else 20]:
            print(_format_subseg_short(r))
            if verbose and r.get("yellow_flags"):
                for f in r["yellow_flags"]:
                    print(f"      flag: {f}")
        if len(rows) > (200 if verbose else 20):
            print(f"  ... and {len(rows) - (200 if verbose else 20)} more")
        print()


# ---------------------------------------------------------------------------
# Phase 1 parity: analyzer's BinaryModel.byte_kind/pool_words must match
# eval_server's pool_priors U binary_pool_targets exactly.  Both views are
# {addr: size} dicts after the union.  Any divergence is a port bug.
# ---------------------------------------------------------------------------

def _build_analyzer_model(yaml_path: Path, project_root: Path):
    """Construct a BinaryModel using the same paths eval_server resolves
    from the yaml's `options:` block.  Returns (model, eval_server_ctx)
    so per-phase tests have both views available for diffing."""
    ctx = _setup(yaml_path, project_root)
    cfg = ctx["cfg"]
    options = cfg.get("options") or {}

    def _resolve(key):
        val = options.get(key)
        if not val:
            return None
        p = Path(val)
        if not p.is_absolute():
            p = (project_root / p).resolve()
        return p

    priors_path = yaml_path.parent / (yaml_path.stem + ".pool_priors.txt")
    reference_dir = _resolve("reference_dir")
    reference_scan_dir = _resolve("reference_scan_dir")

    runtime_hits_dirs = []
    for d in (options.get("runtime_hits_dirs") or []):
        p = Path(d)
        if not p.is_absolute():
            p = (project_root / p).resolve()
        runtime_hits_dirs.append(p)

    model = analyzer.BinaryModel(
        binary=ctx["binary"],
        vram=ctx["vram"],
        pool_priors_path=priors_path if priors_path.exists() else None,
        reference_dir=reference_dir,
        reference_scan_dir=reference_scan_dir,
        runtime_hits_dirs=runtime_hits_dirs,
    )
    return model, ctx


def run_phase1_parity(yaml_path: Path, project_root: Path) -> dict:
    """Build the analyzer's BinaryModel against the same inputs eval_server
    uses, then assert the pool view matches eval_server's union exactly."""
    model, ctx = _build_analyzer_model(yaml_path, project_root)
    expected = ctx["pool_priors"]
    actual = model.pool_priors_dict()

    # Diff
    only_in_expected = {a: expected[a] for a in expected if a not in actual}
    only_in_actual   = {a: actual[a]   for a in actual   if a not in expected}
    size_mismatch    = {
        a: {"expected": expected[a], "actual": actual[a]}
        for a in expected
        if a in actual and expected[a] != actual[a]
    }

    # Pool_words sanity: each addr should have a value that matches a
    # re-read of the binary at that addr.  Catches a copy-paste bug where
    # value comes from somewhere unrelated.
    pool_word_value_mismatches = []
    for addr, pw in model.pool_words.items():
        expected_value = model._read_word(addr, pw.size)
        if pw.value != expected_value:
            pool_word_value_mismatches.append({
                "addr": f"0x{addr:08X}",
                "size": pw.size,
                "stored": pw.value,
                "expected": expected_value,
            })

    return {
        "expected_count": len(expected),
        "actual_count": len(actual),
        "match": (not only_in_expected and not only_in_actual and not size_mismatch),
        "only_in_eval_server": {f"0x{a:08X}": s for a, s in sorted(only_in_expected.items())},
        "only_in_analyzer":    {f"0x{a:08X}": s for a, s in sorted(only_in_actual.items())},
        "size_mismatch":       {f"0x{a:08X}": v for a, v in sorted(size_mismatch.items())},
        "pool_word_value_mismatches": pool_word_value_mismatches,
    }


def _print_phase1(result: dict):
    print()
    print(f"PHASE 1 PARITY — pool detection (analyzer vs eval_server)")
    print(f"  eval_server pool_priors U binary_pool_targets: {result['expected_count']} entries")
    print(f"  analyzer.BinaryModel.byte_kind (POOL*):        {result['actual_count']} entries")
    print()
    if result["match"]:
        print(f"  PASS  pool views are byte-for-byte identical")
    else:
        print(f"  FAIL  MISMATCH")
        if result["only_in_eval_server"]:
            print(f"    Only in eval_server ({len(result['only_in_eval_server'])}): "
                  f"{list(result['only_in_eval_server'].items())[:5]}...")
        if result["only_in_analyzer"]:
            print(f"    Only in analyzer    ({len(result['only_in_analyzer'])}): "
                  f"{list(result['only_in_analyzer'].items())[:5]}...")
        if result["size_mismatch"]:
            print(f"    Size mismatches     ({len(result['size_mismatch'])}): "
                  f"{list(result['size_mismatch'].items())[:5]}...")
    pwm = result["pool_word_value_mismatches"]
    if pwm:
        print(f"  FAIL  pool_words value mismatches ({len(pwm)}): {pwm[:3]}...")
    else:
        print(f"  PASS  pool_words values all read correctly")


# ---------------------------------------------------------------------------
# Phase 3 parity: analyzer.analyze_function must produce a FunctionAnalysis
# whose every field equals the corresponding oracle.analyze_candidate
# FunctionEvidence field.  Run against every verified subseg.
# ---------------------------------------------------------------------------

def _evidence_fields_for_diff(ev) -> dict:
    """Project oracle.FunctionEvidence into the comparable shape."""
    return {
        "start": ev.start,
        "end": ev.end,
        "prologue_range": tuple(ev.prologue_range),
        "prologue_saved": list(ev.prologue_saved),
        "prologue_stack": ev.prologue_stack,
        "epilogue_range": tuple(ev.epilogue_range),
        "final_exit": ev.final_rts,
        "delay_slot": ev.delay_slot,
        "branches": [(b.src, b.target, b.mnem, b.internal) for b in ev.branches],
        "conditional_returns": list(ev.conditional_rts),
        "pool_targets": list(ev.pool_targets),
        "reachable": set(ev.reachable),
        "verdict": ev.verdict,
        "yellow_flags": list(ev.yellow_flags),
    }


def _analysis_fields_for_diff(fa) -> dict:
    """Project analyzer.FunctionAnalysis into the same shape."""
    return {
        "start": fa.start,
        "end": fa.end,
        "prologue_range": tuple(fa.prologue_range),
        "prologue_saved": list(fa.prologue_saved),
        "prologue_stack": fa.prologue_stack,
        "epilogue_range": tuple(fa.epilogue_range),
        "final_exit": fa.final_exit,
        "delay_slot": fa.delay_slot,
        "branches": [(b.src, b.target, b.mnem, b.internal) for b in fa.branches],
        "conditional_returns": list(fa.conditional_returns),
        "pool_targets": list(fa.pool_targets),
        "reachable": set(fa.reachable),
        "verdict": fa.verdict.value,
        "yellow_flags": list(fa.yellow_flags),
    }


def run_phase3_parity(yaml_path: Path, project_root: Path) -> dict:
    """For every verified code subseg, run oracle AND analyzer; verify
    every comparable field matches.  Phase 3a expectation: zero divergence
    (analyzer wraps oracle, conversion is loss-free)."""
    model, ctx = _build_analyzer_model(yaml_path, project_root)
    subsegs = sorted(
        [s for s in ctx["cfg"].get("subsegments", []) if s.get("type") == "code"],
        key=lambda s: s["start"],
    )

    divergences = []
    checked = 0
    for s in subsegs:
        start = s["start"]
        tu = next((t for t in ctx["cfg"].get("tus", []) if t["start"] <= start <= t["end"]), None)
        hint_end = tu["end"] if tu else None

        ev = oracle.analyze_candidate(
            ctx["binary"], ctx["vram"], start,
            hint_end=hint_end,
            pool_priors=ctx["pool_priors"],
        )
        fa = model.analyze_function(start, hint_end=hint_end)

        a = _evidence_fields_for_diff(ev)
        b = _analysis_fields_for_diff(fa)

        per_field = {}
        for k in a:
            if a[k] != b[k]:
                per_field[k] = {"oracle": a[k], "analyzer": b[k]}
        if per_field:
            divergences.append({
                "subseg_start": f"0x{start:08X}",
                "diff_fields": list(per_field.keys()),
                "details": per_field,
            })
        checked += 1

    return {
        "subsegs_checked": checked,
        "divergences": divergences,
        "match": not divergences,
    }


def _print_phase3(result: dict):
    print()
    print(f"PHASE 3 PARITY - analyze_function vs oracle.analyze_candidate")
    print(f"  Subsegs checked: {result['subsegs_checked']}")
    if result["match"]:
        print(f"  PASS  every FunctionAnalysis field matches FunctionEvidence for every subseg")
    else:
        d = result["divergences"]
        print(f"  FAIL  {len(d)} subsegs diverge")
        # Show first few with which fields differ
        for entry in d[:5]:
            print(f"    {entry['subseg_start']}  fields: {entry['diff_fields']}")
        if len(d) > 5:
            print(f"    ... and {len(d) - 5} more")


# ---------------------------------------------------------------------------
# Phase 2 parity: analyzer's reference_starts/static_callers/
# cross_module_callers/runtime_hits must match eval_server's exactly.
# ---------------------------------------------------------------------------

def _diff_dict(name: str, expected: dict, actual: dict) -> dict:
    """Generic exact-match dict diff with hex addr formatting."""
    only_e = {a: expected[a] for a in expected if a not in actual}
    only_a = {a: actual[a]   for a in actual   if a not in expected}
    mismatch = {a: {"expected": expected[a], "actual": actual[a]}
                for a in expected if a in actual and expected[a] != actual[a]}
    return {
        "name": name,
        "expected_count": len(expected),
        "actual_count": len(actual),
        "match": (not only_e and not only_a and not mismatch),
        "only_in_eval_server": {f"0x{a:08X}": expected[a] for a in sorted(only_e)},
        "only_in_analyzer":    {f"0x{a:08X}": actual[a]   for a in sorted(only_a)},
        "mismatch":            {f"0x{a:08X}": v for a, v in sorted(mismatch.items())},
    }


def _diff_set(name: str, expected: set, actual: set) -> dict:
    only_e = expected - actual
    only_a = actual - expected
    return {
        "name": name,
        "expected_count": len(expected),
        "actual_count": len(actual),
        "match": (not only_e and not only_a),
        "only_in_eval_server": sorted(f"0x{a:08X}" for a in only_e),
        "only_in_analyzer":    sorted(f"0x{a:08X}" for a in only_a),
    }


def run_phase2_parity(yaml_path: Path, project_root: Path) -> dict:
    """Compare analyzer's callers/reference/hits dicts vs eval_server's."""
    model, ctx = _build_analyzer_model(yaml_path, project_root)

    # eval_server stores reference_starts as a sorted list; the model
    # stores it as a set.  Normalize both to set for comparison.
    diffs = [
        _diff_set("reference_starts",
                   set(eval_server.STATE.get("reference_starts") or []),
                   model.reference_starts),
        _diff_dict("static_callers",
                    eval_server.STATE.get("static_callers") or {},
                    model.static_callers),
        _diff_dict("cross_module_callers",
                    eval_server.STATE.get("cross_module_callers") or {},
                    model.cross_module_callers),
        _diff_dict("runtime_hits",
                    eval_server.STATE.get("runtime_hits") or {},
                    model.runtime_hits),
    ]
    return {
        "all_match": all(d["match"] for d in diffs),
        "diffs": diffs,
    }


def _print_phase2(result: dict):
    print()
    print(f"PHASE 2 PARITY - reference / callgraph / runtime hits")
    for d in result["diffs"]:
        if d["match"]:
            print(f"  PASS  {d['name']:24s}  {d['expected_count']:6d} entries match")
        else:
            print(f"  FAIL  {d['name']:24s}  expected {d['expected_count']}, got {d['actual_count']}")
            if d.get("only_in_eval_server"):
                ex = d["only_in_eval_server"]
                items = list(ex.items()) if isinstance(ex, dict) else ex
                print(f"        only in eval_server ({len(items)}): {items[:5]}...")
            if d.get("only_in_analyzer"):
                ac = d["only_in_analyzer"]
                items = list(ac.items()) if isinstance(ac, dict) else ac
                print(f"        only in analyzer    ({len(items)}): {items[:5]}...")
            if d.get("mismatch"):
                mm = list(d["mismatch"].items())
                print(f"        value mismatches    ({len(mm)}): {mm[:3]}...")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("yaml_path", help="path to boundary yaml (e.g. config/race.bin.yaml)")
    p.add_argument("--project-root", default=None, help="project root (defaults to yaml's parent's parent)")
    p.add_argument("--baseline", help="write full per-subseg baseline JSON here (current oracle only)")
    p.add_argument("--show", action="append", default=[], help="show full detail for category (END_DISAGREE / LOW_VERDICT / etc.)")
    p.add_argument("--verbose", action="store_true", help="show all rows + yellow flags")
    p.add_argument("--phase", choices=["baseline", "phase1", "phase2", "phase3", "all"], default="baseline",
                   help="which parity check to run (default: baseline)")
    args = p.parse_args()

    yaml_path = Path(args.yaml_path)
    if not yaml_path.is_absolute():
        yaml_path = yaml_path.resolve()

    if args.project_root:
        project_root = Path(args.project_root).resolve()
    else:
        # default: assume <project>/config/<yaml> layout
        project_root = yaml_path.parent.parent

    if args.phase in ("baseline", "all"):
        report = run_baseline(yaml_path, project_root)
        if args.baseline:
            out_path = Path(args.baseline)
            out_path.write_text(json.dumps(report, indent=2))
            print(f"Wrote baseline: {out_path}")
        _print_summary(report, args.show, args.verbose)

    if args.phase in ("phase1", "all"):
        result = run_phase1_parity(yaml_path, project_root)
        _print_phase1(result)
        if not result["match"]:
            sys.exit(1)

    if args.phase in ("phase2", "all"):
        result = run_phase2_parity(yaml_path, project_root)
        _print_phase2(result)
        if not result["all_match"]:
            sys.exit(1)

    if args.phase in ("phase3", "all"):
        result = run_phase3_parity(yaml_path, project_root)
        _print_phase3(result)
        if not result["match"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
