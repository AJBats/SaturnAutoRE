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

_PHANTOM_PREFIX = "supported only by cross-module phantom callers (likely hot-swap collision, not a real entry)"


def _augment_oracle_flags_for_phantom(oracle_flags, ctx, start):
    """Apply eval_server._build_candidate_payload's phantom-prefix
    augmentation to oracle's raw yellow_flags.

    Analyzer's phase-4 analyze_function does this augmentation internally
    (so phase 4 absorbs the "intelligence" eval_server used to apply at
    render time).  For phase 3 parity to remain meaningful, we mirror the
    augmentation on oracle's side too.
    """
    has_cross = ctx["cross_module_callers"].get(start, 0) > 0
    has_same  = ctx["static_callers"].get(start, 0) > 0
    no_prologue = any("no prologue register pushes" in f for f in oracle_flags)
    if has_cross and not has_same and no_prologue:
        return [_PHANTOM_PREFIX] + list(oracle_flags)
    return list(oracle_flags)


def _evidence_fields_for_diff(ev, ctx, start) -> dict:
    """Project oracle.FunctionEvidence into the comparable shape.

    yellow_flags is augmented with the phantom prefix when applicable
    (mirroring what eval_server does at render time) so comparison
    against analyzer's phase-4-aware yellow_flags is symmetric.
    """
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
        "yellow_flags": _augment_oracle_flags_for_phantom(ev.yellow_flags, ctx, start),
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
    every comparable field matches.  Phase 3 expectation: zero divergence
    (analyzer reproduces oracle's behavior on shared fields)."""
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

        a = _evidence_fields_for_diff(ev, ctx, start)
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
# Phase 4 parity: per-function enrichment fields.  For each verified subseg,
# verify analyzer's FunctionAnalysis enrichment values match what eval_server
# computes today via its inline helpers.
# ---------------------------------------------------------------------------

_INDIRECT_HEADS = {"jmp", "jsr", "braf", "bsrf"}


def _expected_indirect_resolutions(ev, ctx) -> dict:
    """Drive eval_server._resolve_indirect_target per indirect instruction
    in the function and collect the resolved targets.  This mirrors what
    eval_server does row-by-row in the renderer; analyzer's phase-4
    indirect_resolutions dict should match the result."""
    import sys as _s
    _s.path.insert(0, str(SCRIPT_DIR / "lib"))
    from sh2_decode import decode_sh2

    binary = ctx["binary"]
    vram = ctx["vram"]
    out = {}
    for addr in sorted(ev.reachable):
        off = addr - vram
        if off + 1 >= len(binary):
            continue
        op = (binary[off] << 8) | binary[off + 1]
        mnem, _ = decode_sh2(op, addr)
        if mnem is None:
            continue
        head = mnem.split()[0]
        if head not in _INDIRECT_HEADS:
            continue
        resolved = eval_server._resolve_indirect_target(addr, mnem, ev)
        if resolved is not None:
            out[addr] = resolved
    return out


def _expected_phantom_hint(ev, ctx, start) -> bool:
    has_cross = ctx["cross_module_callers"].get(start, 0) > 0
    has_same  = ctx["static_callers"].get(start, 0) > 0
    no_prologue = any("no prologue register pushes" in f for f in ev.yellow_flags)
    return has_cross and not has_same and no_prologue


def _ref_to_dict(ref):
    if ref is None:
        return None
    return {
        "verdict": ref.verdict,
        "start_match": ref.start_match,
        "reference_next": ref.reference_next,
        "reference_implied_end": ref.reference_implied_end,
        "end_delta": ref.end_delta,
        "tooltip": ref.tooltip,
    }


def _midpoints_to_list(midpoints):
    return [
        {
            "addr": m.addr,
            "static_callers": m.static_callers,
            "cross_module_callers": m.cross_module_callers,
            "runtime_hits": m.runtime_hits,
        }
        for m in midpoints
    ]


def _eval_server_midpoints_to_list(midpoints):
    """eval_server returns midpoints as list[dict].  Project to the
    same shape as _midpoints_to_list for direct equality."""
    return [
        {
            "addr": m["addr"],
            "static_callers": m["static_callers"],
            "cross_module_callers": m["cross_module_callers"],
            "runtime_hits": m["runtime_hits"],
        }
        for m in midpoints
    ]


def run_phase4_parity(yaml_path: Path, project_root: Path) -> dict:
    """Phase 4 verifies each enrichment field analyzer.analyze_function
    now populates matches what eval_server's inline helpers produce."""
    model, ctx = _build_analyzer_model(yaml_path, project_root)
    subsegs = sorted(
        [s for s in ctx["cfg"].get("subsegments", []) if s.get("type") == "code"],
        key=lambda s: s["start"],
    )

    field_counts = {
        "indent_depths": 0,
        "indirect_resolutions": 0,
        "reference": 0,
        "evidence": 0,
        "midpoints": 0,
        "phantom_hint": 0,
        "indirect_calls_self_consistent": 0,
    }
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
        checked += 1

        per_field = {}

        # --- indent_depths
        expected_indent = eval_server._compute_indent_depths(ev)
        if expected_indent != fa.indent_depths:
            per_field["indent_depths"] = {
                "expected_keys": len(expected_indent),
                "actual_keys": len(fa.indent_depths),
                "only_in_expected": {f"0x{k:08X}": v for k, v in expected_indent.items() if fa.indent_depths.get(k) != v},
                "only_in_actual":   {f"0x{k:08X}": v for k, v in fa.indent_depths.items()   if expected_indent.get(k) != v},
            }
        else:
            field_counts["indent_depths"] += 1

        # --- indirect_resolutions
        expected_resolutions = _expected_indirect_resolutions(ev, ctx)
        if expected_resolutions != fa.indirect_resolutions:
            per_field["indirect_resolutions"] = {
                "expected": {f"0x{k:08X}": f"0x{v:08X}" for k, v in expected_resolutions.items()},
                "actual":   {f"0x{k:08X}": f"0x{v:08X}" for k, v in fa.indirect_resolutions.items()},
            }
        else:
            field_counts["indirect_resolutions"] += 1

        # --- reference
        expected_ref = eval_server._compute_reference_agreement(ev.start, ev.end)
        actual_ref = _ref_to_dict(fa.reference)
        if expected_ref != actual_ref:
            per_field["reference"] = {"expected": expected_ref, "actual": actual_ref}
        else:
            field_counts["reference"] += 1

        # --- evidence + midpoints
        expected_ce = eval_server._compute_candidate_evidence(ev.start, ev.end)
        actual_ev_dict = {
            "static_callers": fa.evidence.static_callers,
            "cross_module_callers": fa.evidence.cross_module_callers,
            "runtime_hits": fa.evidence.runtime_hits,
        }
        expected_ev_dict = {
            "static_callers": expected_ce["static_callers"],
            "cross_module_callers": expected_ce["cross_module_callers"],
            "runtime_hits": expected_ce["runtime_hits"],
        }
        if expected_ev_dict != actual_ev_dict:
            per_field["evidence"] = {"expected": expected_ev_dict, "actual": actual_ev_dict}
        else:
            field_counts["evidence"] += 1

        expected_mids = _eval_server_midpoints_to_list(expected_ce["midpoints"])
        actual_mids = _midpoints_to_list(fa.midpoints)
        if expected_mids != actual_mids:
            per_field["midpoints"] = {"expected": expected_mids, "actual": actual_mids}
        else:
            field_counts["midpoints"] += 1

        # --- phantom_hint
        expected_phantom = _expected_phantom_hint(ev, ctx, start)
        if expected_phantom != fa.phantom_hint:
            per_field["phantom_hint"] = {"expected": expected_phantom, "actual": fa.phantom_hint}
        else:
            field_counts["phantom_hint"] += 1

        # --- indirect_calls self-consistency: each addr must be in reachable
        # AND decode to an indirect-branch instruction.  No oracle equivalent
        # to compare against (oracle's _control_flow_walk drops `indirect`).
        ic_set = set(fa.indirect_calls)
        ic_ok = all(addr in fa.reachable for addr in ic_set)
        if ic_ok:
            field_counts["indirect_calls_self_consistent"] += 1
        else:
            per_field["indirect_calls"] = {
                "not_in_reachable": [f"0x{a:08X}" for a in ic_set - fa.reachable],
            }

        if per_field:
            divergences.append({
                "subseg_start": f"0x{start:08X}",
                "diff_fields": list(per_field.keys()),
                "details": per_field,
            })

    return {
        "subsegs_checked": checked,
        "field_counts": field_counts,
        "divergences": divergences,
        "match": not divergences,
    }


# ---------------------------------------------------------------------------
# Phase 5 parity: SweepState (forward-sweep / gaps / progress) vs the
# behavior eval_server currently produces inline via oracle's
# find_next_forward_sweep_candidate + _detect_internal_gaps +
# _compute_progress.
#
# Three checks:
#   A. natural_candidate() on current yaml  == oracle.find_next_forward_sweep_candidate
#   B. gaps() / progress() == eval_server._detect_internal_gaps / _compute_progress
#   C. Forward-sweep regression: remove each verified subseg from yaml,
#      run sweep, expect it to propose the removed subseg's start.
# ---------------------------------------------------------------------------

def _candidate_start_end(result):
    """Project either eval_server (prev_dict, FunctionEvidence) tuple or
    analyzer.NextCandidate to a comparable (prev_start, start, end) tuple."""
    if result is None:
        return None
    if isinstance(result, tuple):
        prev_dict, ev = result
        prev_start = prev_dict["start"] if prev_dict else None
        return (prev_start, ev.start, ev.end)
    # analyzer.NextCandidate
    prev_start = result.previous.start if result.previous else None
    return (prev_start, result.function.start, result.function.end)


def _gap_to_tuple(g):
    """Project either eval_server gap dict or analyzer.Gap to comparable shape."""
    if isinstance(g, dict):
        return (g["start"], g["end"], g["size"], g["preceding_start"], g["pending"])
    return (g.start, g.end, g.size, g.preceding_start, g.pending)


def run_phase5_parity(yaml_path: Path, project_root: Path) -> dict:
    model, ctx = _build_analyzer_model(yaml_path, project_root)
    sweep = analyzer.SweepState(model, ctx["cfg"], ai_override=None)

    # -- A. natural_candidate (no override) vs oracle.find_next_forward_sweep_candidate
    expected_next = oracle.find_next_forward_sweep_candidate(
        ctx["cfg"], ctx["binary"],
        pool_priors=ctx["pool_priors"],
        reference_starts=ctx["reference_starts"],
        static_callers=ctx["static_callers"],
        cross_module_callers=ctx["cross_module_callers"],
    )
    actual_next = sweep.natural_candidate()
    natural_match = (
        _candidate_start_end(expected_next) == _candidate_start_end(actual_next)
    )

    # -- B. gaps + progress
    expected_gaps_raw = eval_server._detect_internal_gaps(proposed_start=None)
    expected_gaps = [_gap_to_tuple(g) for g in expected_gaps_raw]
    actual_gaps = [_gap_to_tuple(g) for g in sweep.gaps(proposed_start=None)]
    gaps_match = expected_gaps == actual_gaps

    expected_progress = eval_server._compute_progress()
    actual_progress = sweep.progress()
    progress_match = (
        expected_progress["verified_bytes"] == actual_progress.verified_bytes
        and expected_progress["total_bytes"] == actual_progress.total_bytes
        and abs(expected_progress["pct"] - actual_progress.pct) < 1e-9
    )

    # -- C. Forward-sweep discoverability (INFORMATIONAL, not a parity check).
    # Remove each verified subseg, run sweep, see what it proposes.  Three
    # buckets:
    #   FOUND:   sweep proposes the removed subseg's start → naturally
    #              discoverable, the human could have stamped this without
    #              AI assistance.
    #   SKIPPED: sweep proposes a DIFFERENT verified subseg's start (a later
    #              one in the modified yaml) → sweep couldn't find the
    #              removed addr naturally and moved on to the next signal it
    #              could find.  Almost always means the removed stamp was
    #              originally landed via ai_override (no prologue, no
    #              caller signal, no reference label).  This is expected
    #              behavior — sweep is just doing its job.
    #   ANOMALY: sweep proposes a non-verified addr, or returns None →
    #              worth investigating; means sweep would land on an
    #              unstamped address (or nothing) where the human had
    #              previously stamped.
    cfg = ctx["cfg"]
    subsegs = sorted(
        [s for s in cfg.get("subsegments", []) if s.get("type") == "code"],
        key=lambda s: s["start"],
    )
    verified_starts = {s["start"] for s in subsegs}
    last_stamp_end = max(s["end"] for s in subsegs) if subsegs else None
    found = 0
    inside_removed = []         # sweep found a prologue INSIDE the removed function's original range
    skipped_to_verified = []    # sweep proposed a later verified subseg's start
    past_frontier = []          # sweep walked into unstamped territory (past last_stamp_end)
    anomalies = []
    for s in subsegs:
        modified = dict(cfg)
        modified["subsegments"] = [x for x in cfg.get("subsegments", []) if x is not s]
        sub_sweep = analyzer.SweepState(model, modified, ai_override=None)
        nc = sub_sweep.natural_candidate()
        if nc is None:
            anomalies.append({
                "removed": f"0x{s['start']:08X}",
                "result": "sweep returned None",
            })
            continue
        proposed = nc.function.start
        if proposed == s["start"]:
            found += 1
        elif s["start"] < proposed <= s["end"]:
            # Sweep snapped to a prologue-shaped pattern INSIDE the removed
            # function.  Common case: the human's stamp landed via
            # ai_override at a pre-prologue address (e.g. setup code before
            # the canonical sts.l pr push); without that hint, sweep finds
            # the natural prologue further in.
            inside_removed.append({
                "removed": f"0x{s['start']:08X}",
                "proposed": f"0x{proposed:08X}",
                "offset": proposed - s["start"],
            })
        elif proposed in verified_starts and proposed > s["start"]:
            skipped_to_verified.append({
                "removed": f"0x{s['start']:08X}",
                "sweep_jumped_to": f"0x{proposed:08X}",
            })
        elif last_stamp_end is not None and proposed > last_stamp_end:
            # Sweep walked past every stamp and landed on the first
            # unstamped-territory function.  Means no signal was findable
            # in stamped territory after the removed subseg — typical for
            # ai_override stamps near the end of the verified region.
            past_frontier.append({
                "removed": f"0x{s['start']:08X}",
                "proposed": f"0x{proposed:08X}",
            })
        else:
            anomalies.append({
                "removed": f"0x{s['start']:08X}",
                "proposed": f"0x{proposed:08X}",
                "proposed_is_verified": proposed in verified_starts,
            })

    return {
        "natural_match": natural_match,
        "expected_next": _candidate_start_end(expected_next),
        "actual_next": _candidate_start_end(actual_next),
        "gaps_match": gaps_match,
        "expected_gaps_count": len(expected_gaps),
        "actual_gaps_count": len(actual_gaps),
        "progress_match": progress_match,
        "expected_progress": expected_progress,
        "actual_progress": {
            "verified_bytes": actual_progress.verified_bytes,
            "total_bytes": actual_progress.total_bytes,
            "pct": actual_progress.pct,
        },
        "sweep_found": found,
        "sweep_inside_removed": inside_removed,
        "sweep_skipped_to_verified": skipped_to_verified,
        "sweep_past_frontier": past_frontier,
        "sweep_anomalies": anomalies,
        "sweep_total": len(subsegs),
        # Parity = A + B + (no real anomalies in C).  Inside-removed /
        # skipped-to-verified / past-frontier are all expected sweep
        # behaviors when stamps were originally landed via ai_override.
        "match": (
            natural_match and gaps_match and progress_match
            and not anomalies
        ),
    }


def _print_phase5(result: dict):
    print()
    print(f"PHASE 5 PARITY - SweepState (forward-sweep / gaps / progress)")
    a_status = "PASS" if result["natural_match"] else "FAIL"
    print(f"  {a_status}  natural_candidate vs oracle.find_next_forward_sweep_candidate")
    if not result["natural_match"]:
        print(f"        expected: {result['expected_next']}")
        print(f"        actual:   {result['actual_next']}")
    b1 = "PASS" if result["gaps_match"] else "FAIL"
    print(f"  {b1}  gaps() vs eval_server._detect_internal_gaps  ({result['expected_gaps_count']} expected, {result['actual_gaps_count']} actual)")
    b2 = "PASS" if result["progress_match"] else "FAIL"
    print(f"  {b2}  progress() vs eval_server._compute_progress  "
          f"({result['actual_progress']['verified_bytes']}/{result['actual_progress']['total_bytes']} bytes, "
          f"{result['actual_progress']['pct']:.4f}%)")
    sp = result["sweep_found"]
    st = result["sweep_total"]
    inside = len(result["sweep_inside_removed"])
    skipped = len(result["sweep_skipped_to_verified"])
    frontier = len(result["sweep_past_frontier"])
    an = len(result["sweep_anomalies"])
    c_status = "PASS" if an == 0 else "FAIL"
    print(f"  {c_status}  forward-sweep discoverability:  {sp}/{st} naturally found, "
          f"{inside} snap-to-inside-prologue, {skipped} skip-to-next-verified, "
          f"{frontier} walk-to-unstamped, {an} anomalies")
    if result["sweep_inside_removed"]:
        print(f"        INSIDE_REMOVED ({inside}) - sweep landed on a prologue inside the removed function's range:")
        for d in result["sweep_inside_removed"][:5]:
            print(f"          removed {d['removed']} -> proposed {d['proposed']}  (+{d['offset']} bytes)")
        if inside > 5:
            print(f"          ... and {inside - 5} more")
    if result["sweep_past_frontier"]:
        print(f"        PAST_FRONTIER ({frontier}) - sweep walked past all stamps into unstamped territory:")
        for d in result["sweep_past_frontier"][:5]:
            print(f"          removed {d['removed']} -> proposed {d['proposed']}")
        if frontier > 5:
            print(f"          ... and {frontier - 5} more")
    if result["sweep_skipped_to_verified"]:
        print(f"        SKIPPED_TO_VERIFIED ({skipped}) - sweep moved past these to the next verified subseg:")
        for d in result["sweep_skipped_to_verified"][:5]:
            print(f"          removed {d['removed']} -> sweep proposed {d['sweep_jumped_to']}")
        if skipped > 5:
            print(f"          ... and {skipped - 5} more")
    if result["sweep_anomalies"]:
        print(f"        ANOMALIES ({an}):")
        for d in result["sweep_anomalies"][:5]:
            print(f"          {d}")


def _print_phase4(result: dict):
    print()
    print(f"PHASE 4 PARITY - per-function enrichment (indent / indirect / reference / evidence / midpoints / phantom)")
    n = result["subsegs_checked"]
    print(f"  Subsegs checked: {n}")
    for field, count in result["field_counts"].items():
        status = "PASS" if count == n else "FAIL"
        print(f"  {status}  {field:32s}  {count}/{n}")
    d = result["divergences"]
    if not d:
        print(f"  PASS  all enrichment fields match for every subseg")
    else:
        print(f"  FAIL  {len(d)} subsegs have at least one divergence")
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
    p.add_argument("--phase", choices=["baseline", "phase1", "phase2", "phase3", "phase4", "phase5", "all"], default="baseline",
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

    if args.phase in ("phase4", "all"):
        result = run_phase4_parity(yaml_path, project_root)
        _print_phase4(result)
        if not result["match"]:
            sys.exit(1)

    if args.phase in ("phase5", "all"):
        result = run_phase5_parity(yaml_path, project_root)
        _print_phase5(result)
        if not result["match"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
