#!/usr/bin/env python3
"""eval_server.py — UI-only Flask server.

Consumes analyzer.py for every code-related question.  Owns only:
  - HTTP routes (Flask)
  - Session.json read/write (user verdict tracking + AI override)
  - Yaml read/write (verified subsegs)
  - Browser auto-open + Flask hot-reload integration
  - Row/candidate → JSON projection (keys.js wire format)

No decode_sh2 imports.  No pool detection.  No CFG walks.  No caller scans.
Every "what is at address X" question goes through analyzer.

Run from a project's root directory:
    python <SaturnAutoRE>/eval_server.py config/<binary>.yaml
"""

import argparse
import dataclasses
import json
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

import yaml
from flask import Flask, render_template, request, jsonify

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import analyzer

app = Flask(
    __name__,
    template_folder=str(SCRIPT_DIR / "templates"),
    static_folder=str(SCRIPT_DIR / "static"),
)

STATE = {
    "yaml_path": None,
    "project_root": None,
    "session_path": None,
    "model": None,            # cached analyzer.BinaryModel (process-lifetime)
}
LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Session persistence (user verdict + AI override state).
# Verbatim from eval_server.py — no code intelligence here.
# ---------------------------------------------------------------------------

def _empty_session():
    return {
        "history": [],
        "ai_override": None,
        "analyze_mode": None,
        "audit_mode": None,       # {"focus_start": int} when active; None otherwise
        "pending_partners": [],   # addrs queued via /queue-partner; applied on next approve
        "pending_entries": {},    # {main_hex: [addr, ...]} queued via /queue-entry; applied on next approve
    }


def load_session():
    p = STATE["session_path"]
    if p and p.exists():
        with open(p) as f:
            sess = json.load(f)
        # Legacy normalization: older sessions used a list for feedback.
        for entry in sess.get("history", []):
            fb = entry.get("feedback")
            if isinstance(fb, list):
                entry["feedback"] = "\n".join(fb) if fb else ""
            elif fb is None:
                entry["feedback"] = ""
        # Legacy normalization: pending_entries was briefly a flat list
        # bound at-poll-time to the current candidate.  Newer shape is
        # {main_hex: [addr, ...]} so the queue can't silently rebind
        # when the candidate changes.  Drop any legacy list — the user
        # re-queues with the explicit-main shape.
        if isinstance(sess.get("pending_entries"), list):
            sess["pending_entries"] = {}
        return sess
    return _empty_session()


def save_session(session):
    p = STATE["session_path"]
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(session, f, indent=2)


# ---------------------------------------------------------------------------
# Yaml mutation.  Verbatim from eval_server.
# ---------------------------------------------------------------------------

def _remove_subseg_from_yaml(start_addr):
    text = open(STATE["yaml_path"]).read()
    lines = text.splitlines(keepends=True)
    target = f"  - start: 0x{start_addr:08X}"
    out = []
    i = 0
    removed = False
    while i < len(lines):
        if lines[i].rstrip("\r\n") == target:
            i += 1
            while i < len(lines):
                stripped = lines[i].rstrip("\r\n")
                if stripped.startswith("  - ") or (stripped and not stripped.startswith("    ")):
                    break
                i += 1
            removed = True
            continue
        out.append(lines[i])
        i += 1
    if removed:
        with open(STATE["yaml_path"], "w") as f:
            f.writelines(out)
    return removed


def _insert_subseg_in_yaml(start_addr, end_addr, partners=None, entries=None,
                            subseg_type="code"):
    """Insert a subseg block at the address-sorted position.

    Subsegs are kept in start-address order on disk so the file reads
    top-to-bottom in memory order.  Inserts before the first existing
    subseg whose start > new start; appends if none qualifies.

    `subseg_type` is "code" (default) or "data".  Partners/entries are
    code-only — silently ignored when subseg_type == "data".
    """
    text = open(STATE["yaml_path"]).read()
    if not text.endswith("\n"):
        text += "\n"
    lines = text.splitlines(keepends=True)

    block = (
        f"  - start: 0x{start_addr:08X}\n"
        f"    type:  {subseg_type}\n"
        f"    end:   0x{end_addr:08X}\n"
    )
    if subseg_type == "code" and partners:
        partners_list = ", ".join(f"0x{p:08X}" for p in sorted(set(partners)))
        block += f"    partners: [{partners_list}]\n"
    if subseg_type == "code" and entries:
        entries_list = ", ".join(f"0x{e:08X}" for e in sorted(set(entries)))
        block += f"    entries: [{entries_list}]\n"

    insert_at = len(lines)
    for i, line in enumerate(lines):
        stripped = line.rstrip("\r\n")
        if stripped.startswith("  - start: 0x"):
            try:
                existing = int(stripped.split("0x", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            if existing > start_addr:
                insert_at = i
                break

    lines.insert(insert_at, block)
    with open(STATE["yaml_path"], "w") as f:
        f.writelines(lines)


def _add_partner_to_existing_subseg(subseg_start, new_partner):
    """In-place yaml edit: add `new_partner` to the partners list of the
    subseg whose start matches `subseg_start`.  Creates a new partners
    field if none exists.  Idempotent — won't duplicate an existing
    partner.

    Returns True on success, False if no matching subseg was found.
    """
    text = open(STATE["yaml_path"]).read()
    lines = text.splitlines(keepends=True)
    target = f"  - start: 0x{subseg_start:08X}"
    i = 0
    while i < len(lines):
        if lines[i].rstrip("\r\n") == target:
            # Found the subseg.  Scan its body lines for an existing
            # partners field; if found, parse and update; else, insert
            # a new partners line just before the next subseg or EOF.
            j = i + 1
            body_end = j
            partners_line_idx = None
            while body_end < len(lines):
                s = lines[body_end].rstrip("\r\n")
                if s.startswith("  - ") or (s and not s.startswith("    ")):
                    break
                if s.lstrip().startswith("partners:"):
                    partners_line_idx = body_end
                body_end += 1

            partner_hex = f"0x{new_partner:08X}"
            if partners_line_idx is not None:
                pline = lines[partners_line_idx]
                # Existing list: parse inside [...] and append if not present.
                lo = pline.find("[")
                hi = pline.find("]")
                if lo != -1 and hi != -1 and lo < hi:
                    existing = [t.strip() for t in pline[lo + 1 : hi].split(",") if t.strip()]
                    norm = [e.upper().replace("0X", "0x") for e in existing]
                    if partner_hex not in [n.replace("0x", "0x") for n in norm]:
                        existing.append(partner_hex)
                        new_inner = ", ".join(existing)
                        lines[partners_line_idx] = pline[: lo + 1] + new_inner + pline[hi:]
            else:
                indent = "    "
                lines.insert(body_end, f"{indent}partners: [{partner_hex}]\n")

            with open(STATE["yaml_path"], "w") as f:
                f.writelines(lines)
            return True
        i += 1
    return False


def _remove_entry_from_existing_subseg(subseg_start, entry):
    """In-place yaml edit: drop `entry` from the entries list of the
    subseg whose start matches `subseg_start`.  Removes the whole
    `entries:` line if it would become empty.

    Returns True if the entry was removed, False if not found or the
    subseg lacks an entries field.
    """
    text = open(STATE["yaml_path"]).read()
    lines = text.splitlines(keepends=True)
    target = f"  - start: 0x{subseg_start:08X}"
    i = 0
    while i < len(lines):
        if lines[i].rstrip("\r\n") == target:
            j = i + 1
            entries_line_idx = None
            while j < len(lines):
                s = lines[j].rstrip("\r\n")
                if s.startswith("  - ") or (s and not s.startswith("    ")):
                    break
                if s.lstrip().startswith("entries:"):
                    entries_line_idx = j
                    break
                j += 1
            if entries_line_idx is None:
                return False
            pline = lines[entries_line_idx]
            lo = pline.find("[")
            hi = pline.find("]")
            if lo == -1 or hi == -1 or lo >= hi:
                return False
            existing = [t.strip() for t in pline[lo + 1 : hi].split(",") if t.strip()]
            entry_norm = f"0x{entry:08X}".lower()
            kept = [e for e in existing if e.lower() != entry_norm]
            if len(kept) == len(existing):
                return False
            if kept:
                new_inner = ", ".join(kept)
                lines[entries_line_idx] = pline[: lo + 1] + new_inner + pline[hi:]
            else:
                del lines[entries_line_idx]
            with open(STATE["yaml_path"], "w") as f:
                f.writelines(lines)
            return True
        i += 1
    return False


def _find_overlapping_subsegs(new_start, new_end, exclude_start=None):
    """Return [(start, end), ...] for code subsegs whose [start, end]
    intersects [new_start, new_end].  When `exclude_start` is given,
    a subseg with exactly that start is omitted (used to ignore the
    candidate's own pre-existing entry when re-stamping).
    """
    cfg = _load_yaml_cfg()
    overlaps = []
    for sub in cfg.get("subsegments", []):
        if sub.get("type") != "code":
            continue
        s = int(sub["start"])
        e = int(sub["end"])
        if exclude_start is not None and s == exclude_start:
            continue
        if s <= new_end and e >= new_start:
            overlaps.append((s, e))
    return overlaps


# ---------------------------------------------------------------------------
# Analyzer plumbing — build model once at startup, build SweepState per request.
# ---------------------------------------------------------------------------

def _load_yaml_cfg():
    """Reload yaml from disk every call (cheap and catches user edits)."""
    with open(STATE["yaml_path"]) as f:
        return yaml.safe_load(f)


def _resolve_path(cfg_value):
    """Resolve a path string from cfg options against project_root."""
    if not cfg_value:
        return None
    p = Path(cfg_value)
    if not p.is_absolute():
        p = (STATE["project_root"] / p).resolve()
    return p


def _build_or_get_model(cfg):
    """Build BinaryModel once, cache on STATE.  Rebuilt only on Flask
    reload (which restarts the process and reinitializes STATE)."""
    if STATE["model"] is not None:
        return STATE["model"]

    options = cfg.get("options") or {}
    binary_path = STATE["project_root"] / options["target_path"]
    binary = open(binary_path, "rb").read()
    vram = int(options["vram"])

    priors_path = STATE["yaml_path"].parent / (STATE["yaml_path"].stem + ".pool_priors.txt")
    reference_dir = _resolve_path(options.get("reference_dir"))
    reference_scan_dir = _resolve_path(options.get("reference_scan_dir"))
    runtime_hits_dirs = []
    for d in (options.get("runtime_hits_dirs") or []):
        p = Path(d)
        if not p.is_absolute():
            p = (STATE["project_root"] / p).resolve()
        runtime_hits_dirs.append(p)

    STATE["model"] = analyzer.BinaryModel(
        binary=binary,
        vram=vram,
        pool_priors_path=priors_path if priors_path.exists() else None,
        reference_dir=reference_dir,
        reference_scan_dir=reference_scan_dir,
        runtime_hits_dirs=runtime_hits_dirs,
    )
    return STATE["model"]


def _build_sweep(session):
    """Construct a fresh SweepState for this request, honoring the
    current session.ai_override AND session.analyze_mode (the latter
    drives the outstanding-case-target scan as virtual stamps)."""
    cfg = _load_yaml_cfg()
    model = _build_or_get_model(cfg)
    return cfg, model, analyzer.SweepState(
        model, cfg,
        ai_override=session.get("ai_override"),
        analyze_mode=session.get("analyze_mode"),
        frontier_simulation=session.get("frontier_simulation", False),
        pending_entries=session.get("pending_entries") or {},
        pending_partners=session.get("pending_partners") or [],
    )


# ---------------------------------------------------------------------------
# Analyze mode — non-mutating exploration view.  Defines a multi-block
# function (e.g. a switch dispatcher + its disjoint case bodies) and lets
# the user navigate between blocks with ← / → keys.  Approval is disabled
# while active.  Mutually orthogonal to ai_override.
# ---------------------------------------------------------------------------

_ANALYZE_PREV_MAX_GAP = 512  # bytes — UI heuristic, not code intelligence


def _analyze_mode_active_candidate(model, sweep, analyze_mode):
    """Synthesize a NextCandidate from the active block.  Delegates the
    actual analysis to `model.analyze_multi_block`; this function's
    role is purely render-state shaping:

      - Picks the visual "previous" anchor (closest preceding verified
        subseg, dropped when more than _ANALYZE_PREV_MAX_GAP bytes away
        — no useful anchor that far).
    """
    blocks = analyze_mode.get("blocks") or []
    if not blocks:
        return None
    active = analyze_mode.get("active_block", 0) % len(blocks)
    start = int(blocks[active]["start"])

    fa = model.analyze_multi_block(blocks, active_block=active)

    previous = None
    for s in sweep.verified:
        if s.end < start and (previous is None or s.end > previous.end):
            previous = s
    if previous is not None and (start - previous.end - 1) > _ANALYZE_PREV_MAX_GAP:
        previous = None
    return analyzer.NextCandidate(previous=previous, function=fa)


# ---------------------------------------------------------------------------
# Audit mode — read-only walk over already-stamped functions.  No yaml
# mutation from inside audit mode except via /unstamp (the action audit
# exists to expose).  Mutually orthogonal to ai_override and analyze_mode;
# we 409 on conflicting endpoints while it's active.
# ---------------------------------------------------------------------------

def _audit_guard_response(session):
    """If audit_mode is active, return a (jsonify, 409) tuple that the
    caller can `return ...` immediately.  Else return None.  Used to
    keep audit-mode read-only against mutating endpoints (pin, queue,
    verdict, analyze-mode/*) so the UI can't land in a mixed state."""
    if session.get("audit_mode"):
        return jsonify({
            "ok": False,
            "error": "audit_mode is active — exit AUDIT before this action",
        }), 409
    return None


def _audit_mode_active(session):
    """Return the focus_start int if audit_mode is active, else None.
    Source-of-truth for "should I 409 this mutating endpoint?"."""
    am = session.get("audit_mode")
    if not am:
        return None
    try:
        return int(am.get("focus_start"))
    except (TypeError, ValueError):
        return None


def _audit_neighbor_start(verified_sorted, focus_start, direction):
    """Return the start addr of the verified subseg adjacent to focus_start
    in address-sorted order.  Clamps at the ends (no wraparound) — feels
    natural for an audit walk.  When focus_start is no longer in the
    list (stale after an external yaml edit), snaps to the last subseg
    (or None if the list is empty)."""
    starts = [s.start for s in verified_sorted]
    if focus_start not in starts:
        return starts[-1] if starts else None
    i = starts.index(focus_start)
    if direction == "next":
        return starts[min(i + 1, len(starts) - 1)]
    if direction == "prev":
        return starts[max(i - 1, 0)]
    return focus_start


def _audit_sorted_subsegs(sweep):
    """Unified sorted list of code + data subsegs for audit-mode
    navigation.  Audit walks both kinds — the user might want to
    unstamp a misclassified data range just as much as revisit a
    code stamp."""
    return sorted(
        list(sweep.verified) + list(sweep.verified_data),
        key=lambda s: s.start,
    )


def _audit_scrubber_payload(sweep, model):
    """Project every verified subseg → {start, hexes, name, size, verdict}.
    Verdict reuses the analyzer's cached analyze_function + partner-aware
    bump so the scrubber colors match what the user sees in the banner
    when they click that cell.  Fast because analyze_function is cached
    process-lifetime and pre-warmed at startup.

    Data subsegs use the synthetic Verdict.DATA so the scrubber cell
    can color them distinctly from code stamps."""
    out = []
    for sub in _audit_sorted_subsegs(sweep):
        if sub.type == "data":
            verdict = "DATA"
            name = f"DATA_{sub.start:08X}"
        else:
            fa = model.analyze_function(sub.start, hint_end=sub.end)
            fa = sweep.apply_partner_awareness(fa)
            verdict = fa.verdict.value
            name = f"FUN_{sub.start:08X}"
        out.append({
            "start": sub.start,
            "start_hex": f"{sub.start:08X}",
            "end_hex": f"{sub.end:08X}",
            "name": name,
            "size": sub.end - sub.start + 1,
            "verdict": verdict,
        })
    return out


def _audit_state_payload(session, sweep, model):
    """Build the audit-mode portion of /state when audit_mode is active.
    Returns (audit_dict, candidate_payload) or (None, None) if audit_mode
    is invalid (no stamps).

    When focus_start has gone stale (e.g. external yaml edit removed the
    focused subseg), snaps to the last subseg in-memory only — does NOT
    persist.  GET handlers stay read-only; the corrected focus will be
    persisted by the next mutating endpoint or by audit_mode/focus when
    the user navigates.  The in-memory mutation on `session` is harmless
    because /state never calls save_session on this object."""
    verified = _audit_sorted_subsegs(sweep)  # unified code + data list
    if not verified:
        return None, None
    focus_start = _audit_mode_active(session)
    starts = [s.start for s in verified]
    if focus_start is None or focus_start not in starts:
        focus_start = starts[-1]

    i = starts.index(focus_start)
    sub = verified[i]
    prev = verified[i - 1] if i > 0 else None
    prev_start = starts[i - 1] if i > 0 else None
    next_start = starts[i + 1] if i + 1 < len(starts) else None

    if sub.type == "data":
        # Synthetic FA for a focused data subseg — start/end + Verdict.DATA
        # is enough for listing() to short-circuit into raw-row emission,
        # for the banner to render a "DATA" verdict tag, and for the
        # unstamp button to fire on focus_start.
        fa = analyzer.FunctionAnalysis(
            start=sub.start,
            end=sub.end,
            prologue_range=(None, None),
            prologue_saved=[],
            prologue_stack=0,
            prologue_restored=[],
            prologue_restored_extras=[],
            epilogue_range=None,
            final_exit=None,
            delay_slot=None,
            branches=[],
            conditional_returns=[],
            pool_targets=[],
            reachable=set(),
            indirect_calls=[],
            verdict=analyzer.Verdict.DATA,
            yellow_flags=[],
            green_flags=[],
            flag_tooltips={},
            indent_depths={},
            indirect_resolutions={},
            reference=None,
            midpoints=[],
            evidence=analyzer.FunctionEvidence(
                static_callers=0,
                cross_module_callers=0,
                runtime_hits=0,
            ),
            phantom_hint=None,
        )
    else:
        # When frontier_simulation is ON, drop the saved-end cap so the
        # walker runs to natural CFG termination — answers "what would
        # the walker do today if this were the next unswept function?".
        # When OFF, hint_end clamps to the saved end and we backfill in
        # case the walker would have terminated early on its own.
        frontier = bool(session.get("frontier_simulation"))
        hint_end = None if frontier else sub.end
        fa = model.analyze_function(sub.start, hint_end=hint_end)
        if not frontier and fa.end != sub.end:
            fa = dataclasses.replace(fa, end=sub.end)
    payload = _build_candidate_payload(
        sweep, fa, prev,
        attn=None, pending_partners=None, pending_entries=None,
        is_live_candidate=False,
    )
    audit_dict = {
        "focus_start": focus_start,
        "focus_hex": f"{focus_start:08X}",
        "focus_index": i,
        "total": len(verified),
        "prev_start": prev_start,
        "prev_hex": f"{prev_start:08X}" if prev_start is not None else None,
        "next_start": next_start,
        "next_hex": f"{next_start:08X}" if next_start is not None else None,
    }
    return audit_dict, payload


def _analyze_mode_to_dict(analyze_mode):
    """Project session.analyze_mode → wire dict for the frontend.  Only
    called when analyze_mode is active (not None)."""
    blocks = analyze_mode.get("blocks") or []
    return {
        "active_block": analyze_mode.get("active_block", 0) % max(len(blocks), 1),
        "block_count": len(blocks),
        "blocks_summary": [
            {
                "start_hex": f"{int(b['start']):08X}",
                "end_hex":   f"{int(b['end']):08X}",
                "size":      int(b["end"]) - int(b["start"]) + 1,
            }
            for b in blocks
        ],
        "label": analyze_mode.get("label", ""),
    }


# ---------------------------------------------------------------------------
# Wire-format projections: analyzer types → JSON shape consumed by keys.js.
# ---------------------------------------------------------------------------

_ROWKIND_TO_WIRE = {
    "SECTION_HEADER": "section",
    "LABEL": "label",
    "INSTRUCTION": "instr",
    "POOL4": "pool",
    "POOL2": "pool",
    "PADDING": "raw",
    "RAW": "raw",
    "BLANK": "blank",
}

_CATEGORY_TO_CSS = {
    "RETURN": "cat-return",
    "CALL": "cat-call",
    "UNCOND_BRANCH": "cat-uncond",
    "COND_BRANCH": "cat-cond",
    "POOL_LOAD": "cat-pool",
    "COMPARE": "cat-compare",
    "OTHER": "cat-data",
}


def _row_to_dict(row):
    """Project an analyzer.ListingRow to the dict shape keys.js consumes.

    Each row's CSS class list is derived from the row's structural flags
    (kind, section, category, decoration booleans).  Classes come out
    sorted so output is stable across runs.
    """
    classes = []
    section_name = row.section.value if row.section else None
    kind_name = row.kind.name

    if kind_name == "SECTION_HEADER":
        if section_name:
            classes.append(f"section-{section_name}-header")
    elif section_name:
        classes.append(f"section-{section_name}")

    if kind_name == "LABEL":
        classes.append("label")
    if kind_name in ("POOL4", "POOL2"):
        classes.append("pool")

    if row.is_prologue:        classes.append("prologue")
    if row.is_epilogue:        classes.append("epilogue")
    if row.is_final_rts:       classes.append("final-rts")
    if row.is_conditional_rts: classes.append("cond-rts")
    if row.is_unreachable:     classes.append("unreachable")
    if row.is_tail_call:       classes.append("tail-call")
    if row.is_indirect_branch: classes.append("uncond-indirect")
    if row.is_alt_entry:       classes.append("alt-entry")
    if row.category is not None:
        cat_cls = _CATEGORY_TO_CSS.get(row.category.name)
        if cat_cls:
            classes.append(cat_cls)

    # addr_str: empty for section headers and label-only rows
    # (keys.js renders the label string as the visible content; the
    # addr column is hidden for those kinds).
    if kind_name in ("SECTION_HEADER", "LABEL"):
        addr_str = ""
    elif row.addr is not None:
        addr_str = f"{row.addr:08X}"
    else:
        addr_str = ""

    # Wire-format field gating to match eval_server's existing JSON shape.
    # Eval_server's row dicts have OPTIONAL keys — keys are absent when
    # not relevant for the kind+section.  Matching that so keys.js sees
    # identical input from both servers:
    #
    #   SECTION_HEADER:
    #     kind, anchor_addr, addr_str, label, bytes, mnem, margin, classes
    #     (NO addr, NO indent, NO tag, NO branch)
    #
    #   LABEL / INSTRUCTION / POOL4 / POOL2 in a FUNCTION section
    #   (PREV or CURRENT — _emit_function_lines's emission):
    #     addr, addr_str, kind, label, bytes, mnem, classes, margin, indent
    #     (+ optional tag, branch)
    #
    #   POOL4 / POOL2 / RAW in INTERMEDIATE or TRAILING
    #   (_emit_raw_bytes's emission — no indent column there):
    #     addr, addr_str, kind, label, bytes, mnem, classes, margin
    #     (NO indent, NO tag, NO branch)
    #
    is_function_section = section_name in ("prev", "current")

    out = {
        "kind": _ROWKIND_TO_WIRE[kind_name],
        "addr_str": addr_str,
        "bytes": row.bytes_hex,
        "mnem": row.text,
        "label": row.label,
        "margin": row.margin,
        "classes": sorted(set(classes)),
    }
    if kind_name != "SECTION_HEADER":
        out["addr"] = row.addr
    if kind_name != "SECTION_HEADER" and is_function_section:
        out["indent"] = row.indent
    if row.tag and kind_name != "SECTION_HEADER" and is_function_section:
        out["tag"] = row.tag
    if kind_name == "SECTION_HEADER":
        out["anchor_addr"] = row.anchor_addr
    if (row.branch_target is not None and row.branch_type is not None
            and is_function_section):
        out["branch"] = {
            "target": row.branch_target,
            "type": row.branch_type,
            "direction": row.branch_direction,
            "internal": row.branch_internal,
        }
    # Walker-stop confidence on bra/jmp/braf rows — drives tag tooltip
    # in the frontend.  Only set for instruction rows the walker
    # examined as potential tail calls.
    if row.tag_tooltip and is_function_section:
        out["tag_tooltip"] = row.tag_tooltip
    # Tentative instruction decode on POOL2 rows — lets the client
    # show a pale "preview" of what the bytes WOULD mean if they
    # were code, so the user can spot real functions hiding in
    # data classification.
    if row.tentative_decode:
        out["tentative_decode"] = row.tentative_decode
    if row.stop_confidence and is_function_section:
        out["stop_confidence"] = row.stop_confidence
    # Structured callers on "Called from FUN_X" label rows — lets the
    # frontend color each caller name by kind (stamped/partner/analyze).
    if row.callers:
        out["callers"] = list(row.callers)
    return out


def _reference_to_dict(ref):
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


def _midpoint_to_dict(m):
    return {
        "addr": m.addr,
        "addr_hex": f"{m.addr:08X}",
        "static_callers": m.static_callers,
        "cross_module_callers": m.cross_module_callers,
        "runtime_hits": m.runtime_hits,
    }


def _candidate_to_dict(fa, partners=None, pending_partners=None,
                        suggested_partners=None, entries=None,
                        pending_entries=None):
    """Project analyzer.FunctionAnalysis to the candidate dict the
    banner renderer (keys.js renderCandidateBanner) consumes.

    `partners` is the list of int addrs from the yaml subseg's partners
    field (when this candidate is already stamped).  `pending_partners`
    is the session-queued list (added via /queue-partner before approval
    and applied on next approve).  `suggested_partners` is the
    analyzer-derived list of likely partner addrs based on stack
    imbalance signals — the UI renders one button per suggestion.
    `entries` is the list of int alt-entry addrs from the yaml subseg's
    entries field (when this candidate is already stamped) — multi-
    entry functions where several callable entries share one body.
    """
    return {
        "start_hex": f"{fa.start:08X}",
        "start": fa.start,
        "end_hex": f"{fa.end:08X}",
        "end": fa.end,
        "size": fa.end - fa.start + 1,
        "verdict": fa.verdict.value,
        "yellow_flags": list(fa.yellow_flags),
        "green_flags": list(fa.green_flags),
        "flag_tooltips": dict(fa.flag_tooltips or {}),
        "name": f"FUN_{fa.start:08X}",
        "reference": _reference_to_dict(fa.reference),
        "evidence": {
            "static_callers": fa.evidence.static_callers,
            "cross_module_callers": fa.evidence.cross_module_callers,
            "runtime_hits": fa.evidence.runtime_hits,
            "midpoints": [_midpoint_to_dict(m) for m in fa.midpoints],
        },
        "partners": [{"addr": p, "addr_hex": f"{p:08X}"} for p in (partners or [])],
        # pending_partners may arrive as plain int addrs (legacy callers)
        # or as {addr, end} dicts (when the caller resolved ranges via
        # `_resolve_partner_end`).  Normalize to the wire format with
        # both `addr` and `end` populated; `end` is None when the
        # caller didn't / couldn't resolve.
        "pending_partners": [
            {
                "addr": (p["addr"] if isinstance(p, dict) else p),
                "addr_hex": f"{(p['addr'] if isinstance(p, dict) else p):08X}",
                "end": (p.get("end") if isinstance(p, dict) else None),
            }
            for p in (pending_partners or [])
        ],
        "suggested_partners": list(suggested_partners or []),
        "partner_balanced": bool(getattr(fa, "partner_balanced", False)),
        "entries": [{"addr": e, "addr_hex": f"{e:08X}"} for e in (entries or [])],
        "pending_entries": [
            {"addr": e, "addr_hex": f"{e:08X}"} for e in (pending_entries or [])
        ],
    }


def _previous_to_dict(prev):
    if prev is None:
        return None
    return {
        "start_hex": f"{prev.start:08X}",
        "name": f"FUN_{prev.start:08X}",
    }


def _progress_to_dict(p):
    return {
        "verified_bytes": p.verified_bytes,
        "total_bytes": p.total_bytes,
        "pct": p.pct,
    }


def _gap_to_dict(g):
    return {
        "start": g.start,
        "end": g.end,
        "start_hex": f"{g.start:08X}",
        "end_hex": f"{g.end:08X}",
        "size": g.size,
        "preceding_start": g.preceding_start,
        "preceding_start_hex": f"{g.preceding_start:08X}",
        "preceding_end_hex": f"{g.start - 1:08X}",  # gap.start - 1 = preceding's end
        "preceding_name": g.preceding_name,
        "pending": g.pending,
    }


def _resolve_partner_end(sweep, addr):
    """Resolve a queued partner addr to its end addr: stamped subseg's
    end if verified, else CFG walker via model.analyze_function.
    Returns None on failure (bogus addr, walker exception)."""
    for s in sweep.verified:
        if s.start == addr:
            return s.end
    try:
        return sweep.model.analyze_function(addr).end
    except Exception:
        return None


def _build_candidate_payload(sweep, candidate_fa, previous_typed,
                              attn=None, pending_partners=None,
                              pending_entries=None,
                              is_live_candidate=True):
    """Build the per-pane payload (banner + listing rows).  Mirrors
    eval_server._build_candidate_payload's output shape.

    Partners (from yaml) are looked up by candidate's start; pending
    partners (session-queued) are passed in by the caller.

    `is_live_candidate` forwards to sweep.listing so the analyzer
    knows whether to apply the pending-partners caller-tag for this
    pane.  Audit panes pass False — the queue is tied to the next-
    approve target, not whichever stamp the audit walk focuses on.
    """
    rows = sweep.listing(candidate_fa, previous=previous_typed, attn=attn,
                          is_live_candidate=is_live_candidate)
    partners = []
    entries = []
    for s in sweep.verified:
        if s.start == candidate_fa.start:
            partners = list(s.partners or [])
            entries = list(s.entries or [])
            break
    # UI partner suggestions come from back-references only: stamps
    # whose `partners` list already includes this candidate's start,
    # i.e. functions that asserted "this is my partner" before we
    # got here.  Surfacing them lets the human partner back with one
    # click (the /verdict approve also auto-back-refs them on its
    # own, but having the button gives explicit visibility while
    # reviewing the candidate).  The analyzer's heuristic-based
    # sweep.suggested_partners is still used internally for the
    # walker-stop tooltip's partner_ranges, but isn't surfaced
    # here — it produced too many false positives to be worth the
    # button noise.
    suggestions = []
    for s in sweep.verified:
        if candidate_fa.start in (s.partners or []):
            suggestions.append({
                "addr": s.start,
                "addr_hex": f"{s.start:08X}",
                "reason": f"FUN_{s.start:08X} already lists this function as a partner — click to mirror the link.",
            })
    # Trailing-zone warnings: surface a yellow flag when the candidate
    # ends right before case targets of an existing stamped dispatcher
    # — strong signal that the boundary is too short.
    trailing_flags = sweep.check_trailing_zone_case_targets(candidate_fa)
    if trailing_flags:
        candidate_fa = dataclasses.replace(
            candidate_fa,
            yellow_flags=list(candidate_fa.yellow_flags) + trailing_flags,
        )
    # In-candidate suspected-entry warnings: lists hex addresses of
    # prologue / pool4 hits inside the candidate.  Critical for big
    # runaway stamps where the listing is thousands of lines and
    # the user would otherwise have to hunt for the inline hints.
    inside_flags = sweep.check_suspected_fn_entries_inside(candidate_fa)
    if inside_flags:
        candidate_fa = dataclasses.replace(
            candidate_fa,
            yellow_flags=list(candidate_fa.yellow_flags) + inside_flags,
        )
    # Apply partner-aware verdict: suppress imbalance flags when the
    # combined stack frame across this function + its partners is
    # balanced.  Happens AFTER listing emission (listing doesn't use
    # verdict/flags so the order is safe).
    candidate_fa = sweep.apply_partner_awareness(candidate_fa)
    # Resolve each queued partner's (start, end) range so the client
    # can draw partner-pending arcs for branches whose target lands
    # ANYWHERE inside a partner's body, not just at its exact start.
    pending_partners_resolved = [
        {"addr": p, "end": _resolve_partner_end(sweep, p)}
        for p in (pending_partners or [])
    ]
    return {
        "candidate": _candidate_to_dict(
            candidate_fa,
            partners=partners,
            pending_partners=pending_partners_resolved,
            suggested_partners=suggestions,
            entries=entries,
            pending_entries=pending_entries,
        ),
        "previous": _previous_to_dict(previous_typed),
        "lines": [_row_to_dict(r) for r in rows],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("candidate.html")


@app.route("/state")
def state():
    """Polled by the browser every ~1s.  Returns current candidate + UI state."""
    with LOCK:
        session = load_session()
        cfg, model, sweep = _build_sweep(session)
        history = session.get("history", [])

        # Parse attn early — passed to listing() so rows get is_attn flags.
        ov = session.get("ai_override") or {}
        attn_raw = ov.get("attn") or []
        attn_addrs = []
        for a in attn_raw:
            try:
                attn_addrs.append(analyzer._coerce_addr(a))
            except (ValueError, TypeError):
                pass

        progress = _progress_to_dict(sweep.progress())

        # Audit mode short-circuits the live-sweep path: we render the
        # focused stamp's analysis instead of next_candidate, and ship
        # the scrubber payload for the bottom-of-bar bar.
        if session.get("audit_mode"):
            audit_dict, audit_payload = _audit_state_payload(session, sweep, model)
            if audit_dict is None:
                # No verified subsegs — drop out of audit and fall through
                # to the normal caught-up / next_candidate path.
                session["audit_mode"] = None
                save_session(session)
            else:
                return jsonify({
                    "all_caught_up": False,
                    "candidate": audit_payload["candidate"],
                    "previous":  audit_payload["previous"],
                    "lines":     audit_payload["lines"],
                    "natural_view": None,
                    "override_active": False,
                    "start_pinned": False,
                    "end_pinned":   False,
                    "attn": [],
                    "current_verdict": None,
                    "history_count": len(history),
                    "progress": progress,
                    "internal_gaps": [],   # suppressed in audit, like analyze_mode
                    "analyze_mode": None,
                    "audit_mode": audit_dict,
                    "scrubber": _audit_scrubber_payload(sweep, model),
                    "frontier_simulation": bool(session.get("frontier_simulation", False)),
                })

        analyze_mode = session.get("analyze_mode")
        if analyze_mode:
            nxt = _analyze_mode_active_candidate(model, sweep, analyze_mode)
            if nxt is None:
                return jsonify({"all_caught_up": False, "error": "analyze_mode has no blocks"}), 400
        else:
            nxt = sweep.next_candidate()

        if nxt is None:
            return jsonify({
                "all_caught_up": True,
                "history_count": len(history),
                "progress": progress,
                "internal_gaps": [_gap_to_dict(g) for g in sweep.gaps()],
                "audit_mode": None,
                "scrubber": None,
            })

        # Internal gaps with pending gap to proposed candidate surfaced too.
        # Suppressed in analyze_mode (the ANALYZE MODE banner takes the slot).
        if analyze_mode:
            internal_gaps = []
        else:
            internal_gaps = [_gap_to_dict(g) for g in sweep.gaps(proposed_start=nxt.function.start)]

        pending_partners = list(session.get("pending_partners") or [])
        # Pending entries are keyed by main_hex; project only the bucket
        # belonging to the current candidate so the banner / listing
        # only show queue state relevant to what the user is viewing.
        all_pending_entries = session.get("pending_entries") or {}
        main_hex = f"0x{nxt.function.start:08X}"
        pending_entries = list(all_pending_entries.get(main_hex) or [])
        primary_payload = _build_candidate_payload(
            sweep, nxt.function, nxt.previous,
            attn=attn_addrs, pending_partners=pending_partners,
            pending_entries=pending_entries,
        )

        # Natural pane (for split view) — only when override is active AND
        # the natural candidate differs in start OR end.  Suppressed
        # when analyze_mode is active (the user is exploring a synthetic
        # multi-block candidate, not comparing against the sweep).
        natural_view = None
        if session.get("ai_override") and not analyze_mode:
            nat = sweep.natural_candidate()
            if nat is not None and (
                nat.function.start != nxt.function.start
                or nat.function.end != nxt.function.end
            ):
                natural_view = _build_candidate_payload(
                    sweep, nat.function, nat.previous, attn=attn_addrs,
                    is_live_candidate=False,
                )

        # "What verdict did I last leave this candidate at" — surfaced so the
        # reject/unsure button keeps its `pressed` state across polls.
        current_verdict = None
        last = history[-1] if history else None
        if (last is not None
                and last.get("candidate_start") == nxt.function.start
                and last.get("verdict") in ("rejected", "unsure")):
            current_verdict = last["verdict"]

        return jsonify({
            "all_caught_up": False,
            "candidate": primary_payload["candidate"],
            "previous":  primary_payload["previous"],
            "lines":     primary_payload["lines"],
            "natural_view": natural_view,
            "override_active": bool(session.get("ai_override")),
            "start_pinned": "candidate_start" in ov,
            "end_pinned":   "candidate_end"   in ov,
            "attn": attn_addrs,
            "current_verdict": current_verdict,
            "history_count": len(history),
            "progress": progress,
            "internal_gaps": internal_gaps,
            "analyze_mode": _analyze_mode_to_dict(analyze_mode) if analyze_mode else None,
            "audit_mode": None,
            "scrubber": None,
            "frontier_simulation": bool(session.get("frontier_simulation", False)),
        })


@app.route("/pin-end", methods=["POST"])
def pin_end():
    """Pin current candidate's end to the byte BEFORE `next_start`.
    Validation routes through analyzer (no inline code analysis)."""
    data = request.get_json(force=True)
    raw = data.get("next_start")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'next_start'"}), 400
    try:
        next_start = analyzer._coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400

    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        cfg, model, sweep = _build_sweep(session)
        nxt = sweep.next_candidate()
        if nxt is None:
            return jsonify({"ok": False, "error": "no current candidate"}), 400

        new_end = next_start - 1
        if new_end <= nxt.function.start:
            return jsonify({
                "ok": False,
                "error": (f"next_start 0x{next_start:08X} must be after candidate "
                          f"start 0x{nxt.function.start:08X}"),
            }), 400
        # Reject if next_start lands STRICTLY INSIDE an already-verified
        # subseg.  Pinning AT an existing stamp's start is fine — that's
        # the user saying "my candidate ends right before this next
        # function begins," which is exactly the adjacency we want.
        for s in sweep.verified:
            if s.start < next_start <= s.end:
                return jsonify({
                    "ok": False,
                    "error": f"next_start 0x{next_start:08X} is inside verified subseg FUN_{s.start:08X}",
                }), 400

        override = dict(session.get("ai_override") or {})
        override["candidate_start"] = f"0x{nxt.function.start:08X}"
        override["candidate_end"] = f"0x{new_end:08X}"
        if "previous_subseg" not in override and nxt.previous is not None:
            override["previous_subseg"] = {
                "start": nxt.previous.start,
                "end": nxt.previous.end,
                "type": nxt.previous.type,
                "file": nxt.previous.file,
            }
        session["ai_override"] = override
        save_session(session)
    return jsonify({"ok": True, "candidate_end": f"0x{new_end:08X}"})


@app.route("/pin-start", methods=["POST"])
def pin_start():
    """Pin current candidate's start.  Replaces any existing override."""
    data = request.get_json(force=True)
    raw = data.get("addr")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'addr'"}), 400
    try:
        addr = analyzer._coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400

    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        cfg, model, sweep = _build_sweep(session)
        # Reject if addr lands inside an already-verified subseg.
        for s in sweep.verified:
            if s.start <= addr <= s.end:
                return jsonify({
                    "ok": False,
                    "error": f"addr 0x{addr:08X} is inside verified subseg FUN_{s.start:08X}",
                }), 400
        # Find immediately-preceding verified subseg.
        prev = max(
            (s for s in sweep.verified if s.end < addr),
            key=lambda s: s.end,
            default=None,
        )

        override = {"candidate_start": f"0x{addr:08X}"}
        if prev is not None:
            override["previous_subseg"] = {
                "start": prev.start,
                "end": prev.end,
                "type": prev.type,
                "file": prev.file,
            }
        session["ai_override"] = override
        save_session(session)
    return jsonify({"ok": True, "candidate_start": f"0x{addr:08X}"})


@app.route("/unpin-end", methods=["POST"])
def unpin_end():
    """Remove only candidate_end from ai_override.  If the resulting
    override is meaningfully empty, clear it entirely."""
    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        override = dict(session.get("ai_override") or {})
        had_end = "candidate_end" in override
        override.pop("candidate_end", None)
        # Keep override only if there's still something useful pinned.
        keep = bool(override.get("candidate_start")) and (
            "attn" in override or "previous_subseg" in override
        )
        session["ai_override"] = override if keep else None
        save_session(session)
    return jsonify({"ok": True, "had_end": had_end})


@app.route("/unpin-all", methods=["POST"])
def unpin_all():
    """Clear the entire ai_override."""
    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        had_override = bool(session.get("ai_override"))
        session["ai_override"] = None
        save_session(session)
    return jsonify({"ok": True, "had_override": had_override})


@app.route("/frontier/toggle", methods=["POST"])
def frontier_toggle():
    """Flip the frontier_simulation flag.  When on, the walker is
    capped only by natural CFG termination — future stamps don't leak
    into the cap.  Use during audit walks to see what the analyzer
    would propose if THIS were the next unswept function."""
    data = request.get_json(force=True) or {}
    with LOCK:
        session = load_session()
        if "on" in data:
            new_val = bool(data["on"])
        else:
            new_val = not bool(session.get("frontier_simulation", False))
        session["frontier_simulation"] = new_val
        save_session(session)
    return jsonify({"ok": True, "frontier_simulation": new_val})


@app.route("/queue-partner", methods=["POST"])
def queue_partner():
    """Queue a partner address for the next /verdict approve.  Toggles
    if the addr is already queued.  Pure session mutation — no yaml
    write until approve is clicked.

    Used by the UI's '+ Partner FUN_xxxxxxxx' button.  Multiple partners
    can be queued for one approve.
    """
    data = request.get_json(force=True)
    raw = data.get("partner")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'partner'"}), 400
    try:
        addr = analyzer._coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400
    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        pending = list(session.get("pending_partners") or [])
        if addr in pending:
            pending.remove(addr)
            action = "removed"
        else:
            pending.append(addr)
            action = "added"
        session["pending_partners"] = pending
        save_session(session)
    return jsonify({"ok": True, "action": action, "pending_partners": [f"0x{p:08X}" for p in pending]})


@app.route("/queue-entry", methods=["POST"])
def queue_entry():
    """Queue an alt entry for the current candidate.  Toggles if the
    addr is already queued.  Pure session mutation — no yaml write
    until /verdict approve.

    Pending entries are stored as `{main_hex: [addr, ...]}` keyed by
    the candidate's start at queue time.  The binding is explicit and
    survives candidate-identity changes (a queue for FUN_X sits
    dormant when you context-switch to FUN_Y and reappears when you
    come back).  SweepState attaches them to `alt_entry_main` so the
    analyzer (walker, midpoints, confidence) treats them as declared
    entries during /state — letting the human audit the multi-entry
    shape before stamping.

    Validates the entry sits strictly inside the current candidate's
    range and doesn't fall in another stamped subseg.  Rejected while
    analyze_mode is active (no candidate identity to bind to).
    """
    data = request.get_json(force=True)
    raw = data.get("entry")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'entry'"}), 400
    try:
        addr = analyzer._coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400
    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        if session.get("analyze_mode"):
            return jsonify({
                "ok": False,
                "error": "analyze_mode is active — exit ANALYZE MODE before queueing entries",
            }), 409
        cfg, model, sweep = _build_sweep(session)
        nxt = sweep.next_candidate()
        if nxt is None:
            return jsonify({"ok": False, "error": "no current candidate"}), 400
        cand_start = nxt.function.start
        cand_end = nxt.function.end
        main_hex = f"0x{cand_start:08X}"
        # pending_entries is dict-shape (per-main).  Legacy list-shape
        # would have been migrated to {} by load_session.
        all_pending = dict(session.get("pending_entries") or {})
        bucket = list(all_pending.get(main_hex) or [])
        if addr in bucket:
            bucket.remove(addr)
            action = "removed"
        else:
            if not (cand_start < addr <= cand_end):
                return jsonify({
                    "ok": False,
                    "error": (f"entry 0x{addr:08X} must sit strictly inside the "
                              f"current candidate (0x{cand_start:08X}, 0x{cand_end:08X}]"),
                }), 400
            for s in sweep.verified:
                if s.start == cand_start:
                    continue
                if s.start <= addr <= s.end:
                    return jsonify({
                        "ok": False,
                        "error": f"entry 0x{addr:08X} falls inside another stamped subseg FUN_{s.start:08X}",
                    }), 400
            bucket.append(addr)
            action = "added"
        if bucket:
            all_pending[main_hex] = bucket
        else:
            all_pending.pop(main_hex, None)
        session["pending_entries"] = all_pending
        save_session(session)
    return jsonify({
        "ok": True,
        "action": action,
        "main": main_hex,
        "pending_entries": [f"0x{p:08X}" for p in bucket],
    })


@app.route("/add-partner", methods=["POST"])
def add_partner():
    """Add a partner cross-reference to an EXISTING stamped subseg.
    For retroactive partnering — when a relationship is discovered
    after both functions have already been stamped.

    Symmetric: also adds the back-reference on the partner's subseg
    (if it exists in the yaml).  Idempotent.
    """
    data = request.get_json(force=True)
    raw_a = data.get("start")
    raw_b = data.get("partner")
    if raw_a is None or raw_b is None:
        return jsonify({"ok": False, "error": "need 'start' and 'partner'"}), 400
    try:
        a = analyzer._coerce_addr(raw_a)
        b = analyzer._coerce_addr(raw_b)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400
    if a == b:
        return jsonify({"ok": False, "error": "a function can't partner with itself"}), 400
    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        ok_a = _add_partner_to_existing_subseg(a, b)
        ok_b = _add_partner_to_existing_subseg(b, a)
    if not ok_a:
        return jsonify({"ok": False, "error": f"no subseg at 0x{a:08X}"}), 404
    return jsonify({
        "ok": True,
        "updated": [f"0x{a:08X}"] + ([f"0x{b:08X}"] if ok_b else []),
        "back_ref_skipped": not ok_b,
    })


@app.route("/remove-entry", methods=["POST"])
def remove_entry():
    """Remove an alt entry from a stamped subseg's `entries:` list.
    Backout-only — golden path for adding entries is queue+approve
    via /queue-entry; this exists for retroactive correction when an
    already-stamped function shouldn't have had a given alt entry."""
    data = request.get_json(force=True)
    raw_main = data.get("main")
    raw_entry = data.get("entry")
    if raw_main is None or raw_entry is None:
        return jsonify({"ok": False, "error": "need 'main' and 'entry'"}), 400
    try:
        main = analyzer._coerce_addr(raw_main)
        entry = analyzer._coerce_addr(raw_entry)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400
    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        removed = _remove_entry_from_existing_subseg(main, entry)
    if not removed:
        return jsonify({"ok": False, "error": f"entry 0x{entry:08X} not found on FUN_{main:08X}"}), 404
    return jsonify({"ok": True, "main": f"0x{main:08X}", "entry": f"0x{entry:08X}"})


@app.route("/unstamp", methods=["POST"])
def unstamp():
    """Re-dirty a previously verified subseg so forward-sweep proposes
    it again on the next /state poll."""
    data = request.get_json(force=True)
    raw = data.get("start")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'start'"}), 400
    try:
        addr = analyzer._coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400
    with LOCK:
        session = load_session()
        # Snapshot pre-unstamp neighbors so we can advance audit focus
        # WITHOUT re-reading yaml after the mutation.  Sweep here reflects
        # the yaml state BEFORE removal.
        prev_focus = next_focus = None
        if session.get("audit_mode"):
            cfg, model, sweep = _build_sweep(session)
            starts = [s.start for s in _audit_sorted_subsegs(sweep)]
            if addr in starts:
                i = starts.index(addr)
                prev_focus = starts[i - 1] if i > 0 else None
                next_focus = starts[i + 1] if i + 1 < len(starts) else None
        removed = _remove_subseg_from_yaml(addr)
        if not removed:
            return jsonify({"ok": False, "error": f"no subseg found with start 0x{addr:08X}"}), 404
        # Audit-mode focus follow-up: prefer prev (keeps audit walks
        # going backwards-through-time), fall back to next, exit audit
        # if nothing remains.  Only runs when the unstamped addr was the
        # current focus.
        am = session.get("audit_mode") or {}
        cur = am.get("focus_start")
        if am and cur == addr:
            new_focus = prev_focus if prev_focus is not None else next_focus
            if new_focus is None:
                session["audit_mode"] = None
            else:
                session["audit_mode"] = {"focus_start": new_focus}
            save_session(session)
    return jsonify({"ok": True, "unstamped": f"0x{addr:08X}"})


@app.route("/audit-mode/enter", methods=["POST"])
def audit_mode_enter():
    """Enter AUDIT MODE.  Focuses the last (highest-address) verified
    subseg; the user walks back/forward with ←/→ or clicks the scrubber.
    Refuses if zero stamps exist."""
    with LOCK:
        session = load_session()
        # Build a one-shot sweep just to read verified.  Cheap.
        cfg, model, sweep = _build_sweep(session)
        all_subsegs = _audit_sorted_subsegs(sweep)
        if not all_subsegs:
            return jsonify({"ok": False, "error": "no verified subsegs to audit"}), 409
        focus = all_subsegs[-1].start
        session["audit_mode"] = {"focus_start": focus}
        # AUDIT and ai_override / analyze_mode are mutually exclusive;
        # entering audit clears them so the UI can't land in a mixed state.
        session["ai_override"] = None
        session["analyze_mode"] = None
        save_session(session)
    return jsonify({"ok": True, "focus_start": f"0x{focus:08X}"})


@app.route("/audit-mode/exit", methods=["POST"])
def audit_mode_exit():
    """Exit AUDIT MODE — clears session['audit_mode'].  Sweep resumes
    wherever it was.  Idempotent."""
    with LOCK:
        session = load_session()
        had = bool(session.get("audit_mode"))
        session["audit_mode"] = None
        save_session(session)
    return jsonify({"ok": True, "was_active": had})


@app.route("/audit-mode/focus", methods=["POST"])
def audit_mode_focus():
    """Jump audit focus to the verified subseg with the given start.
    Used by scrubber clicks.  Rejects if the address isn't a verified
    subseg start."""
    data = request.get_json(force=True)
    raw = data.get("start")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'start'"}), 400
    try:
        addr = analyzer._coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400
    with LOCK:
        session = load_session()
        if not session.get("audit_mode"):
            return jsonify({"ok": False, "error": "not in audit_mode"}), 409
        cfg, model, sweep = _build_sweep(session)
        all_subsegs = _audit_sorted_subsegs(sweep)
        if not any(s.start == addr for s in all_subsegs):
            return jsonify({"ok": False, "error": f"0x{addr:08X} is not a verified subseg start"}), 404
        session["audit_mode"] = {"focus_start": addr}
        save_session(session)
    return jsonify({"ok": True, "focus_start": f"0x{addr:08X}"})


@app.route("/audit-mode/cycle", methods=["POST"])
def audit_mode_cycle():
    """Advance audit focus to the address-adjacent verified subseg.
    Clamps at the ends (no wrap) — at the last stamp, 'next' is a no-op.
    Wired to ←/→ keys and the arrow buttons."""
    data = request.get_json(force=True)
    direction = data.get("direction")
    if direction not in ("next", "prev"):
        return jsonify({"ok": False, "error": "direction must be 'next' or 'prev'"}), 400
    with LOCK:
        session = load_session()
        am = session.get("audit_mode")
        if not am:
            return jsonify({"ok": False, "error": "not in audit_mode"}), 409
        cfg, model, sweep = _build_sweep(session)
        all_subsegs = _audit_sorted_subsegs(sweep)
        if not all_subsegs:
            session["audit_mode"] = None
            save_session(session)
            return jsonify({"ok": False, "error": "no verified subsegs"}), 409
        focus = int(am.get("focus_start") or 0)
        new_focus = _audit_neighbor_start(all_subsegs, focus, direction)
        if new_focus is None:
            return jsonify({"ok": False, "error": "no verified subsegs"}), 409
        session["audit_mode"] = {"focus_start": new_focus}
        save_session(session)
    return jsonify({"ok": True, "focus_start": f"0x{new_focus:08X}"})


@app.route("/analyze-mode/enter", methods=["POST"])
def analyze_mode_enter():
    """Enter ANALYZE MODE.  Defines a multi-block synthetic function
    (e.g. switch dispatcher + disjoint case bodies).  No yaml mutation,
    no history entries — pure exploration.  AI calls this once to set
    up; the user drives ←/→ block navigation from the UI."""
    data = request.get_json(force=True)
    raw_blocks = data.get("blocks") or []
    if not isinstance(raw_blocks, list) or not raw_blocks:
        return jsonify({"ok": False, "error": "blocks must be a non-empty list"}), 400
    blocks = []
    for i, b in enumerate(raw_blocks):
        try:
            s = analyzer._coerce_addr(b.get("start"))
            e = analyzer._coerce_addr(b.get("end"))
        except (ValueError, TypeError, AttributeError):
            return jsonify({"ok": False, "error": f"bad start/end on block {i}"}), 400
        if e < s:
            return jsonify({"ok": False, "error": f"block {i}: end < start"}), 400
        blocks.append({"start": s, "end": e})
    label = data.get("label") or ""
    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        session["analyze_mode"] = {
            "blocks": blocks,
            "active_block": 0,
            "label": str(label),
        }
        save_session(session)
    return jsonify({"ok": True, "block_count": len(blocks)})


@app.route("/analyze-mode/cycle", methods=["POST"])
def analyze_mode_cycle():
    """Cycle the active block in ANALYZE MODE.  Wired to ←/→ keyboard
    keys and on-screen arrow buttons.  Wraps at boundaries."""
    data = request.get_json(force=True)
    direction = data.get("direction")
    if direction not in ("next", "prev"):
        return jsonify({"ok": False, "error": "direction must be 'next' or 'prev'"}), 400
    with LOCK:
        session = load_session()
        am = session.get("analyze_mode")
        if not am or not am.get("blocks"):
            return jsonify({"ok": False, "error": "not in analyze_mode"}), 400
        n = len(am["blocks"])
        cur = am.get("active_block", 0) % n
        am["active_block"] = (cur + (1 if direction == "next" else -1)) % n
        session["analyze_mode"] = am
        save_session(session)
    return jsonify({"ok": True, "active_block": am["active_block"]})


@app.route("/analyze-mode/clear", methods=["POST"])
def analyze_mode_clear():
    """Exit ANALYZE MODE — clears session["analyze_mode"].  Sweep
    resumes wherever it was.  No side effects on the yaml or history."""
    with LOCK:
        session = load_session()
        had = bool(session.get("analyze_mode"))
        session["analyze_mode"] = None
        save_session(session)
    return jsonify({"ok": True, "was_active": had})


@app.route("/analyze-mode/add", methods=["POST"])
def analyze_mode_add():
    """Alt-click entrypoint: add a block to analyze mode by start addr.
    Server computes the block end from the stamped subseg's end if
    that addr is already verified, else from the CFG walker
    (model.analyze_function).

    If not yet in analyze mode, enters with two blocks — the live
    candidate as block 1, the alt-clicked addr as block 2 (the
    'current function is the first block' rule).  If already in
    analyze mode, appends; toggles a block out if its start is
    already present, and clears the mode entirely when the last
    block is toggled away.
    """
    data = request.get_json(force=True)
    raw = data.get("start")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'start'"}), 400
    try:
        addr = analyzer._coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400

    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        cfg, model, sweep = _build_sweep(session)

        # End comes from yaml if stamped, else CFG walker.
        end = None
        for s in sweep.verified:
            if s.start == addr:
                end = s.end
                break
        if end is None:
            fa = model.analyze_function(addr)
            end = fa.end

        am = session.get("analyze_mode")
        if not am:
            nxt = sweep.next_candidate()
            if nxt is None:
                return jsonify({"ok": False, "error": "no current candidate to anchor analyze mode"}), 400
            if addr == nxt.function.start:
                return jsonify({
                    "ok": False,
                    "error": "alt-click on the current candidate is a no-op — click a different address",
                }), 400
            blocks = [
                {"start": nxt.function.start, "end": nxt.function.end},
                {"start": addr, "end": end},
            ]
            session["analyze_mode"] = {
                "blocks": blocks,
                "active_block": 1,
                "label": "alt-click",
            }
            action = "entered"
        else:
            blocks = [dict(b) for b in (am.get("blocks") or [])]
            existing_idx = next(
                (i for i, b in enumerate(blocks) if int(b["start"]) == addr),
                None,
            )
            if existing_idx is not None:
                blocks.pop(existing_idx)
                if not blocks:
                    session["analyze_mode"] = None
                    action = "cleared"
                else:
                    am["blocks"] = blocks
                    am["active_block"] = min(am.get("active_block", 0), len(blocks) - 1)
                    session["analyze_mode"] = am
                    action = "removed"
            else:
                blocks.append({"start": addr, "end": end})
                am["blocks"] = blocks
                am["active_block"] = len(blocks) - 1  # focus the newly-added block
                session["analyze_mode"] = am
                action = "added"
        save_session(session)
    return jsonify({
        "ok": True,
        "action": action,
        "addr": f"0x{addr:08X}",
        "block_count": len(blocks) if action != "cleared" else 0,
    })


@app.route("/verdict", methods=["POST"])
def verdict():
    data = request.get_json(force=True)
    v = data.get("verdict")
    if v not in ("approved", "rejected", "unsure"):
        return jsonify({"ok": False, "error": "bad verdict"}), 400
    # Optional `type` selects code vs data subseg.  data-type verdicts
    # only make sense paired with "approved" — reject/unsure of a data
    # range isn't meaningful (data is binary yes/no on the candidate
    # range).  Default code preserves the historical behavior.
    verdict_type = data.get("type", "code")
    if verdict_type not in ("code", "data"):
        return jsonify({"ok": False, "error": "type must be 'code' or 'data'"}), 400
    if verdict_type == "data" and v != "approved":
        return jsonify({
            "ok": False,
            "error": "data verdict only supports 'approved' (reject/unsure don't apply to data ranges)",
        }), 400

    with LOCK:
        session = load_session()
        blocked = _audit_guard_response(session)
        if blocked is not None:
            return blocked
        if session.get("analyze_mode"):
            return jsonify({
                "ok": False,
                "error": "analyze_mode is active — exit ANALYZE MODE before recording verdicts",
            }), 409
        cfg, model, sweep = _build_sweep(session)
        nxt = sweep.next_candidate()
        if nxt is None:
            return jsonify({"ok": False, "error": "no candidate"}), 400

        session["ai_override"] = None  # any verdict clears override
        history = session.setdefault("history", [])
        last = history[-1] if history else None
        same_candidate = (
            last is not None
            and last.get("candidate_start") == nxt.function.start
            and last.get("verdict") != "approved"
        )

        if v in ("rejected", "unsure"):
            if same_candidate and last.get("verdict") in ("rejected", "unsure"):
                save_session(session)
                return jsonify({"ok": True, "no_op": True})
            history.append({
                "verdict": v,
                "candidate_start_hex": f"{nxt.function.start:08X}",
                "candidate_start": nxt.function.start,
                "candidate_end": nxt.function.end,
                "feedback": "",
                "ts": time.time(),
            })
            save_session(session)
            return jsonify({"ok": True})

        # v == "approved"
        if same_candidate:
            last["verdict"] = "approved"
            last["candidate_end"] = nxt.function.end
            last["ts"] = time.time()
        else:
            history.append({
                "verdict": "approved",
                "candidate_start_hex": f"{nxt.function.start:08X}",
                "candidate_start": nxt.function.start,
                "candidate_end": nxt.function.end,
                "feedback": "",
                "ts": time.time(),
                "type": verdict_type,
            })

        # Data subseg short-circuit: skip the partner / entry / auto-
        # back-ref / overlap-absorption machinery (those are code-only
        # concepts).  Just record the data range to yaml and return.
        if verdict_type == "data":
            _insert_subseg_in_yaml(
                nxt.function.start, nxt.function.end,
                subseg_type="data",
            )
            save_session(session)
            return jsonify({
                "ok": True,
                "type": "data",
                "range": [f"0x{nxt.function.start:08X}", f"0x{nxt.function.end:08X}"],
            })

        # Auto-unstamp any subsegs whose range overlaps the new one.
        # When a dispatcher's switch absorption (or a manually pinned
        # wider boundary) extends past stamps previously made for case
        # bodies / fall-throughs, the new wider stamp transparently
        # supersedes them — one click, no orphaned overlap.
        absorbed = _find_overlapping_subsegs(
            nxt.function.start, nxt.function.end,
            exclude_start=nxt.function.start,
        )
        for ex_start, _ex_end in absorbed:
            _remove_subseg_from_yaml(ex_start)

        # Partners come from two sources, unioned:
        #   1. pending_partners staged via /queue-partner before approval
        #   2. existing stamps whose partners list already includes this
        #      candidate's start (auto back-reference)
        pending_partners = list(session.get("pending_partners") or [])
        auto_back_refs = []
        for s in sweep.verified:
            if nxt.function.start in (s.partners or []):
                auto_back_refs.append(s.start)
        all_partners = sorted(set(pending_partners) | set(auto_back_refs))

        # Pending alt entries queued via /queue-entry get written to the
        # new subseg's entries: field on approve.  Queue is keyed by
        # main_hex; only this candidate's bucket gets written + cleared.
        # Re-validate against the FINAL fa.start/end here — between
        # queue and approve the user may have pinned the end smaller
        # (or expanded it), so the at-queue check is necessary but not
        # sufficient.
        all_pending_entries = dict(session.get("pending_entries") or {})
        main_hex = f"0x{nxt.function.start:08X}"
        queued = list(all_pending_entries.get(main_hex) or [])
        valid_entries: list = []
        dropped_entries: list = []
        verified_other_ranges = [
            (s.start, s.end) for s in sweep.verified
            if s.start != nxt.function.start
        ]
        for e in queued:
            if not (nxt.function.start < e <= nxt.function.end):
                dropped_entries.append(e)
                continue
            if any(os_start <= e <= os_end for os_start, os_end in verified_other_ranges):
                dropped_entries.append(e)
                continue
            valid_entries.append(e)

        _insert_subseg_in_yaml(
            nxt.function.start, nxt.function.end,
            partners=all_partners,
            entries=valid_entries,
        )
        # Forward cross-reference: for every partner queued (or auto-found),
        # add this candidate's start to their partners list (if they're
        # already stamped).  The pending_partners user-queued addrs may
        # NOT be stamped yet — those back-refs get added when those
        # functions themselves get approved (the auto_back_refs path
        # above catches that on the other side).
        for p in all_partners:
            _add_partner_to_existing_subseg(p, nxt.function.start)

        session["pending_partners"] = []   # clear queue after approve
        all_pending_entries.pop(main_hex, None)
        session["pending_entries"] = all_pending_entries
        save_session(session)
        return jsonify({
            "ok": True,
            "absorbed": [f"0x{s:08X}" for s, _ in absorbed],
            "partners": [f"0x{p:08X}" for p in all_partners],
            "entries": [f"0x{e:08X}" for e in valid_entries],
            "dropped_entries": [f"0x{e:08X}" for e in dropped_entries],
        })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser()
    p.add_argument("yaml_path", help="path to boundary yaml (e.g. config/race.bin.yaml)")
    p.add_argument("--project-root", default=None)
    p.add_argument("--port", type=int, default=5001,
                   help="port (default 5001 so eval_server.py on 5000 can run in parallel)")
    args = p.parse_args()

    project_root = Path(args.project_root) if args.project_root else Path.cwd()
    yaml_path = Path(args.yaml_path)
    if not yaml_path.is_absolute():
        yaml_path = (project_root / yaml_path).resolve()

    STATE["yaml_path"] = yaml_path
    STATE["project_root"] = project_root
    STATE["session_path"] = yaml_path.parent / (yaml_path.stem + ".session.json")
    # Eagerly build the model so the first /state poll is cheap.
    cfg = _load_yaml_cfg()
    model = _build_or_get_model(cfg)
    # Pre-warm analyze_function for every verified subseg.  SweepState's
    # listing() iterates these as siblings on every /state poll (to find
    # cross-function pool references landing in the candidate's range),
    # and an un-warmed cache means N analyze_function calls on the first
    # poll.  Warm here once so all polls — including the first — are
    # fast.  Process-lifetime cache; Flask reload re-runs this.
    is_reloader_child = bool(os.environ.get("WERKZEUG_RUN_MAIN"))
    if not is_reloader_child:
        print(f"  Pre-warming analyze_function cache ...", end=" ", flush=True)
    t0 = time.time()
    subsegs = [s for s in (cfg.get("subsegments") or []) if s.get("type") == "code"]
    for s in subsegs:
        model.analyze_function(s["start"], hint_end=s["end"])
    if not is_reloader_child:
        print(f"{len(subsegs)} functions cached in {time.time() - t0:.2f}s")

    url = f"http://localhost:{args.port}"

    if not is_reloader_child:
        print()
        print(f"  eval_server (analyzer-driven, UI-only)")
        print(f"  Yaml:         {yaml_path}")
        print(f"  Project root: {project_root}")
        print(f"  Session:      {STATE['session_path']}")
        print(f"  Opening {url} in your browser ...")
        print(f"  Auto-reload enabled — saved .py changes restart the")
        print(f"  server in place; browser tab picks up the new code")
        print(f"  on its next /state poll (~1s).")
        print(f"  Press Ctrl+C in this terminal to stop the server.")
        print()
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=True)
    except OSError as e:
        if "address" in str(e).lower() or "10048" in str(e) or "98" in str(e):
            print(f"\n  ERROR: port {args.port} already in use.")
            print(f"  Stop the other instance with Ctrl+C, or pass --port <other>.")
            sys.exit(2)
        raise


if __name__ == "__main__":
    main()
