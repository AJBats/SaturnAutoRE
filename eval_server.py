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
        "pending_partners": [],   # addrs queued via /queue-partner; applied on next approve
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


def _append_subseg_to_yaml(start_addr, end_addr, file_name, partners=None):
    text = open(STATE["yaml_path"]).read()
    if not text.endswith("\n"):
        text += "\n"
    addition = (
        f"  - start: 0x{start_addr:08X}\n"
        f"    type:  code\n"
        f"    file:  {file_name}\n"
        f"    end:   0x{end_addr:08X}\n"
    )
    if partners:
        partners_list = ", ".join(f"0x{p:08X}" for p in sorted(set(partners)))
        addition += f"    partners: [{partners_list}]\n"
    with open(STATE["yaml_path"], "w") as f:
        f.write(text + addition)


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
        }
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
                        suggested_partners=None):
    """Project analyzer.FunctionAnalysis to the candidate dict the
    banner renderer (keys.js renderCandidateBanner) consumes.

    `partners` is the list of int addrs from the yaml subseg's partners
    field (when this candidate is already stamped).  `pending_partners`
    is the session-queued list (added via /queue-partner before approval
    and applied on next approve).  `suggested_partners` is the
    analyzer-derived list of likely partner addrs based on stack
    imbalance signals — the UI renders one button per suggestion.
    """
    return {
        "start_hex": f"{fa.start:08X}",
        "start": fa.start,
        "end_hex": f"{fa.end:08X}",
        "end": fa.end,
        "size": fa.end - fa.start + 1,
        "verdict": fa.verdict.value,
        "yellow_flags": list(fa.yellow_flags),
        "name": f"FUN_{fa.start:08X}",
        "reference": _reference_to_dict(fa.reference),
        "evidence": {
            "static_callers": fa.evidence.static_callers,
            "cross_module_callers": fa.evidence.cross_module_callers,
            "runtime_hits": fa.evidence.runtime_hits,
            "midpoints": [_midpoint_to_dict(m) for m in fa.midpoints],
        },
        "partners": [{"addr": p, "addr_hex": f"{p:08X}"} for p in (partners or [])],
        "pending_partners": [
            {"addr": p, "addr_hex": f"{p:08X}"} for p in (pending_partners or [])
        ],
        "suggested_partners": list(suggested_partners or []),
        "partner_balanced": bool(getattr(fa, "partner_balanced", False)),
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


def _build_candidate_payload(sweep, candidate_fa, previous_typed,
                              attn=None, pending_partners=None):
    """Build the per-pane payload (banner + listing rows).  Mirrors
    eval_server._build_candidate_payload's output shape.

    Partners (from yaml) are looked up by candidate's start; pending
    partners (session-queued) are passed in by the caller.
    """
    rows = sweep.listing(candidate_fa, previous=previous_typed, attn=attn)
    partners = []
    for s in sweep.verified:
        if s.start == candidate_fa.start:
            partners = list(s.partners or [])
            break
    suggestions = sweep.suggested_partners(candidate_fa)
    # Trailing-zone warnings: surface a yellow flag when the candidate
    # ends right before case targets of an existing stamped dispatcher
    # — strong signal that the boundary is too short.
    trailing_flags = sweep.check_trailing_zone_case_targets(candidate_fa)
    if trailing_flags:
        candidate_fa = dataclasses.replace(
            candidate_fa,
            yellow_flags=list(candidate_fa.yellow_flags) + trailing_flags,
        )
    # Apply partner-aware verdict: suppress imbalance flags when the
    # combined stack frame across this function + its partners is
    # balanced.  Happens AFTER listing emission (listing doesn't use
    # verdict/flags so the order is safe).
    candidate_fa = sweep.apply_partner_awareness(candidate_fa)
    return {
        "candidate": _candidate_to_dict(
            candidate_fa,
            partners=partners,
            pending_partners=pending_partners,
            suggested_partners=suggestions,
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

        analyze_mode = session.get("analyze_mode")
        if analyze_mode:
            nxt = _analyze_mode_active_candidate(model, sweep, analyze_mode)
            if nxt is None:
                return jsonify({"all_caught_up": False, "error": "analyze_mode has no blocks"}), 400
        else:
            nxt = sweep.next_candidate()
        progress = _progress_to_dict(sweep.progress())

        if nxt is None:
            return jsonify({
                "all_caught_up": True,
                "history_count": len(history),
                "progress": progress,
                "internal_gaps": [_gap_to_dict(g) for g in sweep.gaps()],
            })

        # Internal gaps with pending gap to proposed candidate surfaced too.
        # Suppressed in analyze_mode (the ANALYZE MODE banner takes the slot).
        if analyze_mode:
            internal_gaps = []
        else:
            internal_gaps = [_gap_to_dict(g) for g in sweep.gaps(proposed_start=nxt.function.start)]

        pending_partners = list(session.get("pending_partners") or [])
        primary_payload = _build_candidate_payload(
            sweep, nxt.function, nxt.previous,
            attn=attn_addrs, pending_partners=pending_partners,
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
        # Reject if next_start lands inside an already-verified subseg.
        for s in sweep.verified:
            if s.start <= next_start <= s.end:
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
        had_override = bool(session.get("ai_override"))
        session["ai_override"] = None
        save_session(session)
    return jsonify({"ok": True, "had_override": had_override})


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
        ok_a = _add_partner_to_existing_subseg(a, b)
        ok_b = _add_partner_to_existing_subseg(b, a)
    if not ok_a:
        return jsonify({"ok": False, "error": f"no subseg at 0x{a:08X}"}), 404
    return jsonify({
        "ok": True,
        "updated": [f"0x{a:08X}"] + ([f"0x{b:08X}"] if ok_b else []),
        "back_ref_skipped": not ok_b,
    })


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
        removed = _remove_subseg_from_yaml(addr)
    if not removed:
        return jsonify({"ok": False, "error": f"no subseg found with start 0x{addr:08X}"}), 404
    return jsonify({"ok": True, "unstamped": f"0x{addr:08X}"})


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


@app.route("/verdict", methods=["POST"])
def verdict():
    data = request.get_json(force=True)
    v = data.get("verdict")
    if v not in ("approved", "rejected", "unsure"):
        return jsonify({"ok": False, "error": "bad verdict"}), 400

    with LOCK:
        session = load_session()
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

        # Find the containing TU for the file_name field.
        tus = cfg.get("tus") or []
        tu = next((t for t in tus if t["start"] <= nxt.function.start <= t["end"]), None)
        file_name = tu["name"] if tu else f"tu_{nxt.function.start:08X}"

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

        _append_subseg_to_yaml(
            nxt.function.start, nxt.function.end, file_name,
            partners=all_partners,
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
        save_session(session)
        return jsonify({
            "ok": True,
            "absorbed": [f"0x{s:08X}" for s, _ in absorbed],
            "partners": [f"0x{p:08X}" for p in all_partners],
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
