#!/usr/bin/env python3
"""eval_server2.py — UI-only Flask server.  Successor to eval_server.py.

Consumes analyzer.py for every code-related question.  Owns only:
  - HTTP routes (Flask)
  - Session.json read/write (user verdict tracking + AI override)
  - Yaml read/write (verified subsegs)
  - Browser auto-open + Flask hot-reload integration
  - Row/candidate → JSON projection (keys.js wire format, unchanged so
    the existing frontend works as-is)

No decode_sh2 imports.  No pool detection.  No CFG walks.  No caller scans.
Every "what is at address X" question goes through analyzer.

Run from a project's root directory:
    python <SaturnAutoRE>/eval_server2.py config/<binary>.yaml
"""

import argparse
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
    return {"history": [], "ai_override": None}


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


def _append_subseg_to_yaml(start_addr, end_addr, file_name):
    text = open(STATE["yaml_path"]).read()
    if not text.endswith("\n"):
        text += "\n"
    addition = (
        f"  - start: 0x{start_addr:08X}\n"
        f"    type:  code\n"
        f"    file:  {file_name}\n"
        f"    end:   0x{end_addr:08X}\n"
    )
    with open(STATE["yaml_path"], "w") as f:
        f.write(text + addition)


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
    current session.ai_override."""
    cfg = _load_yaml_cfg()
    model = _build_or_get_model(cfg)
    return cfg, model, analyzer.SweepState(model, cfg, ai_override=session.get("ai_override"))


# ---------------------------------------------------------------------------
# Wire-format projections: analyzer types → eval_server's existing JSON shape.
# Frontend keys.js is unchanged; eval_server2 just produces the same shape
# from analyzer's output.
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


def _candidate_to_dict(fa):
    """Project analyzer.FunctionAnalysis to the candidate dict the
    banner renderer (keys.js renderCandidateBanner) consumes."""
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


def _build_candidate_payload(sweep, candidate_fa, previous_typed, attn=None):
    """Build the per-pane payload (banner + listing rows).  Mirrors
    eval_server._build_candidate_payload's output shape."""
    rows = sweep.listing(candidate_fa, previous=previous_typed, attn=attn)
    return {
        "candidate": _candidate_to_dict(candidate_fa),
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
        internal_gaps = [_gap_to_dict(g) for g in sweep.gaps(proposed_start=nxt.function.start)]

        primary_payload = _build_candidate_payload(
            sweep, nxt.function, nxt.previous, attn=attn_addrs,
        )

        # Natural pane (for split view) — only when override is active AND
        # the natural candidate differs in start OR end.
        natural_view = None
        if session.get("ai_override"):
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


@app.route("/verdict", methods=["POST"])
def verdict():
    data = request.get_json(force=True)
    v = data.get("verdict")
    if v not in ("approved", "rejected", "unsure"):
        return jsonify({"ok": False, "error": "bad verdict"}), 400

    with LOCK:
        session = load_session()
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
        # Find the containing TU for the file_name field.
        tus = cfg.get("tus") or []
        tu = next((t for t in tus if t["start"] <= nxt.function.start <= t["end"]), None)
        file_name = tu["name"] if tu else f"tu_{nxt.function.start:08X}"
        _append_subseg_to_yaml(nxt.function.start, nxt.function.end, file_name)
        save_session(session)
        return jsonify({"ok": True})


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
        print(f"  eval_server2 (analyzer-driven, UI-only)")
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
