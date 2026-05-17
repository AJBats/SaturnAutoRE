#!/usr/bin/env python3
"""eval_server.py — single-candidate forward-sweep verdict loop.

Run from the project directory (DaytonaCCEReverse):
    python D:/Projects/SaturnAutoRE/eval_server.py config/race.bin.yaml

State machine, one candidate at a time:
  - Server computes the next forward-sweep candidate from current yaml state.
  - Browser polls /state every ~1s and shows it.
  - Human clicks approve → server writes subseg to yaml, computes next.
  - Human clicks reject/unsure + feedback → server marks awaiting_ai.
    Human tabs to chat; AI reads session.json, writes a corrected
    current_candidate (overriding forward-sweep), clears awaiting_ai.
  - Browser auto-refresh shows the new state.

Session file lives at <yaml>.session.json next to the yaml.
"""

import argparse
import json
import sys
import threading
import time
import webbrowser
from pathlib import Path

import yaml
from flask import Flask, render_template, request, jsonify

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR / "lib"))
sys.path.insert(0, str(SCRIPT_DIR))

from sh2_decode import decode_sh2
from oracle import (
    analyze_candidate,
    find_next_forward_sweep_candidate,
    BRANCH_MNEMONICS,
)

app = Flask(__name__, template_folder=str(SCRIPT_DIR / "templates"), static_folder=str(SCRIPT_DIR / "static"))

STATE = {
    "yaml_path": None,
    "project_root": None,
    "session_path": None,
}
LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------

def _empty_session():
    return {"pending_verdict": None, "history": [], "awaiting_ai": False, "ai_override": None}


def load_session():
    p = STATE["session_path"]
    if p and p.exists():
        with open(p) as f:
            return json.load(f)
    return _empty_session()


def save_session(session):
    p = STATE["session_path"]
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(session, f, indent=2)


def load_yaml():
    with open(STATE["yaml_path"]) as f:
        return yaml.safe_load(f)


def load_binary(cfg):
    return open(STATE["project_root"] / cfg["options"]["target_path"], "rb").read()


# ---------------------------------------------------------------------------
# Yaml mutation: append approved candidate as a code subseg
# ---------------------------------------------------------------------------

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
# Listing renderer — four sections: prev / intermediate / current / trailing
# ---------------------------------------------------------------------------

RETURN_HEADS  = {"rts", "rte"}
CALL_HEADS    = {"jsr", "bsr", "bsrf"}
UNCOND_HEADS  = {"bra", "jmp", "braf"}
COND_HEADS    = {"bf", "bt", "bf/s", "bt/s"}
COMPARE_HEADS = {"tst", "cmp/eq", "cmp/ge", "cmp/gt", "cmp/hi", "cmp/hs", "cmp/pl", "cmp/pz", "cmp/str"}

TRAILING_BYTES = 200


def _classify_mnem(mnem):
    if not mnem:
        return None
    head = mnem.split()[0]
    if head in RETURN_HEADS:  return "cat-return"
    if head in CALL_HEADS:    return "cat-call"
    if head in UNCOND_HEADS:  return "cat-uncond"
    if head in COND_HEADS:    return "cat-cond"
    if "@(0x" in mnem and head in ("mov.l", "mov.w", "mova"):
        return "cat-pool"
    if head in COMPARE_HEADS:
        return "cat-compare"
    if mnem.startswith(".byte") or mnem.startswith(".4byte") or mnem.startswith(".2byte"):
        return "cat-data"
    return None


def _pools_and_branches(ev):
    """Return (pool4, pool2, mova, branch_targets) within ev's range."""
    pool4 = set()
    pool2 = set()
    mova = set()
    binary = STATE["binary_cache"]
    vram = STATE["vram_cache"]
    for addr in sorted(ev.reachable):
        if addr in pool4 or addr in pool2:
            continue
        off = addr - vram
        if off + 1 >= len(binary):
            continue
        op = (binary[off] << 8) | binary[off + 1]
        mnem, tgt = decode_sh2(op, addr)
        if tgt is None or mnem is None:
            continue
        if mnem.startswith("mov.l @(0x") and ev.start <= tgt <= ev.end:
            pool4.add(tgt)
        elif mnem.startswith("mov.w @(0x") and ev.start <= tgt <= ev.end:
            pool2.add(tgt)
        elif mnem.startswith("mova @(0x") and ev.start <= tgt <= ev.end:
            mova.add(tgt)

    branch_targets = {}
    for b in ev.branches:
        if b.internal and b.target is not None:
            branch_targets[b.target] = True
    return pool4, pool2, mova, branch_targets


def _symbolize(mnem, pool4, pool2, mova, branch_targets):
    parts = mnem.split(None, 1)
    if not parts:
        return mnem
    head = parts[0]
    tail = parts[1] if len(parts) > 1 else ""

    if "@(0x" in tail and head in ("mov.l", "mov.w", "mova"):
        before, _, after = tail.partition("@(0x")
        hex_str, _, rest = after.partition(")")
        try:
            addr = int(hex_str, 16)
            if addr in pool4 or addr in pool2 or addr in mova:
                return f"{head} {before}.L_pool_{addr:08X}{rest}".strip()
        except ValueError:
            pass

    if head in BRANCH_MNEMONICS:
        try:
            target = int(tail.rstrip(","), 16)
            if target in branch_targets:
                return f"{head} .L_{target:08X}"
        except ValueError:
            pass
    return mnem


def _emit_section_header(lines, section, label):
    lines.append({
        "kind": "section",
        "addr_str": "",
        "label": label,
        "bytes": "",
        "mnem": "",
        "margin": "",
        "classes": [f"section-{section}-header"],
    })


def _branch_direction(b):
    if b is None or b.target is None:
        return None
    if b.target > b.src:
        return "forward"
    return "backward"


def _compute_indent_depths(ev):
    """Compute nesting depth per address via a push/pop sweep on branch targets.

    Rule (matches C reading order):
      - Conditional-branch target (bf/bt/bf.s/bt.s) → push depth
        (the label marks the start of a "branched-to body", i.e. the IF arm)
      - Unconditional-branch target (bra)           → pop depth
        (the label is a merge point — bra'd to from end-of-arm)
      - Fall-through code stays at the current depth
      - Backward branches (loops) are not handled in this version

    Returns dict {addr: int_depth}.  Addresses not in the dict have depth 0.
    """
    if not ev.branches:
        return {}

    cond_targets = set()
    uncond_targets = set()
    for b in ev.branches:
        if not b.internal or b.target is None:
            continue
        if b.target <= b.src:
            continue  # backward — loops, handled in a later pass
        if b.mnem in {"bf", "bt", "bf/s", "bt/s"}:
            cond_targets.add(b.target)
        elif b.mnem in {"bra"}:
            uncond_targets.add(b.target)
        # bsr is a call (returns), not a control-structure boundary — skip

    if not cond_targets and not uncond_targets:
        return {}

    addr_depths = {}
    depth = 0
    addr = ev.start
    while addr <= ev.end:
        # Apply events at this address — pop before push (so a label that's
        # both a merge and a cond-target — rare — ends at the same depth as
        # its predecessor instead of net-incrementing).
        if addr in uncond_targets and depth > 0:
            depth -= 1
        if addr in cond_targets:
            depth += 1
        if depth > 0:
            addr_depths[addr] = depth
        addr += 2

    return addr_depths


def _emit_function_lines(lines, ev, section):
    """Emit a full function listing with symbolized labels.
    `section` is one of 'prev', 'current', and controls highlighting prominence.
    """
    binary = STATE["binary_cache"]
    vram = STATE["vram_cache"]
    pool4, pool2, mova, branch_targets = _pools_and_branches(ev)
    indent_depths = _compute_indent_depths(ev)

    prologue_lo, prologue_hi = ev.prologue_range
    epi_lo, epi_hi = ev.epilogue_range or (None, None)

    branches_at = {b.src: b for b in ev.branches}

    MAX_DISPLAY_INDENT = 4  # v1 heuristic accumulates depth on switch dispatches;
                              # cap so the listing stays scannable
    addr = ev.start
    while addr <= ev.end:
        depth = min(indent_depths.get(addr, 0), MAX_DISPLAY_INDENT)
        line = {
            "addr": addr,
            "addr_str": f"{addr:08X}",
            "classes": [f"section-{section}"],
            "margin": "",
            "label": "",
            "indent": depth,
        }

        if addr in pool4:
            off = addr - vram
            v = (binary[off] << 24) | (binary[off+1] << 16) | (binary[off+2] << 8) | binary[off+3]
            line["kind"] = "pool"
            line["label"] = f".L_pool_{addr:08X}"
            line["bytes"] = " ".join(f"{binary[off+i]:02X}" for i in range(4))
            line["mnem"] = f".4byte 0x{v:08X}"
            line["classes"].append("pool")
            line["indent"] = 0   # pool data doesn't participate in control-flow indentation
            lines.append(line)
            addr += 4
            continue
        if addr in pool2:
            off = addr - vram
            v = (binary[off] << 8) | binary[off+1]
            line["kind"] = "pool"
            line["label"] = f".L_pool_{addr:08X}"
            line["bytes"] = " ".join(f"{binary[off+i]:02X}" for i in range(2))
            line["mnem"] = f".2byte 0x{v:04X}"
            line["classes"].append("pool")
            line["indent"] = 0
            lines.append(line)
            addr += 2
            continue

        if addr in branch_targets and addr != ev.start:
            lines.append({
                "addr": addr,
                "addr_str": "",
                "kind": "label",
                "label": f".L_{addr:08X}:",
                "bytes": "",
                "mnem": "",
                "classes": [f"section-{section}", "label"],
                "margin": "",
                "indent": min(indent_depths.get(addr, 0), MAX_DISPLAY_INDENT),
            })

        off = addr - vram
        if off + 1 >= len(binary):
            break
        op = (binary[off] << 8) | binary[off+1]
        mnem, _ = decode_sh2(op, addr)
        if mnem is None:
            mnem = f".byte 0x{binary[off]:02X}, 0x{binary[off+1]:02X}"

        line["kind"] = "instr"
        line["bytes"] = f"{binary[off]:02X} {binary[off+1]:02X}"
        line["mnem"] = _symbolize(mnem, pool4, pool2, mova, branch_targets)

        if prologue_lo is not None and prologue_lo <= addr <= prologue_hi:
            line["classes"].append("prologue")
        if epi_lo is not None and epi_lo <= addr <= epi_hi:
            line["classes"].append("epilogue")
        if addr == ev.final_rts:
            line["classes"].append("final-rts")
        if addr in ev.conditional_rts:
            line["classes"].append("cond-rts")

        cat = _classify_mnem(mnem)
        if cat:
            line["classes"].append(cat)

        # Margin direction arrow + tail-call flag.
        # `b` is None if this instruction wasn't visited by the oracle's CFG
        # walk (unreachable from the function entry).  Don't make tail-call
        # claims when we don't know — only when oracle explicitly says external.
        head = mnem.split()[0] if mnem else ""
        b = branches_at.get(addr)

        # Expose internal branch info so the front-end can draw arcs.
        if b is not None and b.target is not None and b.internal:
            arc_type = "cond" if b.mnem in {"bf", "bt", "bf/s", "bt/s"} else "uncond"
            line["branch"] = {
                "target": b.target,
                "type": arc_type,
                "direction": "forward" if b.target > b.src else "backward",
            }

        # Direct-target branches: arrow shows direction in margin.
        if b is not None and b.target is not None:
            if b.internal:
                if b.target > b.src:
                    line["margin"] = "↓"
                else:
                    line["margin"] = "↑"
            else:
                # Oracle confirmed: target is OUTSIDE the function.
                line["margin"] = "→"
                if head in UNCOND_HEADS:
                    # Unconditional + external target = tail-call exit. LOUDEST.
                    line["classes"].append("tail-call")
                    line["tag"] = "⇒ TAIL?"
                elif head in COND_HEADS:
                    # Conditional branch out of function — unusual, worth flagging.
                    line["classes"].append("tail-call")
                    line["tag"] = "↗ external"

        # Indirect calls (jsr @rN, bsrf rN) — control returns.  Subtle tag.
        if head in CALL_HEADS:
            if not line.get("tag"):
                line["tag"] = "↩ ret"

        # Indirect unconditional jumps (jmp @rN, braf rN) — control gone.
        if head in ("jmp", "braf"):
            line["classes"].append("uncond-indirect")
            if not line.get("tag"):
                line["tag"] = "⇒ exits"

        # Direct unconditional jumps with INTERNAL target — also "control gone"
        # but staying in the function. Quieter tag.
        if head == "bra" and b is not None and b.internal:
            if not line.get("tag"):
                line["tag"] = "⇒"

        # Returns — explicit EXIT tag.
        if head in RETURN_HEADS:
            line["tag"] = "⇒ EXIT"

        lines.append(line)
        addr += 2


def _emit_raw_bytes(lines, start, end, section):
    binary = STATE["binary_cache"]
    vram = STATE["vram_cache"]
    binary_end = vram + len(binary) - 1
    end = min(end, binary_end)
    addr = start
    while addr <= end:
        off = addr - vram
        if off + 1 >= len(binary):
            break
        op = (binary[off] << 8) | binary[off+1]
        mnem, _ = decode_sh2(op, addr)
        if mnem is None:
            mnem = f".byte 0x{binary[off]:02X}, 0x{binary[off+1]:02X}"
        cls = [f"section-{section}"]
        cat = _classify_mnem(mnem)
        if cat:
            cls.append(cat)
        lines.append({
            "addr": addr,
            "addr_str": f"{addr:08X}",
            "kind": "raw",
            "label": "",
            "bytes": f"{binary[off]:02X} {binary[off+1]:02X}",
            "mnem": mnem,
            "classes": cls,
            "margin": "",
        })
        addr += 2


def render_listing(ev, prev_subseg):
    """Four sections: prev verified function, intermediate bytes, current candidate, trailing."""
    binary = STATE["binary_cache"]
    vram = STATE["vram_cache"]
    lines = []

    if prev_subseg:
        prev_ev = analyze_candidate(binary, vram, prev_subseg["start"], hint_end=prev_subseg["end"])
        size = prev_subseg["end"] - prev_subseg["start"] + 1
        _emit_section_header(
            lines, "prev",
            f"VERIFIED  FUN_{prev_subseg['start']:08X}  0x{prev_subseg['start']:08X} → 0x{prev_subseg['end']:08X}  ({size} bytes)"
        )
        _emit_function_lines(lines, prev_ev, "prev")

        if prev_subseg["end"] + 1 < ev.start:
            _emit_section_header(
                lines, "intermediate",
                f"INTERMEDIATE  0x{prev_subseg['end']+1:08X} → 0x{ev.start-1:08X}  ({ev.start - prev_subseg['end'] - 1} bytes, likely pool/padding)"
            )
            _emit_raw_bytes(lines, prev_subseg["end"] + 1, ev.start - 1, "intermediate")

    size = ev.end - ev.start + 1
    _emit_section_header(
        lines, "current",
        f"PROPOSED  FUN_{ev.start:08X}  0x{ev.start:08X} → 0x{ev.end:08X}  ({size} bytes)  verdict: {ev.verdict}"
    )
    _emit_function_lines(lines, ev, "current")

    trailing_start = ev.end + 1
    trailing_end = ev.end + TRAILING_BYTES
    binary_end = vram + len(binary) - 1
    if trailing_start <= binary_end:
        actual_end = min(trailing_end, binary_end)
        _emit_section_header(
            lines, "trailing",
            f"TRAILING  0x{trailing_start:08X} → 0x{actual_end:08X}  ({actual_end - trailing_start + 1} bytes after candidate)"
        )
        _emit_raw_bytes(lines, trailing_start, actual_end, "trailing")

    return lines


# ---------------------------------------------------------------------------
# Current-candidate computation (with AI override)
# ---------------------------------------------------------------------------

def _compute_current():
    """Return (prev_subseg, evidence) or None.

    If session.json has an `ai_override`, prefer that.
    Otherwise run forward-sweep from the latest verified subseg.
    """
    session = load_session()
    binary = STATE["binary_cache"]
    cfg = STATE["cfg_cache"]

    override = session.get("ai_override")
    if override:
        prev = override.get("previous_subseg")
        start = int(override["candidate_start"], 16) if isinstance(override["candidate_start"], str) else override["candidate_start"]
        tu = next((t for t in cfg.get("tus", []) if t["start"] <= start <= t["end"]), None)
        hint_end = tu["end"] if tu else None
        ev = analyze_candidate(binary, STATE["vram_cache"], start, hint_end)
        return prev, ev

    return find_next_forward_sweep_candidate(cfg, binary)


def _reload_caches():
    cfg = load_yaml()
    STATE["cfg_cache"] = cfg
    STATE["binary_cache"] = load_binary(cfg)
    STATE["vram_cache"] = int(cfg["options"]["vram"])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("candidate.html")


@app.route("/state")
def state():
    """Polled by the browser every ~1s. Returns current candidate + UI state."""
    with LOCK:
        _reload_caches()
        session = load_session()
        nxt = _compute_current()

        if nxt is None:
            return jsonify({
                "all_caught_up": True,
                "history_count": len(session.get("history", [])),
                "awaiting_ai": False,
            })

        prev, ev = nxt
        lines = render_listing(ev, prev)

        return jsonify({
            "all_caught_up": False,
            "candidate": {
                "start_hex": f"{ev.start:08X}",
                "start": ev.start,
                "end_hex": f"{ev.end:08X}",
                "end": ev.end,
                "size": ev.end - ev.start + 1,
                "verdict": ev.verdict,
                "yellow_flags": ev.yellow_flags,
                "name": f"FUN_{ev.start:08X}",
            },
            "previous": {
                "start_hex": f"{prev['start']:08X}",
                "name": f"FUN_{prev['start']:08X}",
            } if prev else None,
            "awaiting_ai": session.get("awaiting_ai", False),
            "pending_verdict": session.get("pending_verdict"),
            "history_count": len(session.get("history", [])),
            "lines": lines,
        })


@app.route("/verdict", methods=["POST"])
def verdict():
    data = request.get_json(force=True)
    v = data.get("verdict")
    feedback = (data.get("feedback") or "").strip()

    if v not in ("approved", "rejected", "unsure"):
        return jsonify({"ok": False, "error": "bad verdict"}), 400

    with LOCK:
        _reload_caches()
        nxt = _compute_current()
        if nxt is None:
            return jsonify({"ok": False, "error": "no candidate"}), 400
        prev, ev = nxt

        record = {
            "verdict": v,
            "candidate_start_hex": f"{ev.start:08X}",
            "candidate_start": ev.start,
            "candidate_end": ev.end,
            "feedback": feedback,
            "ts": time.time(),
        }

        session = load_session()
        # Always clear ai_override since this verdict is for the currently-shown candidate.
        session["ai_override"] = None

        if v == "approved":
            # Find TU for the "file:" field
            tu = next((t for t in STATE["cfg_cache"]["tus"] if t["start"] <= ev.start <= t["end"]), None)
            file_name = tu["name"] if tu else f"tu_{ev.start:08X}"
            _append_subseg_to_yaml(ev.start, ev.end, file_name)
            session["history"].append(record)
            session["pending_verdict"] = None
            session["awaiting_ai"] = False
            save_session(session)
            return jsonify({"ok": True, "auto_advanced": True})

        # Reject or Unsure: pause and wait for AI handling.
        session["pending_verdict"] = record
        session["awaiting_ai"] = True
        save_session(session)
        return jsonify({"ok": True, "awaiting_ai": True})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser()
    p.add_argument("yaml_path", help="path to the boundary yaml (e.g. config/race.bin.yaml)")
    p.add_argument("--project-root", default=None)
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()

    project_root = Path(args.project_root) if args.project_root else Path.cwd()
    yaml_path = Path(args.yaml_path)
    if not yaml_path.is_absolute():
        yaml_path = (project_root / yaml_path).resolve()

    STATE["yaml_path"] = yaml_path
    STATE["project_root"] = project_root
    STATE["session_path"] = yaml_path.parent / (yaml_path.stem + ".session.json")
    _reload_caches()

    url = f"http://localhost:{args.port}"
    print()
    print(f"  Yaml:         {yaml_path}")
    print(f"  Project root: {project_root}")
    print(f"  Session:      {STATE['session_path']}")
    print(f"  Opening {url} in your browser …")
    print(f"  Press Ctrl+C in this terminal to stop the server.")
    print()

    threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    except OSError as e:
        if "address" in str(e).lower() or "10048" in str(e) or "98" in str(e):
            print(f"\n  ERROR: port {args.port} already in use.")
            print(f"  Stop the other instance with Ctrl+C, or pass --port <other>.")
            sys.exit(2)
        raise


if __name__ == "__main__":
    main()
