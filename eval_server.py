#!/usr/bin/env python3
"""eval_server.py — single-candidate forward-sweep verdict loop.

Run from a project's root directory:
    python <SaturnAutoRE>/eval_server.py config/<binary>.yaml

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
import os
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
    return {"history": [], "ai_override": None}


def load_session():
    p = STATE["session_path"]
    if p and p.exists():
        with open(p) as f:
            sess = json.load(f)
        # Feedback is a single string per entry.  Older sessions used a list
        # (when the UI had a textbox and multiple unsure clicks could
        # accumulate notes).  Collapse any legacy list to a single newline-
        # joined string.
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


def load_yaml():
    with open(STATE["yaml_path"]) as f:
        return yaml.safe_load(f)


def load_binary(cfg):
    return open(STATE["project_root"] / cfg["options"]["target_path"], "rb").read()


# ---------------------------------------------------------------------------
# Yaml mutation: append approved candidate as a code subseg
# ---------------------------------------------------------------------------

def _remove_subseg_from_yaml(start_addr):
    """Remove the subseg with the given start address from the yaml.

    Re-review mechanism: when a subseg was approved under an older oracle
    (e.g. before pool-extension existed) and its boundary needs to be
    reconsidered with current logic, remove it from yaml.  Forward-sweep
    will then re-propose it on the next /state poll, and the human can
    stamp the corrected boundary.

    Returns True if a matching subseg was found and removed, False otherwise.
    """
    text = open(STATE["yaml_path"]).read()
    lines = text.splitlines(keepends=True)
    target = f"  - start: 0x{start_addr:08X}"
    out = []
    i = 0
    removed = False
    while i < len(lines):
        if lines[i].rstrip("\r\n") == target:
            # Skip the 4-line block: start / type / file / end.  Continue past
            # any continuation lines (indented with 4+ spaces) until the next
            # `- start:` line or a blank/dedented line.
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
    """Return (pool4, pool2, mova, branch_targets) within ev's range.

    Pool detection covers BOTH:
      - Pools referenced by mov.l/w/mova WITHIN ev (function-internal)
      - Pools referenced from sibling verified subsegs (cross-function pool
        constants clustered in this candidate's range — common Saturn pattern)
    """
    pool4 = set()
    pool2 = set()
    mova = set()
    binary = STATE["binary_cache"]
    vram = STATE["vram_cache"]

    # Pool refs FROM ev to ANY target (including cross-function — pools in
    # sibling subsegs' ranges).  All targets get added so symbolization
    # converts hardcoded addresses to labels.  Label emission only happens
    # when the emission loop walks an address that's in this set AND falls
    # in the current section's range, so out-of-range entries are
    # symbolization-only (label exists in another section's emission).
    for addr in sorted(ev.reachable):
        off = addr - vram
        if off + 1 >= len(binary):
            continue
        op = (binary[off] << 8) | binary[off + 1]
        mnem, tgt = decode_sh2(op, addr)
        if tgt is None or mnem is None:
            continue
        if mnem.startswith("mov.l @(0x"):
            pool4.add(tgt)
        elif mnem.startswith("mov.w @(0x"):
            pool2.add(tgt)
        elif mnem.startswith("mova @(0x"):
            mova.add(tgt)

    # Sibling pool refs landing INSIDE ev's range (cross-function refs into ev).
    sp4, sp2, spm = _sibling_pool_targets(ev.start, ev.end)
    pool4 |= sp4
    pool2 |= sp2
    mova |= spm

    # Reference-derived pool priors (addresses the reference's .s files identified
    # as pool data) — fills in pools referenced from not-yet-verified functions.
    # Skip addresses oracle's CFG walk reached as code: a reference auto-
    # disassembler will sometimes wrap a real branch in a `.4byte 0xXXXXXXXX`
    # literal (e.g. 0x8FF8... bf/s pattern looks data-shaped), but oracle's
    # in-binary decoding is the ground truth — trust it over the prior.
    for addr, size in STATE.get("pool_priors", {}).items():
        if ev.start <= addr <= ev.end and addr not in ev.reachable:
            if size == 4:
                pool4.add(addr)
            elif size == 2:
                pool2.add(addr)

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


def _emit_section_header(lines, section, label, anchor_addr=None):
    lines.append({
        "kind": "section",
        "anchor_addr": anchor_addr,
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
    """Compute nesting depth per address via CFG region analysis.

    Approach:
      1. Build basic blocks: split at every branch instruction and every
         branch target.
      2. Build edges (successor relationships) between blocks.
      3. Identify structured regions:
           - if-then / if-then-else: a block ending in a conditional whose
             two successors merge at a common postdominator
           - while / do-while: a backward edge from a block to a dominator
      4. Build a region tree from the regions; depth = nesting of regions.

    For unreducible control flow (irregular goto, tail calls), the region
    decomposition leaves those addresses at depth 0 — better to be flat than
    misleading.

    Returns dict {addr: int_depth}.
    """
    if not ev.branches:
        return {}

    binary = STATE.get("binary_cache")
    vram = STATE.get("vram_cache")
    if binary is None or vram is None:
        return {}

    # CFG region analysis must NOT walk through the trailing pool zone:
    # pool bytes can spell branch opcodes (rts/jmp/etc.) and create bogus
    # basic blocks that pollute the region containment graph.  Use the
    # last reachable instruction's end as our cap instead of ev.end.
    if not ev.reachable:
        return {}
    fn_start = ev.start
    fn_end = max(ev.reachable) + 1

    # ----- 1. Identify block-start addresses
    block_starts = {fn_start}
    branches_by_src = {}
    for b in ev.branches:
        if not b.internal or b.target is None:
            continue
        branches_by_src[b.src] = b
        block_starts.add(b.target)
        # The instruction after a branch (or its delay slot) begins a new block.
        delay = 2 if b.mnem in {"bra", "bsr", "bf/s", "bt/s"} else 0
        after = b.src + 2 + delay
        if fn_start <= after <= fn_end:
            block_starts.add(after)

    # Also: instruction after rts/jmp/braf (no static target but ends a block)
    addr = fn_start
    while addr <= fn_end:
        off = addr - vram
        if off + 1 >= len(binary):
            break
        op = (binary[off] << 8) | binary[off + 1]
        mnem, _ = decode_sh2(op, addr)
        if mnem:
            head = mnem.split()[0]
            if head in {"rts", "rte", "jmp", "braf"}:
                # Includes delay slot
                after = addr + 4
                if fn_start <= after <= fn_end:
                    block_starts.add(after)
        addr += 2

    block_starts_sorted = sorted(s for s in block_starts if fn_start <= s <= fn_end)
    if not block_starts_sorted:
        return {}

    # ----- 2. Build blocks (each is [start, end_inclusive])
    blocks = []
    for i, s in enumerate(block_starts_sorted):
        e = (block_starts_sorted[i + 1] - 1) if i + 1 < len(block_starts_sorted) else fn_end
        blocks.append({"start": s, "end": e, "id": i})
    addr_to_block = {}
    for blk in blocks:
        for a in range(blk["start"], blk["end"] + 1, 2):
            addr_to_block[a] = blk["id"]

    # ----- 3. Build successor edges per block
    for blk in blocks:
        blk["succs"] = []
    for blk in blocks:
        last = blk["end"]
        # Walk back through the block's last instruction (with delay slot accounting)
        # to find the terminating control-flow.
        # Simple: scan from last backwards to find last decodable terminator.
        term_addr = None
        term_mnem = None
        a = blk["start"]
        while a <= blk["end"]:
            off = a - vram
            if off + 1 < len(binary):
                op = (binary[off] << 8) | binary[off + 1]
                mn, _ = decode_sh2(op, a)
                if mn:
                    head = mn.split()[0]
                    if head in {"rts", "rte", "jmp", "braf", "bra", "bsr", "bf", "bt", "bf/s", "bt/s"}:
                        term_addr = a
                        term_mnem = mn
            a += 2

        if term_mnem is None:
            # No branch in this block — falls through to next block by address
            nxt = blk["end"] + 1
            if nxt in addr_to_block:
                blk["succs"].append(addr_to_block[nxt])
            continue

        head = term_mnem.split()[0]
        # Branch with static target
        b = branches_by_src.get(term_addr)
        if head in {"bra"}:
            if b and b.target in addr_to_block:
                blk["succs"].append(addr_to_block[b.target])
        elif head in {"bf", "bt", "bf/s", "bt/s"}:
            # Conditional: target + fall-through-after-delay
            if b and b.target in addr_to_block:
                blk["succs"].append(addr_to_block[b.target])
            delay = 2 if head in {"bf/s", "bt/s"} else 0
            after = term_addr + 2 + delay
            if after in addr_to_block:
                blk["succs"].append(addr_to_block[after])
        elif head in {"rts", "rte"}:
            pass  # no successor (function exit)
        elif head in {"jmp", "braf"}:
            pass  # indirect — no static successor we can resolve
        elif head == "bsr":
            # Call returns; fall-through after delay slot
            after = term_addr + 4
            if after in addr_to_block:
                blk["succs"].append(addr_to_block[after])

    # ----- 4. Identify structured regions
    # Strategy: scan blocks for two patterns:
    #   (a) if/if-else: block ends in conditional, both successors converge
    #   (b) loop: block has back-edge to an earlier block (potential header)
    #
    # For each region found, we store (header_block_id, body_blocks_set,
    # merge_block_id_or_None).  Then assign depth by region nesting.

    regions = []  # each: {header, body, kind, exit}
    n_blocks = len(blocks)

    # Find back-edges (loops) — a successor that points to an earlier block.
    for blk in blocks:
        for s in blk["succs"]:
            if s <= blk["id"]:
                # back-edge: blk is loop tail, target is loop header
                header_id = s
                tail_id = blk["id"]
                # Loop body = blocks reachable from header without going through tail+1
                body = set()
                stack = [header_id]
                while stack:
                    cur = stack.pop()
                    if cur in body or cur > tail_id:
                        continue
                    body.add(cur)
                    for nx in blocks[cur]["succs"]:
                        if nx not in body and nx >= header_id and nx <= tail_id:
                            stack.append(nx)
                regions.append({"kind": "loop", "header": header_id,
                                "body": body, "exit": None})

    # Find if/if-else: block with two successors, both reach a common merge.
    # We compute "reaches" from each block within the function.
    def reaches_from(block_id, stop_at=None):
        visited = set()
        stack = [block_id]
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            if cur == stop_at:
                continue
            for nx in blocks[cur]["succs"]:
                if nx not in visited:
                    stack.append(nx)
        return visited

    for blk in blocks:
        if len(blk["succs"]) != 2:
            continue
        # By construction: succs[0] is the conditional's BRANCHED-TO target,
        # succs[1] is the fall-through.
        target_succ = blk["succs"][0]
        fall_succ = blk["succs"][1]
        if target_succ <= blk["id"] or fall_succ <= blk["id"]:
            continue  # backward (loop) handled separately
        reach_target = reaches_from(target_succ)
        reach_fall = reaches_from(fall_succ)
        common = reach_target & reach_fall
        if not common:
            continue
        merge = min(common)

        # Two structural patterns:
        #
        #   (a) Branched-to has its own body before reaching the merge.
        #       This is bt-with-body or bf-with-bra-to-merge. The branched-to
        #       arm is the "interesting" code — indent it.  Fall-through
        #       (often just bra-to-merge plumbing) stays at outer depth.
        #
        #   (b) Branched-to IS the merge (target_succ == merge). This is the
        #       bf-no-else / skip-the-body pattern: the conditional jumps OVER
        #       the if-body. The fall-through path IS the if-body — indent it.
        #
        # Same C-correct semantics with different ASM expression depending on
        # which condition polarity the compiler chose.
        if target_succ == merge:
            body = reach_fall - {merge}
        else:
            body = reach_target - {merge}
        body = {bid for bid in body if blk["id"] < bid < merge}
        if not body:
            continue
        regions.append({"kind": "if", "header": blk["id"],
                        "body": body, "exit": merge})

    # Drop "if" regions whose body is empty (degenerate — no real nesting)
    regions = [r for r in regions if r["body"]]

    # ----- 5. Build region tree by containment; depth = chain length.
    # A region R1 is "inside" R2 if R1.body ⊆ R2.body and R1.header in R2.body.
    # Sibling case: if both regions share the same exit (merge point), they
    # are NOT nested — they're parallel arms of a dispatch.  This is the
    # difference between a switch (many bts to common end) and a nested
    # if/else (each branch with its own merge).
    def region_contains(outer, inner):
        if outer is inner:
            return False
        if inner["header"] not in outer["body"]:
            return False
        if not inner["body"].issubset(outer["body"]):
            return False
        if (outer.get("exit") is not None
                and outer.get("exit") == inner.get("exit")
                and outer["kind"] == "if" and inner["kind"] == "if"):
            return False
        return True

    # depth of each region = 1 + max depth of any container.
    # Process OUTERMOST first so parent depths are known when children compute.
    region_depth = [0] * len(regions)
    order = sorted(range(len(regions)), key=lambda i: -len(regions[i]["body"]))
    for i in order:
        parent_depth = 0
        for j in range(len(regions)):
            if j == i:
                continue
            if region_contains(regions[j], regions[i]):
                if region_depth[j] > parent_depth:
                    parent_depth = region_depth[j]
        region_depth[i] = parent_depth + 1

    # ----- 6. Assign per-address depth = depth of innermost containing region
    addr_depths = {}
    addr = fn_start
    while addr <= fn_end:
        bid = addr_to_block.get(addr)
        if bid is None:
            addr += 2
            continue
        best_depth = 0
        for ri, r in enumerate(regions):
            if bid in r["body"]:
                if region_depth[ri] > best_depth:
                    best_depth = region_depth[ri]
        if best_depth > 0:
            addr_depths[addr] = best_depth
        addr += 2

    return addr_depths


def _branch_meta(b):
    """Build the per-line branch payload the front-end uses to draw arcs.
    Returns None when there's no internal-with-target branch at this address.
    Shared by instruction emit AND pool emit — when the reference encodes a
    real branch as `.4byte 0xXXXXXXXX` (auto-disassembler mistake), oracle's
    decoder still recognizes the branch and we still want the arc drawn.
    """
    if b is None or b.target is None or not b.internal:
        return None
    arc_type = "cond" if b.mnem in {"bf", "bt", "bf/s", "bt/s"} else "uncond"
    return {
        "target": b.target,
        "type": arc_type,
        "direction": "forward" if b.target > b.src else "backward",
    }


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
            meta = _branch_meta(branches_at.get(addr))
            if meta:
                line["branch"] = meta
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
            meta = _branch_meta(branches_at.get(addr))
            if meta:
                line["branch"] = meta
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

        # Unreachable from function entry — mark visually so the eye stops
        # parsing as flow.  Pool/data addresses are handled above (continue);
        # what's left here is genuine dead-or-data that decode_sh2 happened
        # to spell as a valid mnemonic.
        if addr not in ev.reachable:
            line["classes"].append("unreachable")
            line["indent"] = 0
            if not line.get("tag"):
                line["tag"] = "unreach"

        cat = _classify_mnem(mnem)
        if cat:
            line["classes"].append(cat)

        # Margin direction arrow + tail-call flag.
        # `b` is None if this instruction wasn't visited by the oracle's CFG
        # walk (unreachable from the function entry).  Don't make tail-call
        # claims when we don't know — only when oracle explicitly says external.
        head = mnem.split()[0] if mnem else ""
        b = branches_at.get(addr)

        meta = _branch_meta(b)
        if meta:
            line["branch"] = meta

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
    """Emit raw bytes for intermediate/trailing sections.

    Uses pool_priors to render known pool addresses as `.4byte`/`.2byte` data
    with `.L_pool_*` labels, instead of bogus instruction decodings.
    """
    binary = STATE["binary_cache"]
    vram = STATE["vram_cache"]
    priors = STATE.get("pool_priors", {})
    binary_end = vram + len(binary) - 1
    end = min(end, binary_end)
    addr = start
    while addr <= end:
        off = addr - vram
        if off + 1 >= len(binary):
            break

        # Prior pool entry — emit as pool data
        size = priors.get(addr)
        if size == 4 and addr + 3 <= end and off + 3 < len(binary):
            value = (binary[off] << 24) | (binary[off+1] << 16) | (binary[off+2] << 8) | binary[off+3]
            lines.append({
                "addr": addr,
                "addr_str": f"{addr:08X}",
                "kind": "pool",
                "label": f".L_pool_{addr:08X}",
                "bytes": " ".join(f"{binary[off+i]:02X}" for i in range(4)),
                "mnem": f".4byte 0x{value:08X}",
                "classes": [f"section-{section}", "pool"],
                "margin": "",
            })
            addr += 4
            continue
        if size == 2 and addr + 1 <= end and off + 1 < len(binary):
            value = (binary[off] << 8) | binary[off+1]
            lines.append({
                "addr": addr,
                "addr_str": f"{addr:08X}",
                "kind": "pool",
                "label": f".L_pool_{addr:08X}",
                "bytes": " ".join(f"{binary[off+i]:02X}" for i in range(2)),
                "mnem": f".2byte 0x{value:04X}",
                "classes": [f"section-{section}", "pool"],
                "margin": "",
            })
            addr += 2
            continue

        # Otherwise decode as instruction (best-effort)
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
        prev_ev = analyze_candidate(
            binary, vram, prev_subseg["start"],
            hint_end=prev_subseg["end"],
            pool_priors=STATE.get("pool_priors"),
        )
        # Honor yaml's `end` — that's what the splitter uses to emit race.s.
        # Oracle's CFG-walk may stop earlier (e.g., at a jmp's delay slot,
        # before unreachable bytes the compiler emitted as a dead epilogue).
        # The eval tool's display should reflect what race.s shows, not what
        # oracle's heuristic thinks is "reachable code only."
        prev_ev.end = prev_subseg["end"]
        size = prev_subseg["end"] - prev_subseg["start"] + 1
        _emit_section_header(
            lines, "prev",
            f"VERIFIED  FUN_{prev_subseg['start']:08X}  0x{prev_subseg['start']:08X} → 0x{prev_subseg['end']:08X}  ({size} bytes)",
            anchor_addr=prev_subseg['start'],
        )
        _emit_function_lines(lines, prev_ev, "prev")

        if prev_subseg["end"] + 1 < ev.start:
            _emit_section_header(
                lines, "intermediate",
                f"INTERMEDIATE  0x{prev_subseg['end']+1:08X} → 0x{ev.start-1:08X}  ({ev.start - prev_subseg['end'] - 1} bytes, likely pool/padding)",
                anchor_addr=prev_subseg['end'] + 1,
            )
            _emit_raw_bytes(lines, prev_subseg["end"] + 1, ev.start - 1, "intermediate")

    size = ev.end - ev.start + 1
    _emit_section_header(
        lines, "current",
        f"PROPOSED  FUN_{ev.start:08X}  0x{ev.start:08X} → 0x{ev.end:08X}  ({size} bytes)  verdict: {ev.verdict}",
        anchor_addr=ev.start,
    )
    _emit_function_lines(lines, ev, "current")

    trailing_start = ev.end + 1
    trailing_end = ev.end + TRAILING_BYTES
    binary_end = vram + len(binary) - 1
    if trailing_start <= binary_end:
        actual_end = min(trailing_end, binary_end)
        _emit_section_header(
            lines, "trailing",
            f"TRAILING  0x{trailing_start:08X} → 0x{actual_end:08X}  ({actual_end - trailing_start + 1} bytes after candidate)",
            anchor_addr=trailing_start,
        )
        _emit_raw_bytes(lines, trailing_start, actual_end, "trailing")

    return lines


# ---------------------------------------------------------------------------
# Current-candidate computation (with AI override)
# ---------------------------------------------------------------------------

def _compute_current(ignore_override=False):
    """Return (prev_subseg, evidence) or None.

    If session.json has an `ai_override`, prefer that (unless
    `ignore_override=True`, used to compute the "natural" view shown in
    the diff pane).
    Otherwise run forward-sweep from the latest verified subseg.
    """
    session = load_session()
    binary = STATE["binary_cache"]
    cfg = STATE["cfg_cache"]

    pool_priors = STATE.get("pool_priors") or {}

    override = session.get("ai_override") if not ignore_override else None
    if override:
        prev = override.get("previous_subseg")
        start = _coerce_addr(override["candidate_start"])
        tu = next((t for t in cfg.get("tus", []) if t["start"] <= start <= t["end"]), None)
        hint_end = tu["end"] if tu else None
        ev = analyze_candidate(binary, STATE["vram_cache"], start, hint_end, pool_priors=pool_priors)
        # AI may also pin the END explicitly (one-off boundary correction
        # the oracle's heuristics can't reach).  Apply after analyze_candidate
        # so pool/CFG/epilogue analysis still runs against the natural code
        # end; only the displayed/written boundary is moved.
        end_override = override.get("candidate_end")
        if end_override is not None:
            ev.end = _coerce_addr(end_override)
        return prev, ev

    return find_next_forward_sweep_candidate(
        cfg, binary,
        pool_priors=pool_priors,
        reference_starts=set(STATE.get("reference_starts") or []),
        static_callers=STATE.get("static_callers") or {},
    )


def _coerce_addr(v):
    """Accept either '0x06029E8F' / '06029E8F' (hex string) or 100833423 (int)."""
    if isinstance(v, str):
        return int(v, 16)
    return int(v)


def _reload_caches():
    cfg = load_yaml()
    STATE["cfg_cache"] = cfg
    STATE["binary_cache"] = load_binary(cfg)
    STATE["vram_cache"] = int(cfg["options"]["vram"])
    # Invalidate sibling-pool cache when yaml changes
    STATE["sibling_pool_cache"] = {}
    STATE["pool_priors"] = _load_pool_priors()
    # Reference starts / static callers / runtime hits are static-ish — load
    # once and stash. (Runtime hits could be refreshed after a new BP probe;
    # for now, restart the server to pick up new data.)
    if "reference_starts" not in STATE:
        STATE["reference_starts"] = _load_reference_starts()
    if "static_callers" not in STATE:
        sc_data = _load_static_callers()
        # Oracle's boundary detection only consumes physically-possible
        # callers — same-module hits.  Cross-module hits at hot-swap
        # load addresses can't resolve to this binary, so they go into
        # a parallel dict that the banner shows as informational only.
        STATE["static_callers"] = sc_data["same"]
        STATE["cross_module_callers"] = sc_data["cross"]
    if "runtime_hits" not in STATE:
        STATE["runtime_hits"] = _load_runtime_hits()


def _resolved_dir_option(key):
    """Read a directory path from cfg.options[key] and resolve it relative
    to project_root.  Returns None if the option is absent or the
    resolved path isn't a directory."""
    cfg = STATE.get("cfg_cache") or {}
    val = (cfg.get("options") or {}).get(key)
    if not val:
        return None
    project_root = STATE.get("project_root")
    p = Path(val)
    if not p.is_absolute() and project_root:
        p = (project_root / p).resolve()
    return p if p.is_dir() else None


def _load_reference_starts():
    """Load reference's view of function start addresses.

    Configured via `options.reference_dir` in the yaml: a directory of
    `.s` files containing `FUN_<addr>:` labels (typical splat / Ghidra
    output structure).  Used as an independent confidence check on our
    own boundaries.

    Returns a SORTED list of int addresses, or [] if the option is
    unset or the directory is missing (graceful degradation — the
    reference-agreement banner signal just shows as 'silent' for every
    candidate).
    """
    reference_dir = _resolved_dir_option("reference_dir")
    if reference_dir is None:
        return []
    import re
    starts = set()
    fun_re = re.compile(r"^FUN_([0-9A-Fa-f]{8}):\s*$")
    for s_file in reference_dir.glob("*.s"):
        for raw in s_file.read_text(errors="replace").splitlines():
            m = fun_re.match(raw.strip())
            if m:
                starts.add(int(m.group(1), 16))
    return sorted(starts)


def _load_static_callers():
    """Scan reference .s files for static call references to function addresses.

    Configured via `options.reference_scan_dir` (the cross-module root for
    a recursive glob).  Falls back to `options.reference_dir` (this
    module's reference only) if scan_dir isn't set.

    Counts these as a "call site":
      - bsr / bsr.s / jsr / jmp / bra / braf / bsrf  to  FUN_<addr>  or  xref_FUN_<addr>
      - .4byte FUN_<addr> / xref_FUN_<addr>  (function pointer in a pool,
        intended to be loaded then called via jsr @rN)
      - .4byte DAT_<addr>  ONLY when <addr> is itself in reference_starts
        (so a Ghidra-mis-labeled function pointer counts, but a pool
        ref pointing at interior data doesn't)

    Excludes:
      - `FUN_<addr> + 0xN` (these point INTO the body, not at the entry)
      - Comment-only mentions

    Returns {"same": {addr: count}, "cross": {addr: count}}.  Callers in
    files under `reference_dir` (this binary's module) count as "same";
    everything else under `reference_scan_dir` counts as "cross".  Same-
    binary-load-address modules (hot-swap slots) physically can't call
    each other at runtime, so only `same` is wired into oracle's
    boundary detection — `cross` is surfaced to the human as informational.
    """
    scan_dir = _resolved_dir_option("reference_scan_dir") or _resolved_dir_option("reference_dir")
    if scan_dir is None:
        return {"same": {}, "cross": {}}
    this_module_dir = _resolved_dir_option("reference_dir")
    this_module_resolved = this_module_dir.resolve() if this_module_dir is not None else None
    import re
    same_callers = {}
    cross_callers = {}

    # Direct branches.  "FUN_xxxxxxxx + 0xN" is excluded because the `+`
    # ends the match before the offset is consumed, but we also explicitly
    # check the trailing context to be safe.
    branch_re = re.compile(
        r"\b(?:bsr|bsr\.s|jsr|jmp|bra|braf|bsrf)\b[^/]*?"
        r"\b(?:xref_)?FUN_([0-9A-Fa-f]{8})\b(?!\s*\+)"
    )
    # .4byte FUN_ / xref_FUN_ always counts.  .4byte DAT_ is ambiguous —
    # it can be a real function pointer (Ghidra mis-labeled the target as
    # data) or a genuine data pointer (e.g. into another function's pool
    # zone).  Cross-reference: count DAT_<addr> only when <addr> is itself
    # a known function start in reference_starts.  This catches references
    # like `.4byte DAT_06029810 /* = FUN_06029810 */` while still
    # rejecting `.4byte DAT_06029958 /* = FUN_06029810 + 0x148 */`.
    pool_re_fun = re.compile(
        r"\.4byte\s+(?:xref_FUN_|FUN_)([0-9A-Fa-f]{8})\b(?!\s*\+)"
    )
    pool_re_dat = re.compile(
        r"\.4byte\s+DAT_([0-9A-Fa-f]{8})\b(?!\s*\+)"
    )
    reference_starts = set(STATE.get("reference_starts") or _load_reference_starts())

    for s_file in scan_dir.glob("**/*.s"):
        try:
            text = s_file.read_text(errors="replace")
        except Exception:
            continue
        # Same-module: caller's .s file lives inside this binary's
        # reference_dir.  When reference_dir isn't configured we can't
        # distinguish, so everything lumps into `same` (preserves
        # pre-scoping behavior for single-module setups).
        if this_module_resolved is None:
            bucket = same_callers
        else:
            try:
                in_same = s_file.resolve().is_relative_to(this_module_resolved)
            except (AttributeError, ValueError):
                in_same = str(s_file.resolve()).startswith(str(this_module_resolved))
            bucket = same_callers if in_same else cross_callers
        for line in text.splitlines():
            for m in branch_re.finditer(line):
                addr = int(m.group(1), 16)
                bucket[addr] = bucket.get(addr, 0) + 1
            for m in pool_re_fun.finditer(line):
                addr = int(m.group(1), 16)
                bucket[addr] = bucket.get(addr, 0) + 1
            for m in pool_re_dat.finditer(line):
                addr = int(m.group(1), 16)
                # Only credit DAT_<addr> when addr is itself a reference
                # function start.  Filters out pool refs pointing at
                # interior data.
                if addr in reference_starts:
                    bucket[addr] = bucket.get(addr, 0) + 1
    return {"same": same_callers, "cross": cross_callers}


def _load_runtime_hits():
    """Aggregate BP-pass hit counts across probe summaries.

    Configured via `options.runtime_hits_dirs` in the yaml: a list of
    directories, each globbed for `*.summary.json` files with a
    `by_address: {hex_addr: count}` field (the standard BP-probe
    summary format).  Returns {addr: max_hits} taking the MAX across
    all summaries.

    Why max (not sum):
      - Probes typically overwrite the same hits file, so summing across
        summaries that "point to the same file" sums across distinct
        runs.
      - Summing double-counts re-snapshots of the same probe.
      - Max is robust: highest count observed for the address across
        any probe.  Never overcounts; may understate if a probe was
        strictly partial.

    Returns {} if the option is unset or no summaries exist.
    """
    cfg = STATE.get("cfg_cache") or {}
    dirs = (cfg.get("options") or {}).get("runtime_hits_dirs") or []
    if not dirs:
        return {}
    project_root = STATE.get("project_root")
    hits = {}
    for d in dirs:
        p = Path(d)
        if not p.is_absolute() and project_root:
            p = (project_root / p).resolve()
        if not p.is_dir():
            continue
        for f in p.glob("*.summary.json"):
            try:
                with open(f) as fp:
                    s = json.load(fp)
            except Exception:
                continue
            ba = s.get("by_address") or {}
            for hex_addr, count in ba.items():
                try:
                    addr = int(hex_addr, 16)
                    c = int(count)
                    if c > hits.get(addr, 0):
                        hits[addr] = c
                except (ValueError, TypeError):
                    pass
    return hits


def _compute_candidate_evidence(start, end):
    """Static + runtime evidence for the candidate, plus midpoint warnings.

    A "midpoint" is an reference FUN_<X> start that falls STRICTLY INSIDE
    (start, end] — i.e., reference thinks there's a function start within our
    proposed body.  For each, report its own evidence so the human can judge
    whether to honor reference's split (real entry point) or override it
    (Ghidra hallucination).
    """
    sc = STATE.get("static_callers") or {}
    cm = STATE.get("cross_module_callers") or {}
    rh = STATE.get("runtime_hits") or {}
    reference_starts = STATE.get("reference_starts") or []

    midpoints = []
    for a in reference_starts:
        if start < a <= end:
            midpoints.append({
                "addr": a,
                "addr_hex": f"{a:08X}",
                "static_callers": sc.get(a, 0),
                "cross_module_callers": cm.get(a, 0),
                "runtime_hits": rh.get(a, 0),
            })

    return {
        "static_callers": sc.get(start, 0),
        "cross_module_callers": cm.get(start, 0),
        "runtime_hits": rh.get(start, 0),
        "midpoints": midpoints,
    }


def _compute_reference_agreement(start, end):
    """Compare our (start, end) candidate against the reference's view.

    Returns dict:
      - verdict: "agrees" | "disagrees" | "silent"
      - start_match: bool                  — reference has FUN_<start>?
      - reference_next: int|None             — reference's next FUN start > our start
      - reference_implied_end: int|None      — reference_next - 1 (its view of end)
      - end_delta: int|None                — our_end - reference_implied_end
                                              (positive = we're longer than reference)
      - tooltip: str                       — human-readable summary
    """
    reference_starts = STATE.get("reference_starts") or []
    start_match = start in reference_starts

    reference_next = None
    for a in reference_starts:
        if a > start:
            reference_next = a
            break

    reference_implied_end = (reference_next - 1) if reference_next is not None else None
    end_delta = (end - reference_implied_end) if reference_implied_end is not None else None

    # Tolerance: reference boundaries include pool/padding between functions, so
    # exact end-byte agreement is rare.  Within 16 bytes counts as "agrees".
    TOL = 16

    if not start_match:
        verdict = "silent"
        tooltip = f"reference has no FUN_{start:08X}"
    elif end_delta is None:
        verdict = "agrees"
        tooltip = f"reference start matches; no reference successor (last fn)"
    elif abs(end_delta) <= TOL:
        verdict = "agrees"
        tooltip = (
            f"reference FUN_{start:08X} → next FUN_{reference_next:08X}; "
            f"our end {end_delta:+d} bytes vs reference implied end "
            f"0x{reference_implied_end:08X}"
        )
    else:
        verdict = "disagrees"
        if end_delta > 0:
            tooltip = (
                f"reference thinks function is shorter by {end_delta} bytes "
                f"(reference next FUN_{reference_next:08X} → implied end "
                f"0x{reference_implied_end:08X})"
            )
        else:
            tooltip = (
                f"reference thinks function is longer by {-end_delta} bytes "
                f"(reference next FUN_{reference_next:08X} → implied end "
                f"0x{reference_implied_end:08X})"
            )

    return {
        "verdict": verdict,
        "start_match": start_match,
        "reference_next": reference_next,
        "reference_implied_end": reference_implied_end,
        "end_delta": end_delta,
        "tooltip": tooltip,
    }


def _detect_internal_gaps(proposed_start=None):
    """Find every uncovered byte range BETWEEN consecutive verified code
    subsegs PLUS the pending gap between the latest verified subseg and the
    currently-proposed candidate (if any).

    Why include the pending gap: when forward-sweep can't find a real
    function in a zone (no reference label, no prologue, no callers), it
    skips over to the next function it CAN find — leaving a would-be gap
    that the user will create the instant they approve.  We catch this
    state pre-emptively rather than waiting for the approval to fire the
    banner.

    The actual tail (after the proposed candidate's end) is still
    excluded — that's the unswept frontier ahead of forward-sweep, not a
    gap.

    Returns a list of gap dicts.  Each dict has a `pending: bool` field —
    True means the gap is between latest-stamped and current proposal
    (would be created on approval); False means it already exists in
    the yaml (a real bug to backfill).
    """
    cfg = STATE["cfg_cache"]
    subs = sorted(
        [s for s in cfg.get("subsegments", []) if s.get("type") == "code"],
        key=lambda s: s["start"],
    )
    gaps = []
    prev = None
    for s in subs:
        if prev is not None and s["start"] > prev["end"] + 1:
            gap_start = prev["end"] + 1
            gap_end = s["start"] - 1
            gaps.append({
                "start": gap_start,
                "end": gap_end,
                "start_hex": f"{gap_start:08X}",
                "end_hex": f"{gap_end:08X}",
                "size": gap_end - gap_start + 1,
                "preceding_start": prev["start"],
                "preceding_start_hex": f"{prev['start']:08X}",
                "preceding_end_hex": f"{prev['end']:08X}",
                "preceding_name": f"FUN_{prev['start']:08X}",
                "pending": False,
            })
        prev = s

    # Pending gap between latest verified and the proposed candidate.
    if proposed_start is not None and prev is not None:
        if proposed_start > prev["end"] + 1:
            gap_start = prev["end"] + 1
            gap_end = proposed_start - 1
            gaps.append({
                "start": gap_start,
                "end": gap_end,
                "start_hex": f"{gap_start:08X}",
                "end_hex": f"{gap_end:08X}",
                "size": gap_end - gap_start + 1,
                "preceding_start": prev["start"],
                "preceding_start_hex": f"{prev['start']:08X}",
                "preceding_end_hex": f"{prev['end']:08X}",
                "preceding_name": f"FUN_{prev['start']:08X}",
                "pending": True,
            })
    return gaps


def _compute_progress():
    """Sum verified code subseg bytes vs total binary size.

    Returns dict with verified_bytes, total_bytes, pct (float 0-100).
    """
    cfg = STATE["cfg_cache"]
    binary = STATE["binary_cache"]
    verified = 0
    for s in cfg.get("subsegments", []):
        if s.get("type") == "code":
            verified += s["end"] - s["start"] + 1
    total = len(binary)
    pct = (verified / total * 100.0) if total else 0.0
    return {"verified_bytes": verified, "total_bytes": total, "pct": pct}


def _load_pool_priors():
    """Load pool address priors from <yaml_stem>.pool_priors.txt if present.

    Returns dict {addr: size_in_bytes} where size is 4 (mov.l) or 2 (mov.w).
    These are pool addresses identified by the reference — used to augment our
    own pool detection, so pools referenced from not-yet-verified functions
    still render as proper pool data instead of bogus decoded instructions.
    """
    yaml_path = STATE.get("yaml_path")
    if yaml_path is None:
        return {}
    priors_path = yaml_path.parent / (yaml_path.stem + ".pool_priors.txt")
    if not priors_path.exists():
        return {}
    priors = {}
    for line in priors_path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                priors[int(parts[0], 16)] = int(parts[1])
            except ValueError:
                pass
    return priors


def _sibling_pool_targets(candidate_start, candidate_end):
    """For all verified code subsegs (excluding the candidate itself), find
    PC-relative load targets that land INSIDE [candidate_start, candidate_end].

    This catches pool entries that physically live in the candidate's address
    range but are referenced from sibling functions in the same TU — a common
    Saturn-era compiler/linker pattern where pool constants cluster between
    functions and any sibling can reference any pool there.

    Returns (pool4, pool2, mova) sets of addresses.
    Results cached at module level; invalidated when yaml is reloaded.
    """
    cfg = STATE["cfg_cache"]
    binary = STATE["binary_cache"]
    vram = STATE["vram_cache"]

    p4, p2, pm = set(), set(), set()
    cache = STATE.setdefault("sibling_pool_cache", {})

    for sub in cfg.get("subsegments", []):
        if sub.get("type") != "code":
            continue
        if sub["start"] == candidate_start:
            continue  # skip the candidate itself

        key = sub["start"]
        if key not in cache:
            # Compute reachable set for this sibling (expensive, do once)
            sib_ev = analyze_candidate(binary, vram, sub["start"], hint_end=sub["end"])
            cache[key] = sib_ev.reachable

        sib_reachable = cache[key]
        for addr in sib_reachable:
            off = addr - vram
            if off + 1 >= len(binary):
                continue
            op = (binary[off] << 8) | binary[off + 1]
            mnem, tgt = decode_sh2(op, addr)
            if tgt is None or mnem is None:
                continue
            if not (candidate_start <= tgt <= candidate_end):
                continue
            if mnem.startswith("mov.l @(0x"):
                p4.add(tgt)
            elif mnem.startswith("mov.w @(0x"):
                p2.add(tgt)
            elif mnem.startswith("mova @(0x"):
                pm.add(tgt)

    return p4, p2, pm


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

        progress = _compute_progress()
        history = session.get("history", [])

        if nxt is None:
            return jsonify({
                "all_caught_up": True,
                "history_count": len(history),
                "progress": progress,
                "internal_gaps": _detect_internal_gaps(),
            })

        prev, ev = nxt
        # Pass the proposed candidate's start so the detector ALSO surfaces
        # the gap between latest-stamped and proposal (forward-sweep skipped
        # a real function in that zone) before the user creates it.
        internal_gaps = _detect_internal_gaps(proposed_start=ev.start)

        primary_payload = _build_candidate_payload(prev, ev)

        # When ai_override is active, ALSO compute what oracle would
        # naturally propose without the override.  Shown in a split-pane
        # diff view so the human can compare "what AI redirected to" vs
        # "what oracle's heuristics produced" side by side.
        natural_view = None
        if session.get("ai_override"):
            nat = _compute_current(ignore_override=True)
            if nat:
                nat_prev, nat_ev = nat
                if nat_ev.start != ev.start:
                    natural_view = _build_candidate_payload(nat_prev, nat_ev)

        # Optional `attn` list inside ai_override — addresses the AI wants
        # to draw the human's eye to.  Rendered as a highlighted box around
        # the address + bold-orange last-4-hex-digit in the listing.
        override = session.get("ai_override") or {}
        attn_raw = override.get("attn") or []
        attn_addrs = []
        for a in attn_raw:
            try:
                attn_addrs.append(_coerce_addr(a))
            except (ValueError, TypeError):
                pass

        return jsonify({
            "all_caught_up": False,
            "candidate": primary_payload["candidate"],
            "previous":  primary_payload["previous"],
            "lines":     primary_payload["lines"],
            "natural_view": natural_view,
            "override_active": bool(session.get("ai_override")),
            "attn": attn_addrs,
            "history_count": len(history),
            "progress": progress,
            "internal_gaps": internal_gaps,
        })


def _build_candidate_payload(prev, ev):
    """Package a candidate's full metadata (banner content + listing) for
    one pane of the split view.  Both panes use the same payload shape so
    the frontend renderer can be agnostic to which side it's drawing."""
    reference = _compute_reference_agreement(ev.start, ev.end)
    evidence = _compute_candidate_evidence(ev.start, ev.end)
    lines = render_listing(ev, prev)
    return {
        "candidate": {
            "start_hex": f"{ev.start:08X}",
            "start": ev.start,
            "end_hex": f"{ev.end:08X}",
            "end": ev.end,
            "size": ev.end - ev.start + 1,
            "verdict": ev.verdict,
            "yellow_flags": ev.yellow_flags,
            "name": f"FUN_{ev.start:08X}",
            "reference": reference,
            "evidence": evidence,
        },
        "previous": {
            "start_hex": f"{prev['start']:08X}",
            "name": f"FUN_{prev['start']:08X}",
        } if prev else None,
        "lines": lines,
    }


@app.route("/unstamp", methods=["POST"])
def unstamp():
    """Re-dirty a previously verified subseg so forward-sweep proposes it again.

    Body JSON: {"start": "0x06028DCA"}  (hex string or int)

    Use when an oracle improvement (pool-zone extension, new prologue
    recognition, etc.) means a previously-approved function's boundary
    deserves another look.  The history record from the original approve
    stays intact; the next /state poll will show the function as the
    current candidate again, and a fresh approve appends a new history
    record + writes the new yaml entry.
    """
    data = request.get_json(force=True)
    raw = data.get("start")
    if raw is None:
        return jsonify({"ok": False, "error": "missing 'start'"}), 400
    try:
        addr = _coerce_addr(raw)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad address"}), 400
    with LOCK:
        removed = _remove_subseg_from_yaml(addr)
        if removed:
            # Invalidate cfg_cache so a same-LOCK follow-up endpoint
            # (e.g. /verdict) sees the post-unstamp yaml, not the stale
            # cached subseg list.
            _reload_caches()
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
        _reload_caches()
        nxt = _compute_current()
        if nxt is None:
            return jsonify({"ok": False, "error": "no candidate"}), 400
        prev, ev = nxt

        session = load_session()
        session["ai_override"] = None

        history = session.setdefault("history", [])
        last = history[-1] if history else None
        same_candidate = (
            last is not None
            and last.get("candidate_start") == ev.start
            and last.get("verdict") != "approved"
        )

        if v in ("rejected", "unsure"):
            # No-op if the same candidate is already in a reject/unsure
            # state.  The AI records the human's reasoning into the
            # existing record's `feedback` field out of band.
            if same_candidate and last.get("verdict") in ("rejected", "unsure"):
                save_session(session)
                return jsonify({"ok": True, "no_op": True})
            history.append({
                "verdict": v,
                "candidate_start_hex": f"{ev.start:08X}",
                "candidate_start": ev.start,
                "candidate_end": ev.end,
                "feedback": "",
                "ts": time.time(),
            })
            save_session(session)
            return jsonify({"ok": True})

        # v == "approved"
        if same_candidate:
            # Promote the prior reject/unsure entry to approved (preserves
            # the AI-recorded feedback that explained the prior verdict).
            last["verdict"] = "approved"
            last["candidate_end"] = ev.end
            last["ts"] = time.time()
        else:
            history.append({
                "verdict": "approved",
                "candidate_start_hex": f"{ev.start:08X}",
                "candidate_start": ev.start,
                "candidate_end": ev.end,
                "feedback": "",
                "ts": time.time(),
            })
        tu = next((t for t in STATE["cfg_cache"]["tus"] if t["start"] <= ev.start <= t["end"]), None)
        file_name = tu["name"] if tu else f"tu_{ev.start:08X}"
        _append_subseg_to_yaml(ev.start, ev.end, file_name)
        save_session(session)
        return jsonify({"ok": True})


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

    # When use_reloader=True, Flask spawns a child process where the actual
    # app runs.  WERKZEUG_RUN_MAIN is set in the child.  We only want to:
    #   - print the banner & open the browser tab ONCE, on the parent's
    #     initial launch (NOT on every code-reload restart)
    #   - load caches in the child (so they survive across reloads)
    is_reloader_child = bool(os.environ.get("WERKZEUG_RUN_MAIN"))

    if not is_reloader_child:
        print()
        print(f"  Yaml:         {yaml_path}")
        print(f"  Project root: {project_root}")
        print(f"  Session:      {STATE['session_path']}")
        print(f"  Opening {url} in your browser …")
        print(f"  Auto-reload enabled — saved .py changes will restart the")
        print(f"  server in place; the browser tab will pick up the new")
        print(f"  code on its next /state poll (~1s).")
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
