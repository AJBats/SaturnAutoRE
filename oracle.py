#!/usr/bin/env python3
"""oracle.py — static analyzer for SH-2 function boundaries.

For a candidate function (start address + raw binary + load address),
produces structured evidence the eval tool uses for both verdict and
rendering: prologue range, epilogue range, final rts, conditional rts
list, every branch's source/target/internality, reachability.

Two entry points:
  - analyze_candidate(binary, vram, start) -> FunctionEvidence
  - find_bedrock_candidates(yaml_cfg, binary) -> [FunctionEvidence]
    For each TU with no declared code subsegment at its start, produce
    a candidate function starting at the TU's start address.

CLI test mode:
    python oracle.py <yaml> <project_root>
    python oracle.py <yaml> <project_root> --candidate 0x06029998
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR / "lib"))

from sh2_decode import decode_sh2

BRANCH_MNEMONICS = {"bra", "bsr", "bf", "bt", "bf/s", "bt/s"}
DELAYED_BRANCH = {"bra", "bsr", "bf/s", "bt/s", "jmp", "jsr", "braf", "bsrf", "rts", "rte"}
UNCONDITIONAL_EXIT = {"bra", "jmp", "rts", "rte"}   # control flow does not fall through


@dataclass
class BranchInfo:
    src: int
    target: Optional[int]   # None if register-indirect (jmp @rN, jsr @rN, braf rN, etc.)
    mnem: str               # 'bra', 'bsr', 'bf', 'bf/s', 'jmp', 'jsr', etc.
    internal: bool          # target inside [func.start, func.end] (False if target is None)


@dataclass
class FunctionEvidence:
    start: int
    end: int                            # last byte inclusive
    prologue_range: tuple               # (start, end_inclusive)
    prologue_saved: list                # ['r14', 'r13', ..., 'pr', 'macl']
    prologue_stack: int                 # bytes reserved (negative add #-N, r15 -> N)
    epilogue_range: tuple               # (start, end_inclusive)
    final_rts: Optional[int]            # addr of rts whose delay slot is at end-1
    delay_slot: Optional[int]           # addr of the delay slot instruction
    branches: list = field(default_factory=list)         # BranchInfo
    conditional_rts: list = field(default_factory=list)  # addrs of non-final rts
    pool_targets: list = field(default_factory=list)     # all PC-rel load targets
    reachable: set = field(default_factory=set)          # set of addrs reachable from start
    verdict: str = "UNKNOWN"                              # HIGH | MEDIUM | LOW
    yellow_flags: list = field(default_factory=list)     # strings describing anomalies

    def to_jsonable(self):
        d = asdict(self)
        d["reachable"] = sorted(d["reachable"])
        d["branches"] = [asdict(b) if not isinstance(b, dict) else b for b in self.branches]
        return d


# ---------------------------------------------------------------------------
# Mnemonic predicates
# ---------------------------------------------------------------------------

def _push_register(mnem):
    """If mnem is `mov.l rN, @-r15`, return rN; else None."""
    if not mnem.startswith("mov.l r"):
        return None
    parts = mnem.split()
    if len(parts) != 3 or parts[2] != "@-r15":
        return None
    reg = parts[1].rstrip(",")
    return reg


def _pop_register(mnem):
    """If mnem is `mov.l @r15+, rN` for callee-saved rN (r8-r14), return rN.
    Pops of r0-r7 are argument cleanup, NOT epilogue restoration — skip those.
    """
    if not mnem.startswith("mov.l @r15+, r"):
        return None
    parts = mnem.split()
    if len(parts) != 3:
        return None
    reg = parts[2]
    if reg in {f"r{i}" for i in range(8, 15)}:
        return reg
    return None


def _is_pr_push(mnem):
    return mnem == "sts.l pr, @-r15"


def _is_pr_pop(mnem):
    return mnem == "lds.l @r15+, pr"


def _is_macl_push(mnem):
    return mnem == "sts.l macl, @-r15"


def _is_macl_pop(mnem):
    return mnem == "lds.l @r15+, macl"


def _is_stack_alloc(mnem):
    """add #-N, r15 — returns N (positive) or None."""
    if not mnem.startswith("add #-"):
        return None
    parts = mnem.split()
    if len(parts) != 3 or parts[2] != "r15":
        return None
    imm = parts[1].rstrip(",")
    if not imm.startswith("#-0x"):
        return None
    try:
        return int(imm[4:], 16)
    except ValueError:
        return None


def _is_stack_dealloc(mnem):
    """add #N, r15 — returns N or None."""
    if not mnem.startswith("add #") or mnem.startswith("add #-"):
        return None
    parts = mnem.split()
    if len(parts) != 3 or parts[2] != "r15":
        return None
    imm = parts[1].rstrip(",")
    if not imm.startswith("#0x"):
        return None
    try:
        return int(imm[3:], 16)
    except ValueError:
        return None


def _branch_target(mnem):
    """If mnem is a direct branch (bra/bsr/bf/bt/...), return target addr; else None."""
    parts = mnem.split()
    if not parts or parts[0] not in BRANCH_MNEMONICS:
        return None
    if len(parts) < 2:
        return None
    try:
        return int(parts[1].rstrip(","), 16)
    except ValueError:
        return None


def _is_indirect_branch(mnem):
    """jmp @rN / jsr @rN / braf rN / bsrf rN — control flow with no static target."""
    parts = mnem.split()
    if not parts:
        return False
    head = parts[0]
    return head in {"jmp", "jsr", "braf", "bsrf"}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _read_opcode(binary, vram, addr):
    off = addr - vram
    if off + 1 >= len(binary):
        return None
    return (binary[off] << 8) | binary[off + 1]


def _walk_prologue(binary, vram, start):
    """Walk forward from `start` recognizing prologue instructions.

    GCC schedulers can interleave non-prologue ops (tst, mov #imm, etc.)
    between register pushes. We allow up to MAX_INTERLEAVE consecutive
    non-prologue instructions before stopping. Anything obviously past
    prologue (branches, calls, returns) stops immediately.

    Returns:
      prologue_end_addr  — addr of LAST prologue instruction (inclusive)
      saved              — list of register names saved (in push order)
      stack              — bytes reserved by `add #-N, r15`, or 0
      flags              — list of yellow flag strings
    """
    MAX_INTERLEAVE = 6  # consecutive non-prologue allowed (GCC scheduler can
                         # interleave several tst/mov-imm/etc. ops between
                         # register pushes — observed up to 4 in FUN_060295DE)
    HARD_STOPS = ("rts", "rte", "bra", "bsr", "bf", "bt", "jmp", "jsr", "braf", "bsrf")

    saved = []
    stack = 0
    flags = []
    addr = start
    last_prologue = start - 2
    consecutive_non_prologue = 0

    while True:
        op = _read_opcode(binary, vram, addr)
        if op is None:
            break
        mnem, _ = decode_sh2(op, addr)
        if mnem is None:
            break

        head = mnem.split()[0] if mnem else ""
        if head in HARD_STOPS:
            break

        reg = _push_register(mnem)
        if reg and reg in {f"r{i}" for i in range(8, 15)}:
            saved.append(reg)
            last_prologue = addr
            consecutive_non_prologue = 0
        elif _is_pr_push(mnem):
            saved.append("pr")
            last_prologue = addr
            consecutive_non_prologue = 0
        elif _is_macl_push(mnem):
            saved.append("macl")
            last_prologue = addr
            consecutive_non_prologue = 0
        elif _is_stack_alloc(mnem) is not None:
            stack = _is_stack_alloc(mnem)
            last_prologue = addr
            break  # add to r15 ends prologue cleanly
        else:
            consecutive_non_prologue += 1
            if consecutive_non_prologue > MAX_INTERLEAVE:
                break

        addr += 2

    return last_prologue, saved, stack, flags


def _walk_epilogue_backward(binary, vram, end, func_start=None):
    """Walk backward from `end` (last byte) recognizing epilogue instructions.

    Returns:
      epilogue_start_addr
      restored           — list of register names restored (in pop order, last in delay slot)
      stack              — bytes deallocated by `add #N, r15`
      final_rts          — addr of the rts
      delay_slot_addr    — addr of the delay-slot instruction (== end - 1 effectively)
    """
    # End is inclusive. Delay slot instruction occupies (end - 1, end).
    delay_slot = end - 1
    rts_addr = delay_slot - 2

    op_rts = _read_opcode(binary, vram, rts_addr)
    mnem_rts, _ = decode_sh2(op_rts, rts_addr) if op_rts is not None else (None, None)

    if mnem_rts != "rts":
        return None, [], 0, None, None  # epilogue not at expected location

    # Delay slot is the last "epilogue" instruction (often a register pop).
    op_ds = _read_opcode(binary, vram, delay_slot)
    mnem_ds, _ = decode_sh2(op_ds, delay_slot) if op_ds is not None else (None, None)

    restored = []
    ds_pop = _pop_register(mnem_ds) if mnem_ds else None

    # Walk backward from rts_addr - 2 collecting register pops, pr/macl pops, stack dealloc.
    # Bound by func_start so we don't scan past the function's prologue into prior bytes.
    epilogue_start = rts_addr
    addr = rts_addr - 2
    stack = 0
    lower_bound = func_start if func_start is not None else 0
    while addr >= lower_bound:
        op = _read_opcode(binary, vram, addr)
        if op is None:
            break
        mnem, _ = decode_sh2(op, addr)
        if mnem is None:
            break
        reg = _pop_register(mnem)
        if reg:
            restored.insert(0, reg)
            epilogue_start = addr
        elif _is_pr_pop(mnem):
            restored.insert(0, "pr")
            epilogue_start = addr
        elif _is_macl_pop(mnem):
            restored.insert(0, "macl")
            epilogue_start = addr
        elif _is_stack_dealloc(mnem) is not None:
            stack = _is_stack_dealloc(mnem)
            epilogue_start = addr
        else:
            break  # not epilogue-ish, stop scanning back
        addr -= 2

    # Append delay-slot pop last (if it is a pop)
    if ds_pop:
        restored.append(ds_pop)

    return epilogue_start, restored, stack, rts_addr, delay_slot


def _control_flow_walk(binary, vram, start, hard_limit_addr):
    """Walk reachable addresses from `start` via control flow.

    Stops at:
      - unconditional terminators (rts/rte/bra/jmp)
      - indirect branches (jmp @rN) — control flow continues into delay slot
        and then terminates (no static target to follow)
      - hard_limit_addr (don't walk past it)

    Returns:
      reachable     — set of addrs that are instruction starts visited
      max_reachable — highest addr in reachable
      branches      — list of BranchInfo (collected during walk)
      indirect_calls — list of addrs where indirect branches occurred (for marking)
    """
    reachable = set()
    branches = []
    indirect = []
    worklist = [start]
    while worklist:
        pc = worklist.pop()
        while True:
            if pc > hard_limit_addr or pc in reachable:
                break
            reachable.add(pc)
            op = _read_opcode(binary, vram, pc)
            if op is None:
                break
            mnem, _ = decode_sh2(op, pc)
            if mnem is None:
                # Unknown opcode — assume linear continue.
                pc += 2
                continue

            head = mnem.split()[0] if mnem else ""

            # Direct branch with static target
            if head in BRANCH_MNEMONICS:
                tgt = _branch_target(mnem)
                b = BranchInfo(src=pc, target=tgt, mnem=head, internal=False)  # internal set later
                branches.append(b)
                # bsr is a CALL (control returns) — don't follow target, fall through after delay slot
                is_call = head == "bsr"
                # delay-slot branches: bra, bsr, bf/s, bt/s
                if head in {"bf/s", "bt/s", "bra", "bsr"}:
                    reachable.add(pc + 2)
                    if tgt is not None and tgt not in reachable and not is_call:
                        worklist.append(tgt)
                    if head == "bra":
                        # unconditional jump — control does NOT fall through past delay slot
                        break
                    # bsr / bf/s / bt/s — fall through after delay slot
                    pc += 4
                    continue
                else:
                    # bf, bt: no delay slot; fall through to pc+2
                    if tgt is not None and tgt not in reachable:
                        worklist.append(tgt)
                    pc += 2
                    continue

            # Indirect branch
            if _is_indirect_branch(mnem):
                indirect.append(pc)
                # Delay slot is reached
                reachable.add(pc + 2)
                if head in {"jmp", "braf"}:
                    # unconditional — terminates
                    break
                # jsr/bsrf — call returns, fall through
                pc += 4
                continue

            # rts / rte (unconditional, with delay slot)
            if head in {"rts", "rte"}:
                reachable.add(pc + 2)
                break

            pc += 2

    max_reachable = max(reachable) if reachable else start
    return reachable, max_reachable, branches, indirect


def _classify_branch_internality(branches, start, end):
    for b in branches:
        if b.target is not None and start <= b.target <= end:
            b.internal = True
        else:
            b.internal = False
    return branches


def _extend_through_trailing_pools(end, binary, vram, hint_end, pool_priors):
    """Walk forward from `end + 1` swallowing contiguous pool-prior entries.

    SH-2 PC-relative loads (mov.l/mov.w @(disp,PC),Rn) can only reach forward
    ~1KB, so GCC scatters small literal pools into .text — most commonly as a
    trailing zone after the function's last reachable instruction.  Archive
    convention (and the eval-tool convention we settled on) treats those
    pools as part of the function: they're only-reachable-from-here, they're
    PC-bound to this function, and lumping them in matches Ghidra-style
    boundaries.

    We extend by walking forward from `end + 1`, consuming any address that
    appears in `pool_priors` (the archive-extracted pool address → size map).
    Stop at the first byte that's NOT in priors — typically the next
    function's prologue, since the pool zone ends exactly where the next
    function begins.

    Returns the new end address (inclusive), or the original `end` if no
    extension applies.
    """
    if not pool_priors:
        return end
    binary_end = vram + len(binary) - 1
    cap = min(hint_end if hint_end is not None else binary_end, binary_end)
    addr = end + 1
    while addr <= cap:
        size = pool_priors.get(addr)
        if size is None:
            # No prior at this address.  Pool tables are 4-byte aligned, so
            # 2 bytes of zero padding between the last code byte and the
            # first .4byte entry is normal.  Peek ahead through 2- and
            # 4-byte zero gaps to see if we can bridge to the next prior.
            bridged = None
            for pad in (2, 4):
                check = addr + pad
                if check > cap or pool_priors.get(check) is None:
                    continue
                off = addr - vram
                if off + pad > len(binary):
                    continue
                if all(binary[off + i] == 0 for i in range(pad)):
                    bridged = check
                    break
            if bridged is None:
                break
            end = bridged - 1   # the padding bytes are part of this fn
            addr = bridged
            continue
        new_end = addr + size - 1
        if new_end > cap:
            break
        end = new_end
        addr = new_end + 1
    return end


def analyze_candidate(binary, vram, start, hint_end=None, pool_priors=None):
    """Static analysis for a function starting at `start`.

    hint_end caps the control flow walk (avoids running off into the next TU
    if a branch goes there). Pass tu.end or sub.end if known.

    pool_priors (optional): archive-derived {addr: size} map.  When provided,
    the returned `end` is extended forward through contiguous pool entries
    (the function's trailing literal-pool zone), matching archive convention.
    """
    binary_max = vram + len(binary) - 1
    hard_limit = hint_end if hint_end is not None else binary_max

    # Walk prologue
    prologue_end, saved, stack_alloc, flags = _walk_prologue(binary, vram, start)
    prologue_range = (start, prologue_end)

    # Walk forward to find reachable extent
    reachable, max_reachable, branches, indirect = _control_flow_walk(
        binary, vram, start, hard_limit
    )

    # The last byte of the function is the last byte of the last reachable instruction.
    # For rts/rte/bra with delay slots, the delay slot's 2nd byte is the end.
    code_end = max_reachable + 1  # +1 because reachable contains instruction-start addrs

    # Walk epilogue backward from the LAST CODE BYTE (not the post-extension
    # boundary).  Epilogue detection has to see real instructions; pool data
    # would scramble it.
    epi_start, restored, stack_dealloc, final_rts, delay_slot = _walk_epilogue_backward(
        binary, vram, code_end, func_start=start
    )
    epilogue_range = (epi_start, code_end) if epi_start is not None else (None, None)

    # Now extend the boundary through any trailing pool zone (no-op if
    # pool_priors not provided).
    end = _extend_through_trailing_pools(code_end, binary, vram, hard_limit, pool_priors)

    # Find conditional rts (rts that are NOT the final one)
    conditional_rts = []
    for addr in sorted(reachable):
        op = _read_opcode(binary, vram, addr)
        if op is None:
            continue
        mnem, _ = decode_sh2(op, addr)
        if mnem and mnem.startswith("rts") and addr != final_rts:
            conditional_rts.append(addr)

    # Classify branches as internal/external relative to [start, end]
    branches = _classify_branch_internality(branches, start, end)

    # Collect pool targets (re-scan reachable instructions)
    pool_targets = []
    for addr in sorted(reachable):
        op = _read_opcode(binary, vram, addr)
        if op is None:
            continue
        _, tgt = decode_sh2(op, addr)
        if tgt is not None:
            pool_targets.append(tgt)

    # Build verdict
    verdict, yellow = _verdict(
        saved, stack_alloc, restored, stack_dealloc,
        final_rts, branches, conditional_rts
    )
    flags.extend(yellow)

    return FunctionEvidence(
        start=start,
        end=end,
        prologue_range=prologue_range,
        prologue_saved=saved,
        prologue_stack=stack_alloc,
        epilogue_range=epilogue_range,
        final_rts=final_rts,
        delay_slot=delay_slot,
        branches=branches,
        conditional_rts=conditional_rts,
        pool_targets=pool_targets,
        reachable=reachable,
        verdict=verdict,
        yellow_flags=flags,
    )


def _verdict(saved, stack_alloc, restored, stack_dealloc, final_rts, branches, conditional_rts):
    flags = []
    score = 0
    max_score = 4

    if final_rts is None:
        flags.append("no clean rts at expected position")
        return "LOW", flags
    score += 1

    if not saved:
        flags.append("no prologue register pushes detected")
    else:
        score += 1

    if stack_alloc != stack_dealloc:
        flags.append(f"stack alloc/dealloc mismatch: {stack_alloc} vs {stack_dealloc}")
    else:
        score += 1

    # Check prologue/epilogue register correspondence
    # Push order: high-to-low. Pop order: low-to-high. So reversed(saved) == restored, modulo pr/macl handling.
    saved_norm = [r for r in saved if r != "pr" and r != "macl"]
    restored_norm = [r for r in restored if r != "pr" and r != "macl"]
    if saved_norm and list(reversed(saved_norm)) != restored_norm:
        flags.append(f"prologue/epilogue register mismatch: pushed {saved}, restored {restored}")
    else:
        score += 1

    if conditional_rts:
        flags.append(f"{len(conditional_rts)} conditional rts (not necessarily wrong, but worth eye)")

    external_branches = [b for b in branches if not b.internal and b.target is not None]
    bras_external = [b for b in external_branches if b.mnem == "bra"]
    if bras_external:
        flags.append(f"{len(bras_external)} unconditional bra exits to outside function")

    if score == max_score and not flags:
        return "HIGH", flags
    if score >= 3:
        return "MEDIUM", flags
    return "LOW", flags


# ---------------------------------------------------------------------------
# Candidate discovery (forward-sweep)
# ---------------------------------------------------------------------------

# Function-start signals — patterns that strongly suggest "a function begins
# at this address." Used to scan past pool/data zones between functions.
_FN_START_PREFIXES = (
    "mov.l r8, @-r15", "mov.l r9, @-r15", "mov.l r10, @-r15",
    "mov.l r11, @-r15", "mov.l r12, @-r15", "mov.l r13, @-r15",
    "mov.l r14, @-r15",
    "sts.l pr, @-r15", "sts.l macl, @-r15",
)


def _looks_like_fn_start(mnem):
    if not mnem:
        return False
    for prefix in _FN_START_PREFIXES:
        if mnem == prefix or mnem.startswith(prefix):
            return True
    return False


def _scan_for_next_prologue(binary, vram, start_addr, max_addr):
    """Walk forward from start_addr looking for a likely function start.
    Returns the first matching address, or None if nothing plausible found
    before max_addr.
    """
    addr = (start_addr + 1) & ~1  # round up to 2-byte alignment
    while addr <= max_addr:
        off = addr - vram
        if off + 1 >= len(binary):
            return None
        opcode = (binary[off] << 8) | binary[off + 1]
        mnem, _ = decode_sh2(opcode, addr)
        if _looks_like_fn_start(mnem):
            return addr
        addr += 2
    return None


def find_next_forward_sweep_candidate(yaml_cfg, binary, pool_priors=None):
    """Forward-sweep candidate generation.

    Sorts verified code subsegs by start. For each, scans the bytes
    immediately after `end` looking for the next function-start pattern.
    Returns the FIRST such candidate that isn't already a verified subseg.

    pool_priors propagates into analyze_candidate so the returned evidence's
    `end` already includes the function's trailing pool zone.

    Returns (previous_subseg_dict, FunctionEvidence) or None if all caught up.
    """
    vram = int(yaml_cfg["options"]["vram"])
    tus = yaml_cfg.get("tus", [])
    subsegs = yaml_cfg.get("subsegments", [])
    declared_code = sorted(
        [s for s in subsegs if s.get("type") == "code"],
        key=lambda s: s["start"],
    )
    declared_starts = {s["start"] for s in declared_code}

    binary_end = vram + len(binary) - 1

    for prev in declared_code:
        next_start = _scan_for_next_prologue(binary, vram, prev["end"] + 1, binary_end)
        if next_start is None:
            continue
        if next_start in declared_starts:
            # The function right after `prev` is already verified — move on
            # to look after the next verified subseg.
            continue
        # Hint analysis bounds to the TU containing the candidate
        tu = next((t for t in tus if t["start"] <= next_start <= t["end"]), None)
        hint_end = tu["end"] if tu else None
        ev = analyze_candidate(binary, vram, next_start, hint_end, pool_priors=pool_priors)
        return (prev, ev)

    return None


# Legacy name kept for any callers that still reference it.
def find_bedrock_candidates(yaml_cfg, binary):
    """DEPRECATED: forward-sweep replaces TU-head batch generation.
    Returned only for back-compat with older callers; prefer
    find_next_forward_sweep_candidate.
    """
    one = find_next_forward_sweep_candidate(yaml_cfg, binary)
    return [one] if one else []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_evidence(tu, ev):
    print(f"--- TU {tu['name']} ---")
    print(f"  Start:        0x{ev.start:08X}")
    print(f"  End:          0x{ev.end:08X}  ({ev.end - ev.start + 1} bytes)")
    print(f"  Prologue:     0x{ev.prologue_range[0]:08X}-0x{ev.prologue_range[1]:08X}  saved={ev.prologue_saved}  stack={ev.prologue_stack}")
    if ev.epilogue_range[0]:
        print(f"  Epilogue:     0x{ev.epilogue_range[0]:08X}-0x{ev.epilogue_range[1]:08X}")
    print(f"  Final rts:    0x{ev.final_rts:08X}" if ev.final_rts else "  Final rts:    NOT FOUND")
    print(f"  Cond rts:     {len(ev.conditional_rts)}  {[hex(a) for a in ev.conditional_rts[:5]]}")
    ext = [b for b in ev.branches if not b.internal and b.target is not None]
    print(f"  Branches:     {len(ev.branches)} total, {len(ext)} external")
    print(f"  Verdict:      {ev.verdict}")
    if ev.yellow_flags:
        for f in ev.yellow_flags:
            print(f"    flag: {f}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("yaml_path")
    p.add_argument("project_root")
    p.add_argument("--candidate", help="hex address of a single candidate to analyze")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = p.parse_args()

    with open(args.yaml_path) as f:
        cfg = yaml.safe_load(f)
    target = Path(args.project_root) / cfg["options"]["target_path"]
    binary = open(target, "rb").read()
    vram = int(cfg["options"]["vram"])

    if args.candidate:
        addr = int(args.candidate, 16)
        # Find which TU it falls in for hint_end
        tu = None
        for t in cfg.get("tus", []):
            if t["start"] <= addr <= t["end"]:
                tu = t
                break
        ev = analyze_candidate(binary, vram, addr, hint_end=tu["end"] if tu else None)
        if args.json:
            print(json.dumps(ev.to_jsonable(), indent=2))
        else:
            fake_tu = tu or {"name": f"<addr 0x{addr:08X}>"}
            _print_evidence(fake_tu, ev)
        return

    # No candidate specified: forward-sweep the next candidate from current
    # verified state. Prints just one (the frontier of forward-sweep).
    nxt = find_next_forward_sweep_candidate(cfg, binary)
    if nxt is None:
        print("No more forward-sweep candidates — all verified subsegs are caught up.")
        return
    prev, ev = nxt
    print(f"Next candidate after verified FUN_{prev['start']:08X} (ends 0x{prev['end']:08X}):")
    fake_tu = {"name": f"FUN_{ev.start:08X}"}
    _print_evidence(fake_tu, ev)


if __name__ == "__main__":
    main()
