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
    """If mnem is `mov.l @r15+, rN` for any rN in r0-r14, return rN.

    Originally only r8-r14 (callee-saved) counted as epilogue restoration on
    the theory that r0-r7 pops were argument cleanup mid-function.  But tiny
    helper functions that only push r0-r7 in their prologue also need their
    pops recognized as the epilogue, or the walker bails immediately.  Mid-
    function scratch pop/push pairs are safely far from the rts — the
    epilogue walker's MAX_INTERLEAVE tolerance prevents the walker from
    reaching them.
    """
    if not mnem.startswith("mov.l @r15+, r"):
        return None
    parts = mnem.split()
    if len(parts) != 3:
        return None
    reg = parts[2]
    if reg in {f"r{i}" for i in range(0, 15)}:
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
        if reg and reg in {f"r{i}" for i in range(0, 15)}:
            # Track scratch (r0-r7) AND callee-saved (r8-r14) pushes the
            # same way.  Tiny helper functions (memclr/memcpy-style loops)
            # only save scratch regs and were otherwise getting a false
            # "no prologue register pushes detected" yellow flag.  Mid-fn
            # save-around-jsr pairs are well past the prologue boundary,
            # protected by consecutive_non_prologue tolerance.
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


_EPI_HARD_STOPS = ("rts", "rte", "bra", "bsr", "bf", "bt", "bf/s", "bt/s",
                    "jmp", "jsr", "braf", "bsrf")


def _walk_epilogue_backward(binary, vram, end, func_start=None, saved=None):
    """Walk backward from `end` (last byte) recognizing epilogue instructions.

    Stop criteria (semantically grounded, no magic interleave count):
      1. Every pop we accept must match the prologue's `saved` list at the
         next expected position.  Push order forward → pop order forward
         is REVERSED(saved) → walking backward through pops the order is
         `saved` itself.  When `expected_idx` reaches `len(saved)`, any
         further pop encountered is body code (e.g. a `mov.l @r15+, r0`
         that pairs with a mid-function `mov.l r13, @-r15` scratch save
         from before a jsr) — stop.
      2. Hard-stop on control flow (`bsr/jsr/bf/bt/bra/...`).  The
         epilogue lives in a single linear basic block ending in `rts`;
         a branch instruction means we've crossed into the prior block.
      3. Bounded interleave tolerance for true noise (e.g. an
         `extu.b r0, r0` value-shape fixup between matched pops).  This
         only ticks BETWEEN matches; once `expected_idx` is exhausted the
         next non-match terminates immediately.
      4. Stack dealloc (`add #N, r15`) is recorded separately — not in
         `saved`, so it doesn't advance expected_idx but it does reset
         the interleave counter.

    `saved` is the list returned by `_walk_prologue` (in push order).
    If omitted or empty, the walker is in "best-effort" mode: it'll
    only succeed if there's literally nothing between rts and func_start
    that needs structured matching.

    Returns:
      epilogue_start_addr
      restored           — list of register names restored, in forward
                           execution order (first popped first, delay
                           slot last)
      stack              — bytes deallocated by `add #N, r15`
      final_rts          — addr of the rts
      delay_slot_addr    — addr of the delay-slot instruction
    """
    saved = saved or []
    expected = list(saved)  # walking backward, expected pop order == saved

    delay_slot = end - 1
    rts_addr = delay_slot - 2

    op_rts = _read_opcode(binary, vram, rts_addr)
    mnem_rts, _ = decode_sh2(op_rts, rts_addr) if op_rts is not None else (None, None)
    # Accept four legitimate exit forms (all have a delay slot):
    #   - rts            : standard return (pops PC from PR)
    #   - jmp @Rn        : indirect tail call — control transfers to Rn
    #                       and that function's rts returns to OUR caller
    #                       (we've already restored PR to caller's value).
    #   - braf Rn        : PC-relative indirect tail call.
    #   - bra disp       : direct PC-relative tail call (target encoded
    #                       in the opcode, ±4KB range).  GCC emits this
    #                       when the tail-call target is statically known
    #                       and nearby; functionally identical to jmp @Rn
    #                       for the caller's accounting.
    # All four are followed by a delay slot which GCC commonly schedules
    # the last epilogue pop into.
    exit_head = mnem_rts.split()[0] if mnem_rts else ""
    if exit_head not in ("rts", "jmp", "braf", "bra"):
        return None, [], 0, None, None

    # Delay slot is conceptually the FIRST step of our backward walk.
    # If it's a pop (r0-r14, pr, or macl) and matches expected[0], consume
    # it.  GCC commonly schedules the LAST epilogue pop into the delay
    # slot of rts — including `lds.l @r15+, macl` for the macl restore
    # (e.g. tiny math helpers like mini-fn 0x0602C020).
    op_ds = _read_opcode(binary, vram, delay_slot)
    mnem_ds, _ = decode_sh2(op_ds, delay_slot) if op_ds is not None else (None, None)
    ds_pop_reg = None
    if mnem_ds:
        ds_pop_reg = (_pop_register(mnem_ds)
                      or ("pr" if _is_pr_pop(mnem_ds) else None)
                      or ("macl" if _is_macl_pop(mnem_ds) else None))
    delay_slot_consumed = False
    if ds_pop_reg and expected and ds_pop_reg == expected[0]:
        delay_slot_consumed = True
        expected_idx = 1
    else:
        # Either not a pop, or doesn't match expected[0] — leave it out
        # so the match check downstream doesn't get a phantom mismatch.
        expected_idx = 0

    MAX_INTERLEAVE = 6
    matches = []                      # pops captured in walk order
    matched_stack = 0
    matched_stack_addr = None
    epilogue_start = rts_addr
    addr = rts_addr - 2
    lower_bound = func_start if func_start is not None else 0
    consecutive_non_epi = 0

    while addr >= lower_bound:
        op = _read_opcode(binary, vram, addr)
        if op is None:
            break
        mnem, _ = decode_sh2(op, addr)
        if mnem is None:
            break
        head = mnem.split()[0] if mnem else ""

        # Hard stop on control flow.  Epilogue is single-block.
        if head in _EPI_HARD_STOPS:
            break

        # Hard stop on a stack PUSH (mov.l rN, @-r15 / sts.l pr/macl,
        # @-r15).  Pushes are unambiguously body code — they decrement
        # r15 to save a value mid-function (commonly to free up an arg
        # register before a jsr).  An epilogue never pushes.  Stopping
        # here prevents the walker from sliding past the body boundary
        # and picking up mid-body deallocs as if they were epilogue
        # deallocs (the false-alarm case that fires the
        # stack-alloc/dealloc-mismatch flag).
        if (_push_register(mnem) is not None
                or mnem == "sts.l pr, @-r15"
                or mnem == "sts.l macl, @-r15"):
            break

        # Pop / pr-pop / macl-pop: must match expected sequence.
        reg = _pop_register(mnem)
        is_pr = _is_pr_pop(mnem)
        is_macl = _is_macl_pop(mnem)
        dealloc = _is_stack_dealloc(mnem)

        if reg or is_pr or is_macl:
            popped = reg or ("pr" if is_pr else "macl")
            if expected_idx < len(expected) and popped == expected[expected_idx]:
                matches.append(popped)
                expected_idx += 1
                epilogue_start = addr
                consecutive_non_epi = 0
            else:
                # Pop without a matching slot in `saved` → body code, stop.
                break
        elif dealloc is not None:
            # Capture only the FIRST dealloc encountered walking backward
            # (= LAST in forward execution = the epilogue's own dealloc,
            # which sits immediately before the pops).  Any subsequent
            # dealloc found walking backward is body code (e.g. a bulk
            # `add #+0xC, r15` that cleans up mid-life pushes used as
            # scratch around an internal jsr).  Without this guard the
            # walker overwrites matched_stack with the body dealloc and
            # the verdict fires a phantom alloc/dealloc mismatch.
            if matched_stack_addr is not None:
                break
            matched_stack = dealloc
            matched_stack_addr = addr
            epilogue_start = addr
            consecutive_non_epi = 0
        else:
            consecutive_non_epi += 1
            if consecutive_non_epi > MAX_INTERLEAVE:
                break

        addr -= 2

    # Build `restored` in forward execution order.  Walking backward we
    # collected matches in the order: r14, r13, ..., pr, macl.  Forward
    # execution pops them in reverse: macl, pr, ..., r13, r14.  Delay slot
    # pop (if matched) executes LAST → goes at the end.
    restored = list(reversed(matches))
    if delay_slot_consumed:
        restored.append(ds_pop_reg)

    return epilogue_start, restored, matched_stack, rts_addr, delay_slot


def _detect_braf_switch_targets(binary, vram, braf_pc, pool_priors,
                                 func_start=None, hard_limit=None):
    """Recognize the GCC SH-2 switch-dispatch idiom around `braf_pc`.

    Idiom (within ~12 bytes before braf):

        mova @(disp,PC), r0    ; loads jump-table base into r0
        mov.w @(r0,rN), r0     ; loads .short offset for case rN
        braf r0                 ; jumps to (PC+4) + sign-extended offset
        <delay slot>

    The jump table is a contiguous run of `.short` entries; each entry's
    value is `target - (braf_pc + 4)` (i.e. relative to the braf's
    delay-slot base, NOT the table's own base — this is a quirk of GCC's
    SH-2 switch lowering).  We walk the table while pool_priors marks
    consecutive 2-byte slots and stop at the first non-prior address.

    Returns list[int] of target addresses (possibly empty).
    """
    if not pool_priors:
        return []

    # Confirm: braf r0 specifically (GCC default).  Other registers possible
    # but rare; handle later if a real case crops up.
    braf_op = _read_opcode(binary, vram, braf_pc)
    if braf_op is None or (braf_op & 0xF0FF) != 0x0023:
        return []
    braf_reg = (braf_op >> 8) & 0xF
    if braf_reg != 0:
        return []

    # Scan back up to 12 bytes for the mova + mov.w pair.  The compiler may
    # schedule an unrelated instruction or two between them, so we don't
    # require strict adjacency.
    movw_seen = False
    table_base = None
    for back in range(2, 14, 2):
        addr = braf_pc - back
        if addr < vram:
            break
        op = _read_opcode(binary, vram, addr)
        if op is None:
            continue
        # mov.w @(r0, rM), r0  encoding 0000 0000 mmmm 1101  (dest r0)
        if (op & 0xF00F) == 0x000D and ((op >> 8) & 0xF) == 0:
            movw_seen = True
            continue
        # mova @(disp, PC), r0  encoding 11000111 dddddddd
        if (op & 0xFF00) == 0xC700:
            disp = (op & 0xFF) * 4
            # SH-2 mova: r0 = (PC & ~3) + 4 + disp, where PC == addr of mova
            table_base = ((addr + 4) & ~3) + disp
            break

    if not movw_seen or table_base is None:
        return []

    # Read .short entries while pool_priors marks consecutive 2-byte slots.
    # Each computed target must land inside the function's range; the
    # .short is signed-extended so a stray high-bit value can produce a
    # huge negative offset that'd otherwise seed _control_flow_walk with
    # garbage addresses and inflate ev.end.
    lo = func_start if func_start is not None else vram
    hi = hard_limit if hard_limit is not None else (vram + len(binary) - 1)
    targets = []
    t = table_base
    while pool_priors.get(t) == 2:
        off = t - vram
        if off + 1 >= len(binary):
            break
        raw = (binary[off] << 8) | binary[off + 1]
        # Sign-extend 16-bit (mov.w sign-extends on load).
        sval = raw - 0x10000 if raw & 0x8000 else raw
        target = braf_pc + 4 + sval
        if lo <= target <= hi:
            targets.append(target)
        t += 2

    return targets


def _control_flow_walk(binary, vram, start, hard_limit_addr, pool_priors=None):
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
                # Don't follow branches whose target lands OUTSIDE this
                # function's range — those are tail-calls / external
                # exits.  Walking into them pulls in branches from
                # OTHER functions' bodies, which then get counted as
                # "this function's external bras" and inflate the
                # bras_external flag count (and pollute the rendered
                # branches list with unreachable source addresses).
                in_range = (tgt is not None
                            and start <= tgt <= hard_limit_addr)
                # delay-slot branches: bra, bsr, bf/s, bt/s
                if head in {"bf/s", "bt/s", "bra", "bsr"}:
                    reachable.add(pc + 2)
                    if in_range and tgt not in reachable and not is_call:
                        worklist.append(tgt)
                    if head == "bra":
                        # unconditional jump — control does NOT fall through past delay slot
                        break
                    # bsr / bf/s / bt/s — fall through after delay slot
                    pc += 4
                    continue
                else:
                    # bf, bt: no delay slot; fall through to pc+2
                    if in_range and tgt not in reachable:
                        worklist.append(tgt)
                    pc += 2
                    continue

            # Indirect branch
            if _is_indirect_branch(mnem):
                indirect.append(pc)
                # Delay slot is reached
                reachable.add(pc + 2)
                if head in {"jmp", "braf"}:
                    # braf: try the SH-2 switch-dispatch idiom — seed case
                    # bodies as reachable so they don't render "unreach".
                    if head == "braf":
                        case_targets = _detect_braf_switch_targets(
                            binary, vram, pc, pool_priors,
                            func_start=start, hard_limit=hard_limit_addr,
                        )
                        for tgt in case_targets:
                            branches.append(BranchInfo(
                                src=pc, target=tgt, mnem="braf", internal=False
                            ))
                            if tgt not in reachable:
                                worklist.append(tgt)
                    # unconditional — terminates THIS linear walk; targets
                    # (if any) continue via worklist
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
    trailing zone after the function's last reachable instruction.  Reference
    convention (and the eval-tool convention we settled on) treats those
    pools as part of the function: they're only-reachable-from-here, they're
    PC-bound to this function, and lumping them in matches Ghidra-style
    boundaries.

    We extend by walking forward from `end + 1`, consuming any address that
    appears in `pool_priors` (a {addr: size} dict — typically a UNION of
    reference-extracted priors AND binary-wide PC-relative load targets so
    pool words that reference missed but the binary itself loads still get
    swallowed).  Stop at the first byte that's NOT in priors — typically
    the next function's prologue.

    Returns the new end address (inclusive), or the original `end` if no
    extension applies.
    """
    if not pool_priors:
        return end
    binary_end = vram + len(binary) - 1
    cap = min(hint_end if hint_end is not None else binary_end, binary_end)
    addr = end + 1

    def _is_padding_pair(off):
        """A 2-byte slot that's clearly compiler-emitted alignment fill:
        either zero (0x0000) or an SH-2 nop opcode (0x0009)."""
        if off + 1 >= len(binary):
            return False
        b0, b1 = binary[off], binary[off + 1]
        return (b0, b1) == (0x00, 0x00) or (b0, b1) == (0x00, 0x09)

    while addr <= cap:
        size = pool_priors.get(addr)
        if size is not None:
            new_end = addr + size - 1
            if new_end > cap:
                break
            end = new_end
            addr = new_end + 1
            continue

        # Not in priors. Two extension cases:
        #
        # (a) Pool-bridge: 2 or 4 bytes of zero alignment immediately before
        #     the next pool entry.  Pool tables are 4-byte aligned so this
        #     gap is common when the code zone ends at a 2-byte boundary.
        #
        # (b) Trailing alignment padding: 2 bytes of zero (0x00 0x00) or
        #     SH-2 nop (0x00 0x09) emitted before the next function starts
        #     at a 4-byte boundary.  GCC uses this whenever the function's
        #     last code byte lands on an odd 4-byte boundary.
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
        if bridged is not None:
            end = bridged - 1
            addr = bridged
            continue

        off = addr - vram
        if _is_padding_pair(off):
            end = addr + 1
            addr += 2
            continue

        break
    return end


def analyze_candidate(binary, vram, start, hint_end=None, pool_priors=None):
    """Static analysis for a function starting at `start`.

    hint_end caps the control flow walk (avoids running off into the next TU
    if a branch goes there). Pass tu.end or sub.end if known.

    pool_priors (optional): reference-derived {addr: size} map.  When provided,
    the returned `end` is extended forward through contiguous pool entries
    (the function's trailing literal-pool zone), matching reference convention.
    """
    binary_max = vram + len(binary) - 1
    hard_limit = hint_end if hint_end is not None else binary_max

    # Walk prologue
    prologue_end, saved, stack_alloc, flags = _walk_prologue(binary, vram, start)
    prologue_range = (start, prologue_end)

    # Walk forward to find reachable extent.  pool_priors lets the walker
    # trace switch-dispatch jump tables (`braf r0` over a `.short` table).
    reachable, max_reachable, branches, indirect = _control_flow_walk(
        binary, vram, start, hard_limit, pool_priors=pool_priors
    )

    # The last byte of the function is the last byte of the last reachable instruction.
    # For rts/rte/bra with delay slots, the delay slot's 2nd byte is the end.
    code_end = max_reachable + 1  # +1 because reachable contains instruction-start addrs

    # Walk epilogue backward from the LAST CODE BYTE (not the post-extension
    # boundary).  Epilogue detection has to see real instructions; pool data
    # would scramble it.
    epi_start, restored, stack_dealloc, final_rts, delay_slot = _walk_epilogue_backward(
        binary, vram, code_end, func_start=start, saved=saved,
    )
    epilogue_range = (epi_start, code_end) if epi_start is not None else (None, None)

    # Augment `restored` with PR / MACL pops anywhere in the function's
    # reachable set.  GCC will cycle-schedule the restore early (with
    # several unrelated instructions between it and the rts/jmp), placing
    # it OUTSIDE the contiguous-epilogue window the backward walker
    # tracks.  Without this scan the critical-pr/macl-not-restored flag
    # fires on otherwise-fine cycle-optimized functions (e.g. early
    # `lds.l @r15+, macl` followed by shll2 / shll / add then a tail-
    # call jmp).  pr and macl have unambiguous restore instructions
    # (only one register targeted), so existence anywhere in the
    # function's CFG is a trustworthy signal.
    if "pr" in saved and "pr" not in restored:
        for a in reachable:
            op = _read_opcode(binary, vram, a)
            if op is None:
                continue
            mnem, _ = decode_sh2(op, a)
            if mnem and _is_pr_pop(mnem):
                restored.append("pr")
                break
    if "macl" in saved and "macl" not in restored:
        for a in reachable:
            op = _read_opcode(binary, vram, a)
            if op is None:
                continue
            mnem, _ = decode_sh2(op, a)
            if mnem and _is_macl_pop(mnem):
                restored.append("macl")
                break

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
        final_rts, branches, conditional_rts,
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
        flags.append("no clean function exit at expected position (rts/jmp/braf)")
        return "LOW", flags
    score += 1

    if not saved:
        flags.append("no prologue register pushes detected")
    else:
        score += 1

    # Only flag mismatch when the prologue ACTUALLY allocated stack
    # (stack_alloc > 0).  If prologue_stack is 0, any dealloc the walker
    # captured is almost certainly a mid-body cleanup `add #+N, r15`
    # immediately following the pops backward (e.g. cleaning up a
    # `mov.l rX, @-r15` argument push that preceded a jsr).  Compilers
    # don't dealloc what they didn't alloc, so dealloc-without-alloc is
    # never a real bug — it's a walker false positive.
    #
    # Only flag UNDER-dealloc — the epilogue freeing less stack than
    # the prologue allocated, which would leak frames upward and
    # eventually corrupt the caller.  Over-dealloc (epi freeing MORE
    # than alloc) is a benign pattern: GCC sometimes merges the epi
    # dealloc with a mid-body push cleanup into a single `add #+N, r15`
    # (e.g. prologue allocs 4, body pushes r4 for jsr arg, then one
    # `add #+8, r15` cleans both up).  Catching over-dealloc as a "bug"
    # produced phantom mismatches on cycle-optimized GCC code.
    if stack_alloc > 0 and stack_dealloc < stack_alloc:
        flags.append(f"stack under-dealloc: alloc {stack_alloc} but only {stack_dealloc} freed")
    else:
        score += 1

    # Prologue/epilogue correspondence.  Two-tier:
    #
    #  (a) pr / macl MUST round-trip.  Pushing pr without popping it before
    #      rts crashes the function (the rts pops PC from the wrong slot).
    #      Same for macl.  Flag immediately if the prologue saved them but
    #      the epilogue walker didn't see the pop.
    #
    #  (b) GP registers (r0-r14) can be legitimately asymmetric: GCC will
    #      sometimes emit a save-around-jsr in the prologue area to
    #      preserve a scratch register across an internal call (e.g.
    #      FUN_0602AE74's `mov.l r4, @-r15` right after `sts.l pr` — r4 is
    #      popped MID-BODY at the function's first jsr return, not at the
    #      function's rts).  The epilogue walker (with the new strict-
    #      matching rule) will only consume pops that match the
    #      prologue's push list in reverse-walk order, so `restored` is
    #      always a SUFFIX of `reversed(saved)`.  Anything missing from
    #      the head of that suffix is a "mid-life save" and not a problem.
    saved_critical = {r for r in saved if r in ("pr", "macl")}
    restored_critical = {r for r in restored if r in ("pr", "macl")}
    missing_critical = saved_critical - restored_critical

    saved_gp = [r for r in saved if r not in ("pr", "macl")]
    restored_gp = [r for r in restored if r not in ("pr", "macl")]
    expected_gp = list(reversed(saved_gp))
    gp_suffix_ok = (not restored_gp) or (restored_gp == expected_gp[-len(restored_gp):])

    if missing_critical:
        flags.append(
            f"critical: prologue pushed {sorted(missing_critical)} but epilogue never restored — function would crash on return")
    elif not gp_suffix_ok:
        # Defensive — should not fire under the new walker, but catches
        # any future regression in walker matching logic.
        flags.append(f"prologue/epilogue register order mismatch: pushed {saved}, restored {restored}")
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
    # Callee-saved pushes — the strong signal that a real function starts here.
    "mov.l r8, @-r15", "mov.l r9, @-r15", "mov.l r10, @-r15",
    "mov.l r11, @-r15", "mov.l r12, @-r15", "mov.l r13, @-r15",
    "mov.l r14, @-r15",
    # PR / MACL push — typical pre-prologue save.
    "sts.l pr, @-r15", "sts.l macl, @-r15",
    # Scratch-register pushes — tiny helper functions (memclr/memcpy-style
    # loops, jsr trampolines) often save only r0-r7 because they don't call
    # out and only need a couple of temporaries.  Without these, forward
    # sweep skips real functions like the FUN_0602AA84 anon mini-fn called
    # twice from race code with 600+ runtime hits.
    "mov.l r0, @-r15", "mov.l r1, @-r15", "mov.l r2, @-r15",
    "mov.l r3, @-r15", "mov.l r4, @-r15", "mov.l r5, @-r15",
    "mov.l r6, @-r15", "mov.l r7, @-r15",
)


def _looks_like_fn_start(mnem):
    if not mnem:
        return False
    for prefix in _FN_START_PREFIXES:
        if mnem == prefix or mnem.startswith(prefix):
            return True
    return False


def _scan_for_next_prologue(binary, vram, start_addr, max_addr,
                            reference_starts=None, static_callers=None,
                            cross_module_callers=None):
    """Walk forward from start_addr looking for the next function entry.

    Four signals, any of which makes us propose `addr` as the next candidate:
      1. static_callers[addr] > 0  — somebody in this binary's reference
         bsr/jsrs to this address; definitively a function entry.
      2. addr in reference_starts    — reference labeled it FUN_<addr>; less
         decisive (reference has Ghidra hallucinations) but a real signal.
      3. cross_module_callers[addr] > 0  — same-name reference in a sibling
         hot-swap module bsr/jsrs to this address.  Can't physically resolve
         to this binary at runtime, but worth surfacing as a candidate so
         the human can quickly judge + reject rather than having us silently
         skip over 30 phantoms in a row.  The candidate-evaluator tags it
         with a yellow flag so it's loud in the banner.
      4. _looks_like_fn_start(...) — first instruction matches a register-
         push pattern.  Misses non-ABI helper functions that have no
         prologue (e.g. FUN_0602A818, which starts with `mov.l @r6, r6`
         and is called 4× via bsr).

    Returns the EARLIEST matching address, or None if nothing matches.
    """
    reference_starts = reference_starts or set()
    static_callers = static_callers or {}
    cross_module_callers = cross_module_callers or {}
    addr = (start_addr + 1) & ~1
    while addr <= max_addr:
        if static_callers.get(addr, 0) > 0:
            return addr
        if addr in reference_starts:
            return addr
        if cross_module_callers.get(addr, 0) > 0:
            return addr
        off = addr - vram
        if off + 1 >= len(binary):
            return None
        opcode = (binary[off] << 8) | binary[off + 1]
        mnem, _ = decode_sh2(opcode, addr)
        if _looks_like_fn_start(mnem):
            return addr
        addr += 2
    return None


def find_next_forward_sweep_candidate(yaml_cfg, binary, pool_priors=None,
                                       reference_starts=None, static_callers=None,
                                       cross_module_callers=None):
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
    def _covered_by_existing(addr):
        """True if addr falls inside any verified subseg's [start, end]
        range — not just at a start.  Catches the case where forward-sweep
        latches on a prologue inside a function that was ai_overridden to
        start a few bytes earlier (e.g. pre-prologue setup like
        `mov r4, r1; mov.l @(pc), r3; sts.l pr, @-r15` — the override
        moves the subseg start to the `mov`, but sweep would otherwise
        find the `sts.l pr` inside the new range and propose an
        overlapping subseg)."""
        for s in declared_code:
            if s["start"] <= addr <= s["end"]:
                return True
        return False

    binary_end = vram + len(binary) - 1

    # Head-of-binary case: if the binary's first address isn't covered by
    # any declared subseg, look for a function there first.  This handles
    # both the bootstrap case (no anchors yet) and re-review of the very
    # first function after an /unstamp at the binary head.
    if not declared_code or declared_code[0]["start"] > vram:
        next_start = _scan_for_next_prologue(
            binary, vram, vram, binary_end,
            reference_starts=reference_starts, static_callers=static_callers,
            cross_module_callers=cross_module_callers,
        )
        if next_start is not None and not _covered_by_existing(next_start):
            tu = next((t for t in tus if t["start"] <= next_start <= t["end"]), None)
            hint_end = tu["end"] if tu else None
            ev = analyze_candidate(binary, vram, next_start, hint_end, pool_priors=pool_priors)
            return (None, ev)

    for prev in declared_code:
        next_start = _scan_for_next_prologue(
            binary, vram, prev["end"] + 1, binary_end,
            reference_starts=reference_starts, static_callers=static_callers,
            cross_module_callers=cross_module_callers,
        )
        if next_start is None:
            continue
        if _covered_by_existing(next_start):
            # Already inside an existing verified subseg — keep iterating.
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
