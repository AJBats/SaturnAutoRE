#!/usr/bin/env python3
"""analyzer.py — single source of truth for code intelligence.

Successor to oracle.py + the analytical half of eval_server.py.  Holds every
decision about "what these bytes mean": pool vs code, function boundaries,
CFG reachability, branch internality, callgraph, reference agreement,
midpoints, indent depths, indirect resolutions, sweep state.

eval_server2.py is its only consumer.  Eval server NEVER asks "what is at
address X" — it asks the analyzer for already-decorated ListingRow objects
and templates them into HTML.

This file is the SKELETON.  Data classes are defined here; implementations
are filled in phase by phase per the refactor plan.  See:
  - Phase 1: BinaryModel.byte_kind / pool_words / instructions
  - Phase 2: BinaryModel.callers / reference_starts / runtime_hits
  - Phase 3: BinaryModel.analyze_function
  - Phase 4: FunctionAnalysis.indent_depths / reference / midpoints / etc.
  - Phase 5: SweepState
  - Phase 6: SweepState.listing
  - Phase 7: SweepState.aligned_listings
"""

from __future__ import annotations

import sys as _sys
from dataclasses import dataclass, field, replace as _dc_replace
from enum import Enum
from pathlib import Path
from typing import Optional

# Phase 3b: analyzer is self-contained.  Only external dependency is the
# SH-2 decoder, which lives in lib/.  Oracle.py is no longer imported.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR / "lib") not in _sys.path:
    _sys.path.insert(0, str(_SCRIPT_DIR / "lib"))

from sh2_decode import decode_sh2 as _decode_sh2


# ---------------------------------------------------------------------------
# Byte-level classification — the foundation everything else builds on.
# ---------------------------------------------------------------------------

class ByteKind(Enum):
    """What does a single 2-byte-aligned address represent?

    Computed once per BinaryModel construction by unifying:
      - reference-derived pool_priors
      - whole-binary PC-relative load target scan (two-pass to avoid the
        data-as-code trap where bytes inside a pool word bit-align as a
        valid mov.l opcode)
      - padding-pair detection (0x0000 / 0x0009)
      - jump-table walking from braf+mova+mov.w switch idioms
      - reachable-set walks from every known function entry

    Every downstream consumer (function-end extension, listing renderer,
    indent computation, indirect resolution) reads from this map.  No
    consumer re-derives.
    """
    INSTRUCTION = "instruction"
    POOL4 = "pool4"                  # 4-byte literal (.4byte)
    POOL2 = "pool2"                  # 2-byte literal (.2byte)
    JUMP_TABLE_ENTRY = "jump_table"  # 2-byte signed offset into a braf table
    PADDING = "padding"              # alignment fill (zero / nop)
    UNKNOWN = "unknown"              # not yet classified


class InstructionCategory(Enum):
    """Coarse-grained category for an instruction, driving UI categorization
    (cat-return / cat-call / cat-uncond / cat-cond / cat-pool / cat-compare).

    Set by the analyzer once per decoded instruction; eval_server maps to
    CSS classes verbatim — no re-classification clientside or serverside.
    """
    RETURN = "return"                  # rts / rte
    CALL = "call"                       # jsr / bsr / bsrf
    UNCOND_BRANCH = "uncond_branch"    # bra / jmp / braf
    COND_BRANCH = "cond_branch"        # bf / bt / bf/s / bt/s
    INDIRECT_BRANCH = "indirect_branch"  # jmp @rN / braf rN  (set additionally to UNCOND_BRANCH for indirect cases)
    POOL_LOAD = "pool_load"            # mov.l/mov.w @(disp,PC) / mova
    COMPARE = "compare"                # tst / cmp.*
    OTHER = "other"


@dataclass
class Instruction:
    """Per-instruction decoded record.  Populated for every addr where
    byte_kind == INSTRUCTION.

    RESERVED — no consumer today.  Phase 6 (listing model) is the
    likely first consumer: each ListingRow with kind=INSTRUCTION would
    pull its decoded text + category from here instead of re-decoding."""
    addr: int
    opcode: int                         # 16-bit raw opcode
    mnem: str                           # disassembled text from decode_sh2
    decoded_target: Optional[int]       # PC-relative target if the opcode encodes one (branches, PC-rel loads)
    category: InstructionCategory
    length_bytes: int = 2                # always 2 for SH-2 but field reserved


@dataclass
class PoolWord:
    """Per-pool-address record.  Populated for every addr where
    byte_kind in {POOL4, POOL2}."""
    addr: int
    size: int                           # 2 or 4
    value: int                          # the literal value at this addr
    loaded_from: list = field(default_factory=list)  # list of instruction addrs that load this pool word


# ---------------------------------------------------------------------------
# Callgraph
# ---------------------------------------------------------------------------

class CallKind(Enum):
    """How a call site references its target.

    RESERVED — phase 2 stores caller COUNTS in flat {addr: int} dicts
    (BinaryModel.static_callers / .cross_module_callers) for byte-exact
    parity with eval_server.  Promoting to structured CallSite records
    is forward-facing; no consumer yet."""
    DIRECT_BSR = "direct_bsr"          # `bsr disp` — PC-relative call
    DIRECT_BRA = "direct_bra"          # `bra disp` — PC-relative jump (tail call)
    DIRECT_JSR = "direct_jsr"          # `jsr @rN` where rN loaded from PC-rel pool (resolved)
    DIRECT_JMP = "direct_jmp"          # `jmp @rN` similarly resolved
    FUNCTION_POINTER = "function_pointer"  # 4-byte word in a pool whose value lands in vram range, 2-byte aligned
    CROSS_MODULE = "cross_module"      # text-scanned from sibling hot-swap module .s files


@dataclass
class CallSite:
    """Structured caller record.  RESERVED — see CallKind."""
    src: Optional[int]                  # caller address (None for cross-module/pool-only refs without resolved src)
    kind: CallKind
    module: Optional[str] = None        # module name for cross-module callers


# ---------------------------------------------------------------------------
# Branch / control-flow records
# ---------------------------------------------------------------------------

@dataclass
class Branch:
    """A branch instruction inside a function.  Same role as oracle.py's
    BranchInfo, kept here so analyzer is self-contained."""
    src: int
    target: Optional[int]               # None for register-indirect branches
    mnem: str                           # 'bra', 'bsr', 'bf', 'bf/s', 'jmp', 'jsr', etc.
    internal: bool                      # target inside [func.start, func.end]
    direction: Optional[str] = None     # 'forward' / 'backward' / None (for indirect)


# ---------------------------------------------------------------------------
# Per-function analysis
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    """Verdict tier emitted by the analyzer's scoring.  Inherits from
    `str` so it serializes to JSON as its value string and concatenates
    into CSS class names (`f"verdict-{v}"` → `"verdict-HIGH"`) without
    needing explicit `.value` access at the wire boundary."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class ReferenceAgreement:
    """Comparison of analyzer's proposed boundary against reference's view."""
    verdict: str                        # "agrees" | "disagrees" | "silent"
    start_match: bool
    reference_next: Optional[int]       # reference's next FUN start > our start
    reference_implied_end: Optional[int]  # reference_next - 1
    end_delta: Optional[int]            # our_end - reference_implied_end (positive = we're longer)
    tooltip: str


@dataclass
class Midpoint:
    """A reference FUN_<X> start that falls strictly inside our proposed
    function's range — i.e., reference thinks there's a function start
    within our body."""
    addr: int
    static_callers: int
    cross_module_callers: int
    runtime_hits: int


@dataclass
class FunctionEvidence:
    """Caller / runtime evidence for a function's start."""
    static_callers: int = 0
    cross_module_callers: int = 0
    runtime_hits: int = 0


@dataclass
class FunctionAnalysis:
    """Full analytical record for one function.  Replaces oracle.py's
    FunctionEvidence and absorbs the per-function fields eval_server
    currently computes separately (indent_depths, reference, midpoints,
    indirect resolutions, phantom_hint)."""

    # ----- Boundaries
    start: int
    end: int                            # last byte inclusive, including trailing pool

    # ----- Prologue / epilogue
    prologue_range: tuple                # (start, end_inclusive)
    prologue_saved: list                 # ['r14', 'r13', ..., 'pr', 'macl']
    prologue_stack: int                  # bytes reserved (negative add #-N, r15)
    epilogue_range: tuple                # (start, end_inclusive) or (None, None)
    final_exit: Optional[int]            # addr of rts/jmp/braf/bra whose delay slot is at end-1
    delay_slot: Optional[int]            # addr of the delay-slot instruction

    # ----- Control flow
    branches: list = field(default_factory=list)         # Branch[]
    conditional_returns: list = field(default_factory=list)  # addrs of non-final rts
    pool_targets: list = field(default_factory=list)     # all PC-rel load targets in reachable set
    reachable: set = field(default_factory=set)          # set of addrs reachable from start
    indirect_calls: list = field(default_factory=list)   # addrs of jsr/jmp/braf/bsrf (register-indirect)

    # ----- Indent depths from CFG region analysis (moved from eval_server)
    indent_depths: dict = field(default_factory=dict)    # {addr: depth}

    # ----- Indirect-target resolutions inside this function (moved from eval_server)
    indirect_resolutions: dict = field(default_factory=dict)  # {addr: resolved_target}

    # ----- Verdict
    verdict: Verdict = Verdict.UNKNOWN
    yellow_flags: list = field(default_factory=list)

    # ----- Reference / midpoint / evidence
    reference: Optional[ReferenceAgreement] = None
    midpoints: list = field(default_factory=list)        # Midpoint[]
    evidence: FunctionEvidence = field(default_factory=FunctionEvidence)
    phantom_hint: bool = False                            # cross-module-only + no prologue + no same-module caller


# ---------------------------------------------------------------------------
# Listing rows — the rich rendering primitives eval_server templates from.
# ---------------------------------------------------------------------------

class RowKind(Enum):
    """What kind of row is this — drives eval_server's HTML template
    selection.  Renderer never re-classifies."""
    SECTION_HEADER = "section_header"   # 'prev' / 'intermediate' / 'current' / 'trailing' banner
    LABEL = "label"                      # `.L_<addr>:` branch target marker
    INSTRUCTION = "instruction"          # decoded SH-2 op
    POOL4 = "pool4"                      # `.4byte 0x...` literal
    POOL2 = "pool2"                      # `.2byte 0x...` literal
    PADDING = "padding"                  # alignment fill
    RAW = "raw"                          # fallback decode in intermediate/trailing zones (rare after byte_kind fully populated)
    BLANK = "blank"                      # diff-alignment placeholder for split view


class Section(Enum):
    PREV = "prev"
    INTERMEDIATE = "intermediate"
    CURRENT = "current"
    TRAILING = "trailing"


class PinAction(Enum):
    """What does the row's `+` button do?  Set by analyzer per row;
    eval_server reads it verbatim to wire the click handler."""
    PIN_START = "pin_start"             # above current candidate start
    PIN_END = "pin_end"                  # on or below current candidate start
    NONE = "none"


class UnpinAction(Enum):
    """What does the row's `[ unpin ]` button do?  Only set on section
    headers; reflects which header it sits on."""
    UNPIN_ALL = "unpin_all"             # PROPOSED header — nuke the entire override
    UNPIN_END = "unpin_end"             # TRAILING header — drop only the end pin
    NONE = "none"


@dataclass
class ListingRow:
    """One row of the listing — fully decorated, no decisions left for
    eval_server beyond field-to-CSS-class mapping.

    Most fields are optional; their relevance depends on `kind` and
    `section`.  Eval_server's renderer must be a single template that
    reads these fields and emits a span — no branching on kind beyond
    template selection."""

    # ----- Identity
    row_id: int                          # stable index within the listing
    kind: RowKind
    section: Optional[Section]

    # ----- Position / anchoring (for diff alignment + scroll)
    addr: Optional[int] = None
    anchor_addr: Optional[int] = None    # used by split-view diff alignment (for section headers)

    # ----- Content (varies by kind)
    bytes_hex: str = ""                  # "A2 A4" — formatted for display
    text: str = ""                        # mnem ("mov.l r4, @-r15") or pool literal (".4byte 0x12345678")
    label: str = ""                       # for LABEL rows ('.L_06028A40:'), pool labels ('.L_pool_06037296'), or section header text
    margin: str = ""                      # '↓' / '↑' / '→' direction arrow
    tag: str = ""                         # right-column annotation ('⇒ EXIT', '⇒ TAIL?', '↩ ret', etc.)

    # ----- Function-relative roles (only meaningful inside Section.CURRENT)
    is_prologue: bool = False
    is_epilogue: bool = False
    is_final_rts: bool = False
    is_conditional_rts: bool = False
    is_unreachable: bool = False

    # ----- Categorization (drives CSS .cat-* classes)
    category: Optional[InstructionCategory] = None
    is_tail_call: bool = False           # external uncond branch — loudest red
    is_indirect_branch: bool = False     # jmp @rN / braf rN — adds .uncond-indirect on top of cat-uncond

    # ----- Indent depth (capped for display in renderer)
    indent: int = 0

    # ----- Branch metadata (for arc drawing — only set on instructions/pools with internal targets)
    branch_target: Optional[int] = None
    branch_direction: Optional[str] = None  # 'forward' / 'backward'
    branch_type: Optional[str] = None        # 'cond' / 'uncond'

    # ----- Indirect-target resolution annotation ("⇒ FUN_X" inline tail)
    indirect_resolved_label: str = ""    # "FUN_0602AB10" or "0x06037000" — empty if not applicable

    # ----- Decoration flags (precedence already resolved: attn > midpoint > ref_end)
    is_attn: bool = False
    is_midpoint: bool = False
    is_ref_end: bool = False

    # ----- Action wiring — eval_server reads these to attach click handlers
    pin_action: PinAction = PinAction.NONE
    unpin_action: UnpinAction = UnpinAction.NONE


# ---------------------------------------------------------------------------
# Sweep state — yaml + session-driven derived state
# ---------------------------------------------------------------------------

@dataclass
class Gap:
    """One uncovered byte range between verified subsegs, or between the
    last verified subseg and the proposed candidate."""
    start: int
    end: int
    size: int
    preceding_start: int
    preceding_name: str                  # 'FUN_06028000'
    pending: bool                        # True if gap is "would be created on approval"


@dataclass
class Progress:
    verified_bytes: int
    total_bytes: int
    pct: float


@dataclass
class VerifiedSubseg:
    """Mirrors the yaml subseg shape but as a typed record."""
    start: int
    end: int
    type: str = "code"
    file: str = ""


@dataclass
class NextCandidate:
    """What SweepState.next_candidate returns: the next function the human
    should verdict, plus its immediately-preceding verified subseg (for
    rendering the 'prev' section above it)."""
    previous: Optional[VerifiedSubseg]
    function: FunctionAnalysis


# ---------------------------------------------------------------------------
# Static-analysis helpers (moved verbatim from oracle.py in phase 3b).
#
# Pure functions: take binary/vram/etc. as arguments, return analysis
# results.  No `self`; no module state.  Used by BinaryModel.analyze_function
# and (later) by SweepState.next_candidate.
# ---------------------------------------------------------------------------

_BRANCH_MNEMONICS = {"bra", "bsr", "bf", "bt", "bf/s", "bt/s"}
_DELAYED_BRANCH   = {"bra", "bsr", "bf/s", "bt/s", "jmp", "jsr", "braf", "bsrf", "rts", "rte"}
_UNCONDITIONAL_EXIT = {"bra", "jmp", "rts", "rte"}
_EPI_HARD_STOPS = ("rts", "rte", "bra", "bsr", "bf", "bt", "bf/s", "bt/s",
                    "jmp", "jsr", "braf", "bsrf")

# Listing category sets (mirror eval_server's grouping for parity).
_RETURN_HEADS  = {"rts", "rte"}
_CALL_HEADS    = {"jsr", "bsr", "bsrf"}
_UNCOND_HEADS  = {"bra", "jmp", "braf"}
_COND_HEADS    = {"bf", "bt", "bf/s", "bt/s"}
_COMPARE_HEADS = {"tst", "cmp/eq", "cmp/ge", "cmp/gt", "cmp/hi", "cmp/hs",
                  "cmp/pl", "cmp/pz", "cmp/str"}

# Listing layout constants (moved from eval_server in phase 6).  Indent
# cap keeps deep switch-dispatch chains scannable; trailing window is the
# bytes-after-candidate zone the UI shows for context.
MAX_DISPLAY_INDENT = 4
TRAILING_BYTES = 200

# Function-start signals — patterns that strongly suggest "a function begins
# at this address."  Used by forward sweep to scan past pool/data zones.
# RESERVED FOR PHASE 5 — wired by SweepState.next_candidate when forward
# sweep moves from oracle.find_next_forward_sweep_candidate into analyzer.
_FN_START_PREFIXES = (
    # Callee-saved pushes — strong signal that a real function starts here.
    "mov.l r8, @-r15", "mov.l r9, @-r15", "mov.l r10, @-r15",
    "mov.l r11, @-r15", "mov.l r12, @-r15", "mov.l r13, @-r15",
    "mov.l r14, @-r15",
    # PR / MACL push — typical pre-prologue save.
    "sts.l pr, @-r15", "sts.l macl, @-r15",
    # Scratch-register pushes — tiny helper functions (memclr/memcpy-style
    # loops, jsr trampolines) save only r0-r7 because they don't call out.
    "mov.l r0, @-r15", "mov.l r1, @-r15", "mov.l r2, @-r15",
    "mov.l r3, @-r15", "mov.l r4, @-r15", "mov.l r5, @-r15",
    "mov.l r6, @-r15", "mov.l r7, @-r15",
)


# ----- Mnemonic predicates --------------------------------------------------

def _push_register(mnem):
    """If mnem is `mov.l rN, @-r15`, return rN; else None."""
    if not mnem.startswith("mov.l r"):
        return None
    parts = mnem.split()
    if len(parts) != 3 or parts[2] != "@-r15":
        return None
    return parts[1].rstrip(",")


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


def _is_pr_push(mnem):   return mnem == "sts.l pr, @-r15"
def _is_pr_pop(mnem):    return mnem == "lds.l @r15+, pr"
def _is_macl_push(mnem): return mnem == "sts.l macl, @-r15"
def _is_macl_pop(mnem):  return mnem == "lds.l @r15+, macl"


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
    if not parts or parts[0] not in _BRANCH_MNEMONICS:
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
    return parts[0] in {"jmp", "jsr", "braf", "bsrf"}


def _read_opcode(binary, vram, addr):
    off = addr - vram
    if off + 1 >= len(binary):
        return None
    return (binary[off] << 8) | binary[off + 1]


def _looks_like_fn_start(mnem):
    if not mnem:
        return False
    for prefix in _FN_START_PREFIXES:
        if mnem == prefix or mnem.startswith(prefix):
            return True
    return False


# ----- Prologue / epilogue walkers ------------------------------------------

def _walk_prologue(binary, vram, start):
    """Walk forward from `start` recognizing prologue instructions.

    GCC schedulers can interleave non-prologue ops (tst, mov #imm, etc.)
    between register pushes.  We allow up to MAX_INTERLEAVE consecutive
    non-prologue instructions before stopping.  Anything obviously past
    prologue (branches, calls, returns) stops immediately.

    Returns:
      prologue_end_addr  — addr of LAST prologue instruction (inclusive)
      saved              — list of register names saved (in push order)
      stack              — bytes reserved by `add #-N, r15`, or 0
      flags              — list of yellow flag strings
    """
    MAX_INTERLEAVE = 6   # consecutive non-prologue allowed (GCC scheduler can
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
        mnem, _ = _decode_sh2(op, addr)
        if mnem is None:
            break

        head = mnem.split()[0] if mnem else ""
        if head in HARD_STOPS:
            break

        reg = _push_register(mnem)
        if reg and reg in {f"r{i}" for i in range(0, 15)}:
            # Track scratch (r0-r7) AND callee-saved (r8-r14) pushes the
            # same way.  Tiny helpers (memclr/memcpy loops) only save
            # scratch regs and were otherwise getting a false "no prologue
            # register pushes detected" yellow flag.
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
    mnem_rts, _ = _decode_sh2(op_rts, rts_addr) if op_rts is not None else (None, None)
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
    # GCC schedules ONE useful instruction into the rts delay slot for
    # cycle efficiency.  Two patterns matter:
    #   (a) A pop matching expected[0] (the last epilogue restore).
    #       e.g. `lds.l @r15+, macl` for macl restore in tiny helpers.
    #   (b) A stack dealloc `add #+N, r15` that balances the prologue
    #       alloc.  Saturn compilers very commonly do this for
    #       functions with no register saves but a small frame
    #       allocation — the alloc gets dealloc'd in the delay slot
    #       for free.  Without recognizing this, the alloc/dealloc
    #       checker would see "alloc N but 0 freed" → phantom flag.
    op_ds = _read_opcode(binary, vram, delay_slot)
    mnem_ds, _ = _decode_sh2(op_ds, delay_slot) if op_ds is not None else (None, None)
    ds_pop_reg = None
    if mnem_ds:
        ds_pop_reg = (_pop_register(mnem_ds)
                      or ("pr" if _is_pr_pop(mnem_ds) else None)
                      or ("macl" if _is_macl_pop(mnem_ds) else None))
    ds_dealloc = _is_stack_dealloc(mnem_ds) if mnem_ds else None
    delay_slot_consumed = False
    matched_stack = 0
    matched_stack_addr = None
    if ds_pop_reg and expected and ds_pop_reg == expected[0]:
        delay_slot_consumed = True
        expected_idx = 1
    elif ds_dealloc is not None:
        # Delay-slot stack dealloc — capture as the function's dealloc.
        # Don't set delay_slot_consumed (that flag means "we captured a
        # POP from the delay slot to append to `restored`") and don't
        # advance expected_idx (the dealloc isn't a register restore).
        matched_stack = ds_dealloc
        matched_stack_addr = delay_slot
        expected_idx = 0
    else:
        # Either not a pop/dealloc, or doesn't match expected[0] — leave
        # it out so the match check downstream doesn't get a phantom
        # mismatch.
        expected_idx = 0

    MAX_INTERLEAVE = 6
    matches = []
    epilogue_start = rts_addr
    addr = rts_addr - 2
    lower_bound = func_start if func_start is not None else 0
    consecutive_non_epi = 0

    while addr >= lower_bound:
        op = _read_opcode(binary, vram, addr)
        if op is None:
            break
        mnem, _ = _decode_sh2(op, addr)
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


# ----- braf-switch jump-table detection -------------------------------------

def _detect_mov_l_jmp_switch_targets(binary, vram, jmp_pc, binary_end=None,
                                      func_start=None, hard_limit=None):
    """Recognize the GCC SH-2 indirect switch-dispatch idiom around `jmp_pc`.

    Idiom (within ~8 instructions before the jmp):
        mov.l @(disp,PC), rN     ; rN = address of the jump table
        ...                       ; (shll2 / add r_idx, rN / etc.)
        mov.l @rN, rN             ; rN = table[idx]
        jmp @rN                   ; transfer

    The pool word's value is the table start.  The table is a run of
    4-byte case body addresses; we walk forward stopping at the first
    entry whose value isn't in vram range or isn't 2-byte aligned.

    Returns list[int] of in-range case body addresses (filtered to
    [func_start, hard_limit] if those are supplied).
    """
    if binary_end is None:
        binary_end = vram + len(binary) - 1

    jmp_op = _read_opcode(binary, vram, jmp_pc)
    # jmp @rN: encoding 0100 NNNN 0010 1011  (0x402B with N in bits 11-8)
    if jmp_op is None or (jmp_op & 0xF0FF) != 0x402B:
        return []
    reg = (jmp_op >> 8) & 0xF

    # Scan back up to 8 instructions (16 bytes) for the pattern.
    # We need both `mov.l @rN, rN` (indirection through rN) AND
    # `mov.l @(disp,PC), rN` (the pool load that supplied the table start).
    mov_l_via_rn_seen = False
    pool_addr = None
    for back in range(2, 18, 2):
        addr = jmp_pc - back
        if addr < vram:
            break
        op = _read_opcode(binary, vram, addr)
        if op is None:
            continue

        # mov.l @rM, rN: 0110 NNNN MMMM 0010 — looking for src==dst==reg
        if (op & 0xF00F) == 0x6002:
            src = (op >> 4) & 0xF
            dst = (op >> 8) & 0xF
            if src == reg and dst == reg:
                mov_l_via_rn_seen = True
                continue

        # mov.l @(disp,PC), rN: 1101 NNNN dddd dddd
        if (op & 0xF000) == 0xD000 and ((op >> 8) & 0xF) == reg:
            disp = op & 0xFF
            pool_addr = ((addr + 4) & 0xFFFFFFFC) + disp * 4
            break

    if not mov_l_via_rn_seen or pool_addr is None:
        return []
    if not (vram <= pool_addr <= binary_end):
        return []

    # Read the pool word — that's the table START address.
    poff = pool_addr - vram
    if poff + 3 >= len(binary):
        return []
    table_start = (
        (binary[poff] << 24) | (binary[poff + 1] << 16)
        | (binary[poff + 2] << 8) | binary[poff + 3]
    )
    if not (vram <= table_start <= binary_end):
        return []
    if table_start & 1:
        return []  # not 2-byte aligned, can't be a code addr

    lo = func_start if func_start is not None else vram
    hi = hard_limit if hard_limit is not None else binary_end

    # Walk the table forward.  Each entry is a 4-byte case body addr.
    # Stop at the first entry whose value is out of vram range or odd.
    # Collect every in-range target; filter by [lo, hi] on return.
    targets = []
    t = table_start
    while t + 3 <= binary_end:
        toff = t - vram
        if toff + 3 >= len(binary):
            break
        value = (
            (binary[toff] << 24) | (binary[toff + 1] << 16)
            | (binary[toff + 2] << 8) | binary[toff + 3]
        )
        if not (vram <= value <= binary_end):
            break
        if value & 1:
            break
        if lo <= value <= hi:
            targets.append(value)
        t += 4

    return targets


def _detect_braf_switch_targets(binary, vram, braf_pc, pool_priors,
                                 func_start=None, hard_limit=None):
    """Recognize the GCC SH-2 switch-dispatch idiom around `braf_pc`.

    Idiom (within ~12 bytes before braf):
        mova @(disp,PC), r0
        mov.w @(r0,rN), r0
        braf r0
        <delay slot>

    Returns list[int] of target addresses (possibly empty).
    """
    if not pool_priors:
        return []

    braf_op = _read_opcode(binary, vram, braf_pc)
    if braf_op is None or (braf_op & 0xF0FF) != 0x0023:
        return []
    braf_reg = (braf_op >> 8) & 0xF
    if braf_reg != 0:
        return []

    movw_seen = False
    table_base = None
    for back in range(2, 14, 2):
        addr = braf_pc - back
        if addr < vram:
            break
        op = _read_opcode(binary, vram, addr)
        if op is None:
            continue
        # mov.w @(r0, rM), r0  encoding 0000 0000 mmmm 1101
        if (op & 0xF00F) == 0x000D and ((op >> 8) & 0xF) == 0:
            movw_seen = True
            continue
        # mova @(disp, PC), r0  encoding 11000111 dddddddd
        if (op & 0xFF00) == 0xC700:
            disp = (op & 0xFF) * 4
            table_base = ((addr + 4) & ~3) + disp
            break

    if not movw_seen or table_base is None:
        return []

    lo = func_start if func_start is not None else vram
    hi = hard_limit if hard_limit is not None else (vram + len(binary) - 1)
    targets = []
    t = table_base
    while pool_priors.get(t) == 2:
        off = t - vram
        if off + 1 >= len(binary):
            break
        raw = (binary[off] << 8) | binary[off + 1]
        sval = raw - 0x10000 if raw & 0x8000 else raw
        target = braf_pc + 4 + sval
        if lo <= target <= hi:
            targets.append(target)
        t += 2

    return targets


# ----- Control-flow walk + branch classification + pool extension ----------

def _control_flow_walk(binary, vram, start, hard_limit_addr, pool_priors=None):
    """Walk reachable addresses from `start` via control flow.  Returns
    (reachable, max_reachable, branches, indirect_calls).

    Branches collected as analyzer.Branch records (internal=False initially;
    set later by _classify_branch_internality)."""
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
            mnem, _ = _decode_sh2(op, pc)
            if mnem is None:
                pc += 2
                continue

            head = mnem.split()[0] if mnem else ""

            # Direct branch with static target
            if head in _BRANCH_MNEMONICS:
                tgt = _branch_target(mnem)
                b = Branch(src=pc, target=tgt, mnem=head, internal=False)
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
                in_range = (tgt is not None and start <= tgt <= hard_limit_addr)
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
                    # Try the SH-2 switch-dispatch idioms — seed case bodies
                    # into the worklist so the dispatcher absorbs them into
                    # its reachable set.
                    if head == "braf":
                        case_targets = _detect_braf_switch_targets(
                            binary, vram, pc, pool_priors,
                            func_start=start, hard_limit=hard_limit_addr,
                        )
                    else:  # jmp
                        case_targets = _detect_mov_l_jmp_switch_targets(
                            binary, vram, pc,
                            func_start=start, hard_limit=hard_limit_addr,
                        )
                    if case_targets:
                        for tgt in case_targets:
                            branches.append(Branch(
                                src=pc, target=tgt, mnem=head, internal=False,
                            ))
                            if tgt not in reachable:
                                worklist.append(tgt)
                    else:
                        # No switch dispatch — try resolving as a simple
                        # `mov.l @(disp,PC), rN ; jmp @rN` (single-target
                        # indirect, common for tail calls / internal jumps
                        # via pool).  When the load is in our in-progress
                        # reachable set, we can statically resolve the
                        # target and record it as a Branch so the listing
                        # draws an arrow.
                        resolved = _resolve_indirect_target(
                            binary, vram, reachable, start, pc, mnem,
                        )
                        if resolved is not None:
                            branches.append(Branch(
                                src=pc, target=resolved, mnem=head, internal=False,
                            ))
                            if (start <= resolved <= hard_limit_addr
                                    and resolved not in reachable):
                                worklist.append(resolved)
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
    """Set Branch.internal in-place based on whether target falls in
    [start, end].  Also fills in `direction` field for analyzer.Branch."""
    for b in branches:
        if b.target is not None and start <= b.target <= end:
            b.internal = True
        else:
            b.internal = False
        if b.target is None:
            b.direction = None
        elif b.target > b.src:
            b.direction = "forward"
        else:
            b.direction = "backward"
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


# ----- Verdict scoring -----------------------------------------------------

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


# ----- Indent depths from CFG region analysis -------------------------------

def _compute_indent_depths(binary, vram, fn_start, fn_end, branches):
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
    decomposition leaves those addresses at depth 0 — better to be flat
    than misleading.

    `fn_end` is the address of the last byte of the function's last
    reachable instruction (= max(reachable) + 1).  Pool data past that
    must NOT be walked: pool bytes can spell branch opcodes and create
    bogus basic blocks that pollute the region containment graph.

    Returns dict {addr: int_depth} — sparse, only entries with depth > 0.
    """
    if not branches:
        return {}
    if binary is None or vram is None:
        return {}

    # ----- 1. Identify block-start addresses
    block_starts = {fn_start}
    branches_by_src = {}
    for b in branches:
        if not b.internal or b.target is None:
            continue
        branches_by_src[b.src] = b
        block_starts.add(b.target)
        # Instruction after a branch (or its delay slot) begins a new block.
        # All SH-2 unconditional and *-with-delay-slot branches carry a 2-byte
        # delay slot.  Indirect branches (jmp, braf, jsr, bsrf) included so
        # switch-detector-added Branch records don't mis-split the delay slot
        # into a phantom basic block.
        delay = 2 if b.mnem in {"bra", "bsr", "bf/s", "bt/s", "jmp", "braf", "jsr", "bsrf"} else 0
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
        mnem, _ = _decode_sh2(op, addr)
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
        # Find this block's terminating control-flow instruction.
        term_addr = None
        term_mnem = None
        a = blk["start"]
        while a <= blk["end"]:
            off = a - vram
            if off + 1 < len(binary):
                op = (binary[off] << 8) | binary[off + 1]
                mn, _ = _decode_sh2(op, a)
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
    regions = []

    # Find back-edges (loops) — a successor that points to an earlier block.
    for blk in blocks:
        for s in blk["succs"]:
            if s <= blk["id"]:
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
        #   (a) Branched-to has its own body before reaching the merge.
        #       This is bt-with-body or bf-with-bra-to-merge. The branched-to
        #       arm is the "interesting" code — indent it.  Fall-through
        #       (often just bra-to-merge plumbing) stays at outer depth.
        #   (b) Branched-to IS the merge (target_succ == merge). This is the
        #       bf-no-else / skip-the-body pattern: the conditional jumps OVER
        #       the if-body. The fall-through path IS the if-body — indent it.
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


# ----- Forward-sweep helpers (phase 5) --------------------------------------

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
        mnem, _ = _decode_sh2(opcode, addr)
        if _looks_like_fn_start(mnem):
            return addr
        addr += 2
    return None


def _coerce_addr(v):
    """Accept either '0x06029E8F' / '06029E8F' (hex string) or 100833423 (int).

    Used by SweepState when parsing ai_override values (which may come
    from either JSON int literals or hex strings written by the AI).
    """
    if isinstance(v, str):
        return int(v, 16)
    return int(v)


# ----- Listing helpers (phase 6) --------------------------------------------

def _classify_mnem_to_category(mnem) -> Optional[InstructionCategory]:
    """Map a decoded mnem string to its InstructionCategory.

    Mirrors eval_server._classify_mnem.  Returns None for instructions
    that don't get a category class (which is the catchall — most ALU
    ops, loads, stores, etc.).
    """
    if not mnem:
        return None
    head = mnem.split()[0]
    if head in _RETURN_HEADS:  return InstructionCategory.RETURN
    if head in _CALL_HEADS:    return InstructionCategory.CALL
    if head in _UNCOND_HEADS:  return InstructionCategory.UNCOND_BRANCH
    if head in _COND_HEADS:    return InstructionCategory.COND_BRANCH
    if "@(0x" in mnem and head in ("mov.l", "mov.w", "mova"):
        return InstructionCategory.POOL_LOAD
    if head in _COMPARE_HEADS:
        return InstructionCategory.COMPARE
    if mnem.startswith(".byte") or mnem.startswith(".4byte") or mnem.startswith(".2byte"):
        return InstructionCategory.OTHER  # eval_server uses 'cat-data' here; mapped via the OTHER bucket
    return None


def _symbolize_mnem(mnem, pool4, pool2, mova, branch_targets) -> str:
    """Replace inline addresses in `mnem` with symbolic labels.

    Two transformations:
      - `mov.l @(0xADDR, PC), Rn` → `mov.l .L_pool_ADDR, Rn`
        (and same for mov.w / mova) when ADDR is in the pool sets.
      - `bra 0xADDR` / `bf 0xADDR` / etc. → `bra .L_ADDR` when ADDR is
        an internal branch target.

    Mirrors eval_server._symbolize.  Returns the rewritten string.
    """
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

    if head in _BRANCH_MNEMONICS:
        try:
            target = int(tail.rstrip(","), 16)
            if target in branch_targets:
                return f"{head} .L_{target:08X}"
        except ValueError:
            pass
    return mnem


# ----- Indirect-target resolution -------------------------------------------

def _resolve_indirect_target(binary, vram, reachable, fn_start, addr, mnem):
    """For jmp/jsr/bsrf/braf @rN, find the most recent `mov.l @(disp,PC),
    rN` that loaded that register, and read the 4-byte pool word it
    targets — that's the actual runtime branch target.

    GCC almost always emits the load 1–4 instructions before the
    indirect branch (load pool, jump-to-Rn pattern).  We walk backward
    in the function's reachable set, stopping at the first instruction
    that either:
      - loads the target register from a PC-relative pool (success), OR
      - writes the target register some other way (gives up — we
        can't determine the value statically).

    Returns the resolved target address, or None if not resolvable.
    """
    parts = mnem.split()
    if len(parts) < 2:
        return None
    operand = parts[1].lstrip("@").rstrip(",")
    if not operand.startswith("r") or not operand[1:].isdigit():
        return None
    reg = operand
    cur = addr - 2
    # Walk backward up to 16 instructions — well past GCC's typical
    # 1–4 instruction gap between load and indirect branch.
    for _ in range(16):
        if cur < fn_start or cur not in reachable:
            break
        off = cur - vram
        if off + 1 >= len(binary):
            break
        op = (binary[off] << 8) | binary[off + 1]
        m, tgt = _decode_sh2(op, cur)
        if m is None:
            cur -= 2
            continue
        # Word-boundary match for `..., rN` as the destination — bare
        # substring would treat `r1` as a prefix of `r15`, etc.
        def _ends_with_reg(s, r):
            tail = f", {r}"
            idx = s.rfind(tail)
            if idx < 0:
                return False
            nxt = s[idx + len(tail) : idx + len(tail) + 1]
            return nxt == "" or not nxt.isdigit()

        # mov.l @(0x..., PC), rN — the load we're looking for
        if m.startswith("mov.l @(0x") and _ends_with_reg(m, reg) and tgt is not None:
            poff = tgt - vram
            if 0 <= poff + 3 < len(binary):
                v = (binary[poff] << 24) | (binary[poff+1] << 16) | (binary[poff+2] << 8) | binary[poff+3]
                return v
            return None
        # Any other write to rN — stop, value unknowable statically
        # (covers: mov.l @rX, rN ; mov rX, rN ; mov #imm, rN ; etc.)
        # Store-to-mem forms (`mov.l rN, @...`) have rN as source, not
        # destination — skip those.  Cmp/tst don't modify their second
        # operand either.
        if (_ends_with_reg(m, reg)
                and not m.startswith(("cmp", "tst",
                                      f"mov.l {reg},",
                                      f"mov.w {reg},",
                                      f"mov.b {reg},"))):
            return None
        cur -= 2
    return None


# ---------------------------------------------------------------------------
# The model itself.  Implementations land here phase by phase.
# ---------------------------------------------------------------------------

class BinaryModel:
    """Whole-binary code intelligence.  Built once per server boot; refreshed
    only when reference/probe inputs change (which they don't during a
    session).  Verified-subseg state is held by SweepState, not here.

    Construction reads:
      - binary bytes (target_path)
      - vram (load address)
      - pool_priors_path (optional, from <yaml>.pool_priors.txt)
      - reference_dir (optional, .s files with FUN_<addr>: labels)        [phase 2]
      - reference_scan_dir (optional, sibling .s tree)                     [phase 2]
      - runtime_hits_dirs (optional, *.summary.json probe files)           [phase 2]

    Phase plan:
      Phase 1: __init__ + byte_kind + pool_words                  ← DONE
      Phase 2: callers + reference_starts + runtime_hits
      Phase 3: analyze_function (replaces oracle.analyze_candidate)
    """

    def __init__(self,
                 binary: bytes,
                 vram: int,
                 pool_priors_path: Optional[Path] = None,
                 reference_dir: Optional[Path] = None,
                 reference_scan_dir: Optional[Path] = None,
                 runtime_hits_dirs: Optional[list] = None,
                 ):
        self.binary = binary
        self.vram = vram
        self.end_addr = vram + len(binary) - 1

        # Phase 1 outputs
        self.byte_kind: dict = {}            # {addr: ByteKind}
        self.pool_words: dict = {}           # {addr: PoolWord}

        # Phase 2 outputs
        # NOTE: kept as flat {addr: count} dicts to match eval_server's
        # wire format exactly for parity.  The richer CallSite-list shape
        # in this file's dataclasses is reserved for future enrichment
        # when a consumer needs it (no consumer today, so we don't build
        # what we don't use).
        self.static_callers: dict = {}       # {addr: int} — same-binary calls
        self.cross_module_callers: dict = {} # {addr: int} — sibling hot-swap modules
        self.reference_starts: set = set()   # set of int addrs
        self.reference_nexts: dict = {}      # {ref_start: next_ref_start}
        self.runtime_hits: dict = {}         # {addr: int}
        # Switch-dispatch case targets found by scanning the binary for
        # the `mov.l @(disp,PC), rN; ...; mov.l @rN, rN; jmp @rN` pattern
        # and walking the 4-byte jump table it loads from.  Treated as a
        # fourth function-entry signal by Pass E — switch case bodies
        # are real code entries even though nothing bsr/bra's them
        # directly.
        self.switch_targets: set = set()     # set of int addrs

        # Phase 3 outputs
        self.instructions: dict = {}         # {addr: Instruction}
        self.indirect_resolutions: dict = {} # {addr: resolved_target}

        # analyze_function result cache.  Key: (start, hint_end).  Pure
        # over BinaryModel inputs, so process-lifetime caching is safe.
        # `analyze_function` returns a `dataclasses.replace`-copy on each
        # access so the (int-only) `end` field can be safely mutated by
        # callers (e.g. SweepState honoring a yaml end-override on the
        # prev section) without polluting the cached version.
        #
        # The big win is avoiding repeated phase-4 enrichment work
        # (`_compute_indent_depths` in particular is O(blocks^2) per
        # function and dominates per-poll cost when SweepState's
        # listing() iterates ~N siblings to compute cross-function
        # pool references.
        self._analyze_cache: dict = {}

        # ----- Phase 1: pool detection -----
        # Union of (a) reference-derived priors from the .pool_priors.txt
        # sidecar AND (b) whole-binary PC-relative load target scan
        # (two-pass to filter the data-as-code trap).  Matches the union
        # eval_server.py currently builds inline via
        # `dict(binary_pool_targets); priors.update(file_priors)`.
        #
        # The binary-scan subset is also retained on `self` because the
        # phase-2 caller scan needs to skip ONLY binary-scan pool bytes
        # (not file priors) for byte-exact parity with
        # eval_server._load_static_callers.
        file_priors = self._load_file_priors(pool_priors_path)
        self._binary_pool_targets = self._scan_binary_pool_targets()

        pool_union = dict(self._binary_pool_targets)
        pool_union.update(file_priors)       # file priors win on conflict

        for addr, size in pool_union.items():
            self.byte_kind[addr] = ByteKind.POOL4 if size == 4 else ByteKind.POOL2
            self.pool_words[addr] = PoolWord(
                addr=addr,
                size=size,
                value=self._read_word(addr, size),
                loaded_from=[],              # reserved — no consumer yet
            )

        # ----- Phase 2: reference / callgraph / runtime -----
        # Order matters: reference_starts feeds cross_module_callers.
        self.reference_starts = self._load_reference_starts(reference_dir)
        self.reference_nexts  = self._build_reference_nexts(self.reference_starts)
        # Sorted list for "next reference start after arbitrary addr"
        # lookups (used by phase-4 reference agreement).  Computed once
        # because the set never changes during a session.
        self._reference_starts_sorted = sorted(self.reference_starts)
        self.static_callers   = self._scan_static_callers()
        self.cross_module_callers = self._scan_cross_module_callers(
            reference_scan_dir, reference_dir,
        )
        self.runtime_hits = self._load_runtime_hits(runtime_hits_dirs)

        # ----- Switch-dispatch target detection -----
        # Scan the binary for `mov.l @(disp,PC), rN; ...; mov.l @rN, rN;
        # jmp @rN` switch idioms.  Each detected dispatch contributes
        # its case body addresses to switch_targets.  Pass E uses them
        # as function-entry signals so it doesn't classify case bodies
        # as orphan pool.
        self.switch_targets = self._scan_all_switch_targets()

        # ----- Pass E: orphan pool inference -----
        # Contiguous UNKNOWN runs bracketed by POOL on BOTH sides AND
        # containing no function-entry signals (static caller, reference
        # FUN_ label, cross-module caller, switch-dispatch target)
        # → classify as POOL2.
        self._classify_orphan_pool()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def pool_priors_dict(self) -> dict:
        """Return a {addr: size} dict equivalent to the union eval_server
        currently feeds to oracle.analyze_candidate(..., pool_priors=...).

        UNION VIEW — combines file_priors + binary-scan targets.  When a
        consumer needs the binary-scan SUBSET only (as `_scan_static_callers`
        does to build its pool-data skip set), access
        `self._binary_pool_targets` directly rather than this method.

        Used during phase 3 transition: while analyze_function isn't yet
        implemented, eval_server (or the parity harness) can swap its
        inline `dict(binary_pool_targets); update(file_priors)` for
        `model.pool_priors_dict()` and get identical behavior.
        """
        out = {}
        for addr, kind in self.byte_kind.items():
            if kind is ByteKind.POOL4:
                out[addr] = 4
            elif kind is ByteKind.POOL2:
                out[addr] = 2
        return out

    def is_address_in_function(self, addr: int, fn: FunctionAnalysis) -> bool:
        """Cheap membership check — used by eval_server to validate pin
        requests without re-analyzing.

        RESERVED — no consumer today; phase 8 (eval_server2 routes) will
        call this from /pin-start and /pin-end handlers."""
        return fn.start <= addr <= fn.end

    def analyze_multi_block(self,
                            blocks: list,
                            active_block: int = 0,
                            ) -> FunctionAnalysis:
        """Synthesize a FunctionAnalysis for one block of a multi-block
        function (e.g. a switch dispatcher whose case bodies live in
        physically disjoint regions of the binary).

        `blocks` is a list of dicts with int `start` and `end` keys.
        `active_block` selects which block to materialize.  The result:

          - walks from `block.start` with hint_end=`block.end` to get
            the primary FunctionAnalysis
          - finds every function-entry signal in (block.start, block.end]
            (reference_starts, static_callers > 0, switch_targets) that
            isn't already classified as pool data, walks from each, and
            unions the resulting reachable + branches into the primary
            so case bodies past the primary walker's natural end show
            up as code (not as POOL from Pass E's mis-classification).
          - forces `end` to `block.end` so the row emitter renders the
            full block range even when the walker stopped short.

        Filtering by pool data prevents the JT base address being walked
        as code — `static_callers` can flag a JT base when some other
        function loads it via pool, but it IS data and walking it
        decodes the table entries as instructions.
        """
        if not blocks:
            raise ValueError("analyze_multi_block: blocks must be non-empty")
        idx = active_block % len(blocks)
        blk = blocks[idx]
        start = int(blk["start"])
        end = int(blk["end"])

        fa = self.analyze_function(start, hint_end=end)

        pool_addrs = self.pool_words
        extra_starts: set = set()
        for a in self.reference_starts:
            if start < a <= end and a not in pool_addrs:
                extra_starts.add(a)
        for a, n in self.static_callers.items():
            if n > 0 and start < a <= end and a not in pool_addrs:
                extra_starts.add(a)
        for a in self.switch_targets:
            if start < a <= end and a not in pool_addrs:
                extra_starts.add(a)

        if extra_starts:
            merged_reachable = set(fa.reachable)
            merged_branches = list(fa.branches)
            merged_resolutions = dict(fa.indirect_resolutions)
            for s in extra_starts:
                sub = self.analyze_function(s, hint_end=end)
                merged_reachable |= sub.reachable
                merged_branches.extend(sub.branches)
                merged_resolutions.update(sub.indirect_resolutions)
            fa = _dc_replace(
                fa,
                reachable=merged_reachable,
                branches=merged_branches,
                indirect_resolutions=merged_resolutions,
            )

        if fa.end != end:
            fa = _dc_replace(fa, end=end)

        # Re-classify branch internality against the full block range.
        # Each sub-walk classified branches against its own narrow range
        # (e.g., case 9's walk only knew [0x0604D570, ...]).  In the
        # merged view the block's range is wider, so previously-external
        # targets that land inside the block become internal arrows.
        fa = _dc_replace(
            fa,
            branches=_classify_branch_internality(fa.branches, start, end),
        )

        return fa

    def analyze_function(self,
                         start: int,
                         hint_end: Optional[int] = None,
                         ) -> FunctionAnalysis:
        """Cached analyze_function.  Returns a copy of the cached
        FunctionAnalysis so callers can safely mutate `end` (the only
        field SweepState mutates post-analysis) without polluting the
        cache.  Cache key is (start, hint_end)."""
        key = (start, hint_end)
        cached = self._analyze_cache.get(key)
        if cached is None:
            cached = self._analyze_function_uncached(start, hint_end)
            self._analyze_cache[key] = cached
        # `_dc_replace` makes a new FunctionAnalysis with the SAME field
        # values.  Primitive fields (start, end, prologue_stack, etc.)
        # are copied by value; container fields (branches, reachable,
        # indent_depths, ...) are shared by reference — safe because no
        # code mutates them post-analysis (verified by inspection of
        # SweepState's call sites: only `.end` gets mutated).
        return _dc_replace(cached)

    def _analyze_function_uncached(self,
                                    start: int,
                                    hint_end: Optional[int] = None,
                                    ) -> FunctionAnalysis:
        """Phase 3b: produces FunctionAnalysis using inlined helpers.

        Mirrors oracle.analyze_candidate's flow exactly:
          1. Walk prologue → saved/stack/flags
          2. Control-flow walk → reachable + branches
          3. Epilogue walk backward from last reachable instruction
          4. Augment restored set with PR/MACL pops anywhere in reachable
             (handles GCC's early-cycle-scheduled restores)
          5. Extend end through trailing pool zone
          6. Find conditional_rts
          7. Classify branch internality (also sets direction)
          8. Collect pool_targets
          9. Run verdict

        Phase-4 fields (indent_depths, reference, midpoints, evidence,
        phantom_hint, indirect_resolutions) stay at dataclass defaults
        until phase 4 moves the corresponding eval_server logic here.
        """
        binary = self.binary
        vram = self.vram
        pool_priors = self.pool_priors_dict()

        binary_max = vram + len(binary) - 1
        hard_limit = hint_end if hint_end is not None else binary_max

        # 1. Prologue
        prologue_end, saved, stack_alloc, flags = _walk_prologue(binary, vram, start)
        prologue_range = (start, prologue_end)

        # 2. Control flow + branches.  Pool_priors lets the walker trace
        # switch-dispatch jump tables (braf r0 over a .short table).
        reachable, max_reachable, branches, indirect = _control_flow_walk(
            binary, vram, start, hard_limit, pool_priors=pool_priors,
        )

        # Last byte of the function is the last byte of the last reachable
        # instruction.  For rts/rte/bra with delay slots, the delay slot's
        # 2nd byte is the end.
        code_end = max_reachable + 1

        # 3. Epilogue walk from the last code byte (NOT post-extension
        # boundary — pool data would scramble it).
        epi_start, restored, stack_dealloc, final_rts, delay_slot = _walk_epilogue_backward(
            binary, vram, code_end, func_start=start, saved=saved,
        )
        epilogue_range = (epi_start, code_end) if epi_start is not None else (None, None)

        # 4. Augment `restored` with PR / MACL pops anywhere in reachable.
        # GCC will cycle-schedule the restore early, placing it OUTSIDE the
        # contiguous-epilogue window the backward walker tracks.  Without
        # this scan the critical-pr/macl-not-restored flag fires on
        # otherwise-fine cycle-optimized functions.
        if "pr" in saved and "pr" not in restored:
            for a in reachable:
                op = _read_opcode(binary, vram, a)
                if op is None:
                    continue
                mnem, _ = _decode_sh2(op, a)
                if mnem and _is_pr_pop(mnem):
                    restored.append("pr")
                    break
        if "macl" in saved and "macl" not in restored:
            for a in reachable:
                op = _read_opcode(binary, vram, a)
                if op is None:
                    continue
                mnem, _ = _decode_sh2(op, a)
                if mnem and _is_macl_pop(mnem):
                    restored.append("macl")
                    break

        # 5. Extend end through trailing pool zone (no-op if pool_priors empty).
        end = _extend_through_trailing_pools(code_end, binary, vram, hard_limit, pool_priors)

        # 6. Find conditional rts (rts that are NOT the final one).
        conditional_rts = []
        for addr in sorted(reachable):
            op = _read_opcode(binary, vram, addr)
            if op is None:
                continue
            mnem, _ = _decode_sh2(op, addr)
            if mnem and mnem.startswith("rts") and addr != final_rts:
                conditional_rts.append(addr)

        # 7. Classify branches (sets internal + direction).
        branches = _classify_branch_internality(branches, start, end)

        # 8. Collect pool targets (rescan reachable instructions).
        pool_targets = []
        for addr in sorted(reachable):
            op = _read_opcode(binary, vram, addr)
            if op is None:
                continue
            _, tgt = _decode_sh2(op, addr)
            if tgt is not None:
                pool_targets.append(tgt)

        # 9. Verdict.
        verdict_str, yellow = _verdict(
            saved, stack_alloc, restored, stack_dealloc,
            final_rts, branches, conditional_rts,
        )
        flags.extend(yellow)
        try:
            verdict_enum = Verdict[verdict_str]
        except KeyError:
            verdict_enum = Verdict.UNKNOWN

        # ----- Phase 4: per-function enrichment -----
        # All fields below were previously computed in eval_server and
        # bolted onto FunctionEvidence after the fact.  Pulling them into
        # FunctionAnalysis means eval_server2 just reads them.

        # CFG region depths.  Uses the same fn_start/fn_end as eval_server:
        # function start through last reachable instruction's end byte
        # (code_end, NOT the post-pool-extension `end`) so pool data
        # doesn't pollute the region graph.
        indent_depths = _compute_indent_depths(
            binary, vram, start, code_end, branches,
        )

        # Indirect-branch target resolutions.  For every jmp/jsr/braf/bsrf
        # instruction in `indirect`, walk backward to find the load that
        # produced its register value.  Pre-computed here so the renderer
        # doesn't re-scan per row.
        indirect_resolutions = {}
        for ind_addr in indirect:
            op = _read_opcode(binary, vram, ind_addr)
            if op is None:
                continue
            mnem, _ = _decode_sh2(op, ind_addr)
            if mnem is None:
                continue
            resolved = _resolve_indirect_target(
                binary, vram, reachable, start, ind_addr, mnem,
            )
            if resolved is not None:
                indirect_resolutions[ind_addr] = resolved

        # Reference agreement, evidence, midpoints.
        reference = self._compute_reference_agreement(start, end)
        evidence, midpoints = self._compute_evidence_and_midpoints(start, end)

        # Phantom-caller hint.  Computed from the augmented flag list
        # (which already includes _verdict's "no prologue" string when
        # applicable).  When phantom_hint is True we ALSO prepend the
        # human-facing warning string to flags — matching eval_server's
        # _build_candidate_payload behavior so consumers see the warning
        # in the same form they always have.
        phantom_hint = self._compute_phantom_hint(evidence, flags)
        if phantom_hint:
            flags = ["supported only by cross-module phantom callers (likely hot-swap collision, not a real entry)"] + list(flags)

        return FunctionAnalysis(
            start=start,
            end=end,
            prologue_range=prologue_range,
            prologue_saved=saved,
            prologue_stack=stack_alloc,
            epilogue_range=epilogue_range,
            final_exit=final_rts,
            delay_slot=delay_slot,
            branches=branches,
            conditional_returns=conditional_rts,
            pool_targets=pool_targets,
            reachable=reachable,
            indirect_calls=list(indirect),
            verdict=verdict_enum,
            yellow_flags=flags,
            indent_depths=indent_depths,
            indirect_resolutions=indirect_resolutions,
            reference=reference,
            midpoints=midpoints,
            evidence=evidence,
            phantom_hint=phantom_hint,
        )

    # ------------------------------------------------------------------
    # Phase 1 internals
    # ------------------------------------------------------------------

    def _read_word(self, addr: int, size: int) -> int:
        """Read a big-endian 2- or 4-byte word at addr.  Used during
        pool_words construction."""
        off = addr - self.vram
        if size == 4 and off + 3 < len(self.binary):
            b = self.binary
            return (b[off] << 24) | (b[off+1] << 16) | (b[off+2] << 8) | b[off+3]
        if size == 2 and off + 1 < len(self.binary):
            b = self.binary
            return (b[off] << 8) | b[off+1]
        return 0

    def _load_file_priors(self, priors_path: Optional[Path]) -> dict:
        """Load pool address priors from <yaml_stem>.pool_priors.txt.

        Format: one address-size pair per line, hex addr + decimal size:
            0x06037296 2
            0x0603729C 4
            # comments allowed, blank lines OK

        Mirrors eval_server._load_pool_priors verbatim.  Returns {addr: size}.
        """
        if priors_path is None or not priors_path.exists():
            return {}
        priors = {}
        for raw in priors_path.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    priors[int(parts[0], 16)] = int(parts[1])
                except ValueError:
                    pass
        return priors

    def _scan_binary_pool_targets(self) -> dict:
        """Two-pass binary-wide PC-relative load target scan.

        Walks every 2-byte-aligned address, decodes the opcode, and if it's
        a PC-relative load (`mov.l @(disp,PC),Rn`, `mov.w @(disp,PC),Rn`,
        `mova @(disp,PC),r0`), records the target address with the right
        size (4 for mov.l/mova, 2 for mov.w).

        Two passes avoid the data-as-code trap: bytes INSIDE a pool word
        can themselves bit-align as a valid `mov.l @(disp,PC)` opcode and
        produce a phantom pool target.  Pass 1 builds the naive pool set;
        pass 2 re-scans skipping bytes inside pass-1 pool words.

        Mirrors eval_server._load_binary_pool_targets verbatim.  Returns
        {addr: size}.
        """
        binary = self.binary
        vram = self.vram
        end_addr = self.end_addr

        def scan(skip_addrs: set) -> dict:
            pool_sizes = {}
            for addr in range(vram, end_addr, 2):
                if addr in skip_addrs:
                    continue
                off = addr - vram
                op = (binary[off] << 8) | binary[off + 1]
                hi = (op >> 12) & 0xF
                if hi == 0xD:
                    # mov.l @(disp,PC), Rn — 4-byte aligned target
                    disp = op & 0xFF
                    tgt = (addr & 0xFFFFFFFC) + 4 + disp * 4
                    if vram <= tgt <= end_addr:
                        pool_sizes[tgt] = 4
                elif hi == 0x9:
                    # mov.w @(disp,PC), Rn — 2-byte target.  Don't downgrade
                    # if mov.l already claimed it (same address can be loaded
                    # both ways, but mov.l implies 4-byte semantics).
                    disp = op & 0xFF
                    tgt = addr + 4 + disp * 2
                    if vram <= tgt <= end_addr and tgt not in pool_sizes:
                        pool_sizes[tgt] = 2
                elif hi == 0xC and ((op >> 8) & 0xF) == 7:
                    # mova @(disp,PC), r0 — 4-byte aligned target (jump-table head)
                    disp = op & 0xFF
                    tgt = (addr & 0xFFFFFFFC) + 4 + disp * 4
                    if vram <= tgt <= end_addr:
                        pool_sizes[tgt] = 4
            return pool_sizes

        # Pass 1: naive scan, no skips
        pass1 = scan(set())
        # Pass 2: skip every 2-byte address inside a pass-1 pool word
        pool_data_addrs = set()
        for tgt, size in pass1.items():
            for i in range(0, size, 2):
                pool_data_addrs.add(tgt + i)
        return scan(pool_data_addrs)

    # ------------------------------------------------------------------
    # Phase 2 internals — reference / callgraph / runtime
    # ------------------------------------------------------------------

    @staticmethod
    def _load_reference_starts(reference_dir: Optional[Path]) -> set:
        """Parse `FUN_<addr>:` labels from every .s file in reference_dir.

        Mirrors eval_server._load_reference_starts.  Returns a set of int
        addrs (eval_server returns sorted list; set + sorted-on-demand is
        cheaper for membership tests).
        """
        if reference_dir is None or not reference_dir.is_dir():
            return set()
        import re
        starts = set()
        fun_re = re.compile(r"^FUN_([0-9A-Fa-f]{8}):\s*$")
        for s_file in reference_dir.glob("*.s"):
            for raw in s_file.read_text(errors="replace").splitlines():
                m = fun_re.match(raw.strip())
                if m:
                    starts.add(int(m.group(1), 16))
        return starts

    @staticmethod
    def _build_reference_nexts(reference_starts: set) -> dict:
        """Precompute the next-reference-start for each reference start.

        Used by FunctionAnalysis.reference (phase 4) to compute end_delta
        without re-iterating reference_starts on every lookup.
        """
        if not reference_starts:
            return {}
        sorted_starts = sorted(reference_starts)
        nexts = {}
        for i, s in enumerate(sorted_starts):
            nexts[s] = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else None
        return nexts

    def _scan_static_callers(self) -> dict:
        """Scan THIS binary's bytes for call references to each address.

        Two patterns:
          1. Direct PC-relative branches (`bsr disp`, `bra disp`): top
             nibble 0xA / 0xB, 12-bit signed disp.
          2. Pool-loaded function pointers: `mov.l @(disp,PC),Rn` reads
             a 4-byte pool word; if the word's value lands in vram range
             AND is 2-byte aligned, count it as a function-pointer ref.

        Skips bytes inside known pool words (from the binary-scan subset
        only — NOT file priors — to match eval_server byte-for-byte).
        Pool bytes that bit-align as bsr/bra opcodes would otherwise
        produce phantom callers.

        Mirrors eval_server._load_static_callers.  Returns {addr: count}.
        """
        import struct
        binary = self.binary
        vram = self.vram
        end = self.end_addr

        # Build pool-data-skip set from the binary-scan subset (matching
        # eval_server's STATE["binary_pool_targets"] usage exactly).
        pool_data_addrs = set()
        for tgt, size in self._binary_pool_targets.items():
            for i in range(0, size, 2):
                pool_data_addrs.add(tgt + i)

        callers: dict = {}
        for addr in range(vram, end, 2):
            if addr in pool_data_addrs:
                continue
            off = addr - vram
            op = (binary[off] << 8) | binary[off + 1]
            hi = (op >> 12) & 0xF
            if hi in (0xA, 0xB):
                disp = op & 0xFFF
                if disp > 0x7FF:
                    disp -= 0x1000
                target = addr + 4 + disp * 2
                if vram <= target <= end:
                    callers[target] = callers.get(target, 0) + 1
            elif hi == 0xD:
                disp = op & 0xFF
                pool_addr = (addr & 0xFFFFFFFC) + 4 + disp * 4
                poff = pool_addr - vram
                if 0 <= poff + 3 < len(binary):
                    v = struct.unpack(">I", binary[poff:poff + 4])[0]
                    if vram <= v <= end and (v & 1) == 0:
                        callers[v] = callers.get(v, 0) + 1
        return callers

    def _scan_cross_module_callers(self,
                                    scan_dir: Optional[Path],
                                    this_module_dir: Optional[Path],
                                    ) -> dict:
        """Text-scan sibling hot-swap module .s files for same-name refs.

        Saturn games hot-swap modules into a shared load address (Daytona's
        race/select/result2p/name/backup/ending all live at 0x06028000,
        only one resident at a time).  A `bsr FUN_X` in select's reference
        cannot resolve to this binary at runtime — but we surface them as
        informational pills so the human knows the address collides with
        same-name targets in other binaries.

        Skips .s files inside `this_module_dir` — those are picked up by
        `_scan_static_callers` from raw binary bytes.

        Mirrors eval_server._load_cross_module_callers.  Returns {addr: count}.
        """
        if scan_dir is None or this_module_dir is None:
            return {}
        if not scan_dir.is_dir() or not this_module_dir.is_dir():
            return {}
        import re
        this_module_resolved = this_module_dir.resolve()
        branch_re = re.compile(
            r"\b(?:bsr|bsr\.s|jsr|jmp|bra|braf|bsrf)\b[^/]*?"
            r"\b(?:xref_)?FUN_([0-9A-Fa-f]{8})\b(?!\s*\+)"
        )
        pool_re_fun = re.compile(
            r"\.4byte\s+(?:xref_FUN_|FUN_)([0-9A-Fa-f]{8})\b(?!\s*\+)"
        )
        pool_re_dat = re.compile(
            r"\.4byte\s+DAT_([0-9A-Fa-f]{8})\b(?!\s*\+)"
        )
        reference_starts = self.reference_starts
        cross: dict = {}
        for s_file in scan_dir.glob("**/*.s"):
            try:
                in_same = s_file.resolve().is_relative_to(this_module_resolved)
            except (AttributeError, ValueError):
                in_same = str(s_file.resolve()).startswith(str(this_module_resolved))
            if in_same:
                continue
            try:
                text = s_file.read_text(errors="replace")
            except Exception:
                continue
            for line in text.splitlines():
                for m in branch_re.finditer(line):
                    a = int(m.group(1), 16); cross[a] = cross.get(a, 0) + 1
                for m in pool_re_fun.finditer(line):
                    a = int(m.group(1), 16); cross[a] = cross.get(a, 0) + 1
                for m in pool_re_dat.finditer(line):
                    a = int(m.group(1), 16)
                    if a in reference_starts:
                        cross[a] = cross.get(a, 0) + 1
        return cross

    # ------------------------------------------------------------------
    # Switch-dispatch target detection + Pass E (orphan pool)
    # ------------------------------------------------------------------

    def _scan_all_switch_targets(self) -> set:
        """Walk the binary at 2-byte stride; for every `jmp @rN` that
        matches the GCC switch-dispatch idiom, harvest the jump-table
        case body addresses into a set.

        Pattern (within ~8 instructions before the jmp):
            mov.l @(disp,PC), rN     ; rN = *pool — the table start addr
            ...                       ; (shll2 / add / etc.)
            mov.l @rN, rN             ; rN = *rN  — case body at table[index]
            jmp @rN                   ; transfer

        The pool word's VALUE is the table start.  The table is a run
        of 4-byte case body addresses; we walk forward stopping at the
        first entry whose value isn't a valid 2-byte-aligned vram-range
        address.
        """
        binary = self.binary
        vram = self.vram
        binary_end = self.end_addr

        targets: set = set()
        for jmp_pc in range(vram, binary_end, 2):
            tgts = self._detect_mov_l_jmp_switch_targets(jmp_pc)
            for t in tgts:
                targets.add(t)
        return targets

    def _detect_mov_l_jmp_switch_targets(self, jmp_pc: int) -> list:
        """Binary-wide variant: returns ALL in-vram-range case targets at
        jmp_pc (no func_start/hard_limit filter).  Used by the binary-wide
        switch-target pre-scan that feeds Pass E.  Per-function callers
        (the control-flow walker) use the module-level helper directly
        with func_start/hard_limit filtering.
        """
        return _detect_mov_l_jmp_switch_targets(
            self.binary, self.vram, jmp_pc, binary_end=self.end_addr,
        )

    def _classify_orphan_pool(self) -> None:
        """Pass E: orphan pool inference.

        For each contiguous run of UNKNOWN 2-byte-aligned addresses
        (neither already-classified in byte_kind nor inside a multi-byte
        pool word), classify the run as POOL2 if:
          (1) the address immediately before the run is POOL or
              pool-internal,
          (2) the address immediately after the run is POOL or
              pool-internal,
          (3) no address in the run carries a function-entry signal:
              static_caller > 0, reference FUN_ label, cross-module
              caller > 0, OR a switch-dispatch case target.

        Condition (3) is the safeguard.  Without the switch-target
        check, case bodies sitting between pool zones (like
        FUN_060352FA's switch cases at 0x06035314, 0x0603533C, ...)
        would be wrongly classified as data because no direct
        bsr/bra/reference points to them — they're reached only via
        the dispatcher's `jmp @rN` through the jump table.
        """
        binary = self.binary
        vram = self.vram
        binary_end = self.end_addr

        # Pool-internal byte set: every byte INSIDE a multi-byte pool
        # word.  byte_kind only stores the start-of-word address.
        pool_internal: set = set()
        for addr, pw in self.pool_words.items():
            for i in range(2, pw.size, 2):
                pool_internal.add(addr + i)

        def _is_pool_anchor(a: int) -> bool:
            kind = self.byte_kind.get(a)
            if kind in (ByteKind.POOL2, ByteKind.POOL4):
                return True
            return a in pool_internal

        def _is_unknown(a: int) -> bool:
            return (a not in self.byte_kind) and (a not in pool_internal)

        def _has_fn_entry_signal(a: int) -> bool:
            if a in self.reference_starts:
                return True
            if self.static_callers.get(a, 0) > 0:
                return True
            if self.cross_module_callers.get(a, 0) > 0:
                return True
            if a in self.switch_targets:
                return True
            return False

        addr = vram
        run_start: Optional[int] = None
        run_has_signal = False
        while addr + 1 <= binary_end:
            if _is_unknown(addr):
                if run_start is None:
                    run_start = addr
                    run_has_signal = False
                if _has_fn_entry_signal(addr):
                    run_has_signal = True
                addr += 2
                continue

            # Classified address — close any open run.
            if run_start is not None:
                run_end = addr - 2
                before = run_start - 2
                after = addr
                bracketed = (
                    before >= vram
                    and _is_pool_anchor(before)
                    and _is_pool_anchor(after)
                )
                if bracketed and not run_has_signal:
                    a = run_start
                    while a <= run_end:
                        off = a - vram
                        if off + 1 >= len(binary):
                            break
                        value = (binary[off] << 8) | binary[off + 1]
                        self.byte_kind[a] = ByteKind.POOL2
                        self.pool_words[a] = PoolWord(
                            addr=a, size=2, value=value, loaded_from=[],
                        )
                        a += 2
                run_start = None
                run_has_signal = False

            addr += 2

    # ------------------------------------------------------------------
    # Phase 4 internals — per-function enrichment
    # ------------------------------------------------------------------

    def _compute_reference_agreement(self, start: int, end: int) -> ReferenceAgreement:
        """Compare proposed (start, end) against the reference's view.

        Returns a ReferenceAgreement with:
          - verdict: "agrees" | "disagrees" | "silent"
          - start_match: bool (does reference have FUN_<start>?)
          - reference_next: addr of reference's next FUN > start, or None
          - reference_implied_end: reference_next - 1, or None
          - end_delta: our_end - reference_implied_end (positive = we're longer)
          - tooltip: human-readable summary

        Mirrors eval_server._compute_reference_agreement.  Tolerance for
        "agrees" is 16 bytes — reference boundaries include pool/padding
        between functions so exact end-byte agreement is rare.
        """
        start_match = start in self.reference_starts

        reference_next = None
        for a in self._reference_starts_sorted:
            if a > start:
                reference_next = a
                break

        reference_implied_end = (reference_next - 1) if reference_next is not None else None
        end_delta = (end - reference_implied_end) if reference_implied_end is not None else None

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

        return ReferenceAgreement(
            verdict=verdict,
            start_match=start_match,
            reference_next=reference_next,
            reference_implied_end=reference_implied_end,
            end_delta=end_delta,
            tooltip=tooltip,
        )

    def _compute_evidence_and_midpoints(self, start: int, end: int):
        """Build the function's evidence (caller + runtime counts at
        start) and its midpoints (reference FUN starts strictly inside
        (start, end] with their own evidence).

        Returns (FunctionEvidence, list[Midpoint]).
        Mirrors eval_server._compute_candidate_evidence.
        """
        sc = self.static_callers
        cm = self.cross_module_callers
        rh = self.runtime_hits

        midpoints = []
        for a in self._reference_starts_sorted:
            if a <= start:
                continue
            if a > end:
                break  # sorted list — no more candidates beyond end
            # a is in (start, end]
            midpoints.append(Midpoint(
                addr=a,
                static_callers=sc.get(a, 0),
                cross_module_callers=cm.get(a, 0),
                runtime_hits=rh.get(a, 0),
            ))

        evidence = FunctionEvidence(
            static_callers=sc.get(start, 0),
            cross_module_callers=cm.get(start, 0),
            runtime_hits=rh.get(start, 0),
        )
        return evidence, midpoints

    @staticmethod
    def _compute_phantom_hint(evidence: FunctionEvidence, yellow_flags: list) -> bool:
        """Detect the 'cross-module phantom caller' pattern: a candidate
        supported ONLY by sibling hot-swap module references (physically
        impossible at runtime), with no same-module caller and no
        prologue register pushes.  Strongly suggests the address isn't a
        real function entry in this binary.

        Mirrors eval_server._build_candidate_payload's inline check.
        """
        has_cross = evidence.cross_module_callers > 0
        has_same = evidence.static_callers > 0
        no_prologue = any("no prologue register pushes" in f for f in yellow_flags)
        return has_cross and not has_same and no_prologue

    @staticmethod
    def _load_runtime_hits(runtime_hits_dirs: Optional[list]) -> dict:
        """Aggregate BP-pass hit counts across probe summaries.

        Each directory is globbed for `*.summary.json` files; their
        `by_address: {hex_addr: count}` field gets max-merged across
        summaries (probes overwrite their own summary so summing across
        re-snapshots would double-count).

        Mirrors eval_server._load_runtime_hits.  Returns {addr: max_count}.
        """
        if not runtime_hits_dirs:
            return {}
        import json as _json
        hits: dict = {}
        for d in runtime_hits_dirs:
            p = Path(d)
            if not p.is_dir():
                continue
            for f in p.glob("*.summary.json"):
                try:
                    with open(f) as fp:
                        s = _json.load(fp)
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


# ---------------------------------------------------------------------------
# Sweep state — encapsulates yaml + override-driven candidate selection,
# gap detection, progress, and the listing model.
# ---------------------------------------------------------------------------

class SweepState:
    """Yaml-state-dependent derived state.  Cheap to construct per /state
    poll (the BinaryModel is the expensive bit, reused across polls).

    Phase plan:
      Phase 5: next_candidate / gaps / progress      ← DONE
      Phase 6: listing (per-pane)
      Phase 7: aligned_listings (split-view diff)
    """

    def __init__(self,
                 model: BinaryModel,
                 yaml_cfg: dict,
                 ai_override: Optional[dict] = None,
                 analyze_mode: Optional[dict] = None,
                 ):
        self.model = model
        self.yaml_cfg = yaml_cfg
        self.ai_override = dict(ai_override or {})
        # Analyze-mode blocks are treated as "virtual stamps" by the
        # outstanding-case-target scan: their switch dispatchers feed
        # into outstanding_case_of just like real verified subsegs do.
        # Lets the user explore a multi-block hypothesis in analyze mode
        # and see "Possible case N" hints fire as if each block were
        # already approved.
        self.analyze_mode = dict(analyze_mode or {})

        # Parse verified code subsegs into typed records.  Sort by start
        # so forward-sweep gets deterministic predecessor order.
        self.verified = [
            VerifiedSubseg(
                start=s["start"],
                end=s["end"],
                type=s.get("type", "code"),
                file=s.get("file", ""),
            )
            for s in (yaml_cfg.get("subsegments") or [])
            if s.get("type") == "code"
        ]
        self.verified.sort(key=lambda s: s.start)

        # Translation units (file boundaries) — used to cap analyze_function's
        # hint_end so the CFG walk doesn't run off into the next TU when a
        # branch goes there.
        self.tus = list(yaml_cfg.get("tus") or [])

        # Sibling-pool cache: per-subseg reachable sets are expensive to
        # build (each requires a full analyze_function), so cache and
        # reuse.  Keyed by subseg start; invalidated implicitly because
        # SweepState is rebuilt per /state poll.
        self._sibling_pool_cache: dict = {}

        # Verified-starts set for fast membership tests during listing
        # symbolization (indirect-target resolution renders "FUN_<addr>"
        # vs "0x<addr>" based on whether the resolved target is stamped).
        self._verified_starts = {s.start for s in self.verified}

        # Lazy cache for the outstanding-case-targets map.  Built on
        # first access via `outstanding_case_of`.
        self._outstanding_case_of_cache: Optional[dict] = None

    @property
    def outstanding_case_of(self) -> dict:
        """For every stamped code subseg, scan it for jmp@rN / braf switch
        dispatchers.  For each case target that lands OUTSIDE the
        dispatcher's own subseg, record it here.

        Returns dict: target_addr -> list of (dispatcher_start, case_idx)
        tuples (one address can be the target of multiple cases — both
        across dispatchers AND within a single dispatcher's table when
        duplicate slots share a handler).

        Used by the listing renderer to hint "Possible case N of
        FUN_xxxxxxxx" when a trailing-zone address coincides with a
        known outstanding case target.  This is the canonical signal
        for "the analyzer's suggested function boundary is probably too
        short — the next address is actually a switch case body".
        """
        if self._outstanding_case_of_cache is not None:
            return self._outstanding_case_of_cache

        binary = self.model.binary
        vram = self.model.vram
        binary_max = vram + len(binary) - 1
        pool_priors = self.model.pool_priors_dict()

        # Union of real verified subsegs and analyze-mode "virtual" blocks.
        # Both are scanned the same way: jmp@rN / braf inside their range,
        # case targets that fall outside their range are "outstanding".
        ranges = [(s.start, s.end) for s in self.verified]
        for b in (self.analyze_mode.get("blocks") or []):
            ranges.append((int(b["start"]), int(b["end"])))

        result: dict = {}
        for r_start, r_end in ranges:
            for pc in range(r_start, r_end, 2):
                # mov.l + jmp @rN switch
                tgts = _detect_mov_l_jmp_switch_targets(
                    binary, vram, pc, binary_end=binary_max,
                )
                if not tgts:
                    # mova + braf switch (alt idiom)
                    tgts = _detect_braf_switch_targets(
                        binary, vram, pc, pool_priors,
                    )
                for idx, t in enumerate(tgts):
                    if r_start <= t <= r_end:
                        continue  # target lives inside the dispatcher itself
                    result.setdefault(t, []).append((r_start, idx))

        self._outstanding_case_of_cache = result
        return result

    # ------------------------------------------------------------------
    # Public — candidate selection
    # ------------------------------------------------------------------

    def next_candidate(self) -> Optional[NextCandidate]:
        """Return the candidate the UI should show.  If ai_override is
        active, honor it; otherwise forward-sweep from the latest
        verified subseg.

        Mirrors eval_server._compute_current(ignore_override=False).
        """
        if self.ai_override.get("candidate_start"):
            return self._override_candidate()
        return self._forward_sweep_candidate()

    def natural_candidate(self) -> Optional[NextCandidate]:
        """Same as next_candidate but ignores ai_override — used by the
        split-view 'ORACLE NATURAL' pane.

        Mirrors eval_server._compute_current(ignore_override=True).
        """
        return self._forward_sweep_candidate()

    # ------------------------------------------------------------------
    # Public — gap detection + progress
    # ------------------------------------------------------------------

    def gaps(self, proposed_start: Optional[int] = None) -> list:
        """Find every uncovered byte range BETWEEN consecutive verified
        code subsegs PLUS the pending gap between the latest verified
        subseg and the currently-proposed candidate (if any).

        Why include the pending gap: when forward-sweep can't find a real
        function in a zone (no reference label, no prologue, no callers),
        it skips over to the next function it CAN find — leaving a
        would-be gap that the user will create the instant they approve.
        We catch this state pre-emptively rather than waiting for the
        approval to fire the banner.

        The actual tail (after the proposed candidate's end) is still
        excluded — that's the unswept frontier ahead of forward-sweep,
        not a gap.

        Returns list[Gap].  Each `pending` field:
          False = gap already exists in the yaml (a real bug to backfill)
          True  = gap is between latest-stamped and current proposal
                  (would be created on approval)
        """
        gaps = []
        prev = None
        for s in self.verified:
            if prev is not None and s.start > prev.end + 1:
                gap_start = prev.end + 1
                gap_end = s.start - 1
                gaps.append(Gap(
                    start=gap_start,
                    end=gap_end,
                    size=gap_end - gap_start + 1,
                    preceding_start=prev.start,
                    preceding_name=f"FUN_{prev.start:08X}",
                    pending=False,
                ))
            prev = s

        # Pending gap between latest verified and the proposed candidate.
        if proposed_start is not None and prev is not None:
            if proposed_start > prev.end + 1:
                gap_start = prev.end + 1
                gap_end = proposed_start - 1
                gaps.append(Gap(
                    start=gap_start,
                    end=gap_end,
                    size=gap_end - gap_start + 1,
                    preceding_start=prev.start,
                    preceding_name=f"FUN_{prev.start:08X}",
                    pending=True,
                ))
        return gaps

    def progress(self) -> Progress:
        """Sum verified code subseg bytes vs total binary size.

        Mirrors eval_server._compute_progress.
        """
        verified_bytes = sum(s.end - s.start + 1 for s in self.verified)
        total_bytes = len(self.model.binary)
        pct = (verified_bytes / total_bytes * 100.0) if total_bytes else 0.0
        return Progress(
            verified_bytes=verified_bytes,
            total_bytes=total_bytes,
            pct=pct,
        )

    # ------------------------------------------------------------------
    # Internal — forward-sweep + override resolution
    # ------------------------------------------------------------------

    def _forward_sweep_candidate(self) -> Optional[NextCandidate]:
        """Forward-sweep candidate generation.

        Sorts verified subsegs by start.  For each, scans the bytes
        immediately after `end` looking for the next function-start
        pattern.  Returns the FIRST such candidate that isn't already
        a verified subseg.

        Mirrors oracle.find_next_forward_sweep_candidate, but pulls
        binary/vram/pool_priors/reference_starts/static_callers/
        cross_module_callers from self.model (single source of truth).
        """
        model = self.model
        binary = model.binary
        vram = model.vram
        binary_end = vram + len(binary) - 1

        pool_priors = model.pool_priors_dict()
        reference_starts = model.reference_starts
        static_callers = model.static_callers
        cross_module_callers = model.cross_module_callers

        def _covered_by_existing(addr):
            """True if addr falls inside any verified subseg's [start, end]
            range — not just at a start.  Catches the case where forward
            sweep latches on a prologue inside a function that was
            ai_overridden to start a few bytes earlier."""
            for s in self.verified:
                if s.start <= addr <= s.end:
                    return True
            return False

        # Head-of-binary case: if the binary's first address isn't covered
        # by any declared subseg, look for a function there first.  Handles
        # both the bootstrap case (no anchors yet) and re-review of the
        # very first function after an /unstamp at the binary head.
        if not self.verified or self.verified[0].start > vram:
            next_start = _scan_for_next_prologue(
                binary, vram, vram, binary_end,
                reference_starts=reference_starts,
                static_callers=static_callers,
                cross_module_callers=cross_module_callers,
            )
            if next_start is not None and not _covered_by_existing(next_start):
                tu = next((t for t in self.tus if t["start"] <= next_start <= t["end"]), None)
                hint_end = tu["end"] if tu else None
                fa = model.analyze_function(next_start, hint_end=hint_end)
                return NextCandidate(previous=None, function=fa)

        for prev in self.verified:
            next_start = _scan_for_next_prologue(
                binary, vram, prev.end + 1, binary_end,
                reference_starts=reference_starts,
                static_callers=static_callers,
                cross_module_callers=cross_module_callers,
            )
            if next_start is None:
                continue
            if _covered_by_existing(next_start):
                # Already inside an existing verified subseg — keep iterating.
                continue
            # Pick the ACTUAL immediately-preceding subseg, not the iteration's
            # `prev`.  The scan can walk past an unsignaled-but-verified subseg
            # (e.g. a 4-byte alternate-entry stub with no callers + no reference
            # FUN_<addr>: declaration) and land on a candidate further out.  In
            # that case the `prev` we're iterating from is stale — the real
            # previous-verified-subseg is the one that hugs next_start.
            actual_prev = max(
                (s for s in self.verified if s.end < next_start),
                key=lambda s: s.end,
                default=prev,
            )
            tu = next((t for t in self.tus if t["start"] <= next_start <= t["end"]), None)
            hint_end = tu["end"] if tu else None
            fa = model.analyze_function(next_start, hint_end=hint_end)
            return NextCandidate(previous=actual_prev, function=fa)

        return None

    # ------------------------------------------------------------------
    # Phase 6 — listing model
    # ------------------------------------------------------------------

    def listing(self,
                candidate: FunctionAnalysis,
                previous: Optional[VerifiedSubseg],
                attn: Optional[list] = None,
                ) -> list:
        """Build the four-section row list for one pane.

        Sections: prev (verified) / intermediate (between prev end and
        candidate start) / current (candidate) / trailing (TRAILING_BYTES
        bytes after candidate).

        Decorations applied per row:
          - section, kind, indent (capped at MAX_DISPLAY_INDENT)
          - prologue / epilogue / final_rts / cond_rts / unreachable
          - category + is_tail_call + is_indirect_branch
          - branch_target / direction / type for arc rendering
          - attn / midpoint / ref_end (precedence: attn > midpoint > ref_end)
          - indirect_resolved_label inline annotation
          - pin_action: PIN_START above candidate, PIN_END at/below
          - unpin_action on section headers when override active

        Mirrors eval_server.render_listing + _emit_function_lines +
        _emit_raw_bytes + _emit_section_header.
        """
        attn_set = set(attn or [])

        rows = []
        row_id = [0]  # mutable counter so _emit_* can bump it

        def next_id():
            i = row_id[0]
            row_id[0] += 1
            return i

        # ----- 1. Previous section (if a prev subseg is provided) -----
        if previous is not None:
            # Analyze prev with hint_end = yaml's stamped end so the
            # analysis honors the human's recorded boundary.  Then force
            # .end to the yaml end so the displayed range matches what
            # the splitter will emit (analyzer's CFG-walk may stop short
            # at a delay slot, but the eval_tool's display must reflect
            # what race.s shows, not what oracle's heuristic considers
            # "reachable code only").
            prev_fa = self.model.analyze_function(
                previous.start, hint_end=previous.end,
            )
            prev_fa.end = previous.end

            size = previous.end - previous.start + 1
            self._emit_section_header(
                rows, next_id, Section.PREV,
                f"VERIFIED  FUN_{previous.start:08X}  "
                f"0x{previous.start:08X} → 0x{previous.end:08X}  ({size} bytes)",
                anchor_addr=previous.start,
            )
            self._emit_function_rows(rows, next_id, prev_fa, Section.PREV, attn_set, candidate)

            # ----- 2. Intermediate section (gap between prev end and candidate start) -----
            if previous.end + 1 < candidate.start:
                gap_start = previous.end + 1
                gap_end = candidate.start - 1
                self._emit_section_header(
                    rows, next_id, Section.INTERMEDIATE,
                    f"INTERMEDIATE  0x{gap_start:08X} → 0x{gap_end:08X}  "
                    f"({candidate.start - previous.end - 1} bytes, likely pool/padding)",
                    anchor_addr=gap_start,
                )
                self._emit_raw_rows(rows, next_id, gap_start, gap_end, Section.INTERMEDIATE)

        # ----- 3. Current section (the candidate) -----
        size = candidate.end - candidate.start + 1
        self._emit_section_header(
            rows, next_id, Section.CURRENT,
            f"PROPOSED  FUN_{candidate.start:08X}  "
            f"0x{candidate.start:08X} → 0x{candidate.end:08X}  ({size} bytes)  "
            f"verdict: {candidate.verdict.value}",
            anchor_addr=candidate.start,
        )
        self._emit_function_rows(rows, next_id, candidate, Section.CURRENT, attn_set, candidate)

        # ----- 4. Trailing section (TRAILING_BYTES past candidate end) -----
        trailing_start = candidate.end + 1
        trailing_end = candidate.end + TRAILING_BYTES
        binary_end = self.model.end_addr
        if trailing_start <= binary_end:
            actual_end = min(trailing_end, binary_end)
            self._emit_section_header(
                rows, next_id, Section.TRAILING,
                f"TRAILING  0x{trailing_start:08X} → 0x{actual_end:08X}  "
                f"({actual_end - trailing_start + 1} bytes after candidate)",
                anchor_addr=trailing_start,
            )
            self._emit_raw_rows(rows, next_id, trailing_start, actual_end, Section.TRAILING)

        return rows

    # ----- Section / row emitters --------------------------------------

    def _emit_section_header(self, rows, next_id, section, label, anchor_addr=None):
        """Emit a section header row.  Anchor_addr used by split-view
        diff alignment to pair headers across panes."""
        # Unpin action: only the PROPOSED (current) and TRAILING headers
        # in the primary pane get [unpin] buttons, and only when an
        # ai_override is active.  Eval_server's keys.js gates the buttons
        # on `showUnpinAll` / `showUnpinEnd` flags — analyzer encodes the
        # same semantics structurally.
        unpin = UnpinAction.NONE
        if self.ai_override.get("candidate_start"):
            if section is Section.CURRENT:
                unpin = UnpinAction.UNPIN_ALL
            elif section is Section.TRAILING and self.ai_override.get("candidate_end") is not None:
                unpin = UnpinAction.UNPIN_END
        rows.append(ListingRow(
            row_id=next_id(),
            kind=RowKind.SECTION_HEADER,
            section=section,
            addr=None,
            anchor_addr=anchor_addr,
            label=label,
            unpin_action=unpin,
        ))

    def _emit_function_rows(self, rows, next_id, fa, section, attn_set, candidate):
        """Translate FunctionAnalysis + pool sets into ListingRows for [fa.start, fa.end].

        SINGLE RESPONSIBILITY: lookup, not decide.  Reads pre-decided
        classifications (fa.reachable, fa.branches, fa.indirect_resolutions,
        fa.indent_depths, pool sets) and translates to row records.
        Doesn't re-derive any of them.

        `candidate` is the CURRENT candidate — pin clicks always refer
        to it (above candidate.start → PIN_START; on/below → PIN_END).
        """
        binary = self.model.binary
        vram = self.model.vram

        # Per-function pool view: pool4/pool2/mova sets + internal branch targets.
        pool4, pool2, mova, branch_targets = self._build_per_function_pool_view(fa)

        prologue_lo, prologue_hi = fa.prologue_range
        epi_lo, epi_hi = fa.epilogue_range if fa.epilogue_range else (None, None)
        branches_at = {b.src: b for b in fa.branches}

        # Decoration sets: midpoints and ref-end derived from this
        # function's analysis (NOT the displayed candidate's), so prev-
        # section midpoints land on prev's rows.  attn applies to all
        # rows regardless of section (it's a user-set address list).
        midpoint_set = {m.addr for m in fa.midpoints}
        ref_end_addr = None
        if fa.reference is not None and fa.reference.reference_next is not None:
            ref_end_addr = fa.reference.reference_next

        addr = fa.start
        while addr <= fa.end:
            depth = min(fa.indent_depths.get(addr, 0), MAX_DISPLAY_INDENT)

            # Decoration precedence: attn > midpoint > ref_end.  Each row
            # gets AT MOST one of these flags set true.
            is_attn = addr in attn_set
            is_mid  = (not is_attn) and (addr in midpoint_set)
            is_ref_end = (not is_attn) and (not is_mid) and (addr == ref_end_addr)

            # Pin action: above candidate.start → pin_start (clicking +
            # nudges candidate start back to this addr); at/below →
            # pin_end (clicking + pins candidate end to addr-1, "next
            # function starts here").
            if addr < candidate.start:
                pin = PinAction.PIN_START
            else:
                pin = PinAction.PIN_END

            # ----- Outstanding switch-case-target hint label
            # When this address is a known case target of an already-
            # stamped (or analyze-mode-block) switch dispatcher, emit a
            # suggestion label so the user knows where the address sits
            # in the dispatch table — critical when the analyzer's
            # boundary may be cutting through a case body.
            case_hint = self.outstanding_case_of.get(addr)
            if case_hint:
                by_disp: dict = {}
                for disp_start, case_idx in case_hint:
                    by_disp.setdefault(disp_start, []).append(case_idx)
                parts = []
                for disp_start, idxs in by_disp.items():
                    cases_str = ", ".join(str(i) for i in sorted(set(idxs)))
                    parts.append(f"case {cases_str} of FUN_{disp_start:08X}")
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label="Possible " + "; ".join(parts) + ":",
                ))

            # ----- Pool4 row?
            if addr in pool4:
                off = addr - vram
                v = (binary[off] << 24) | (binary[off+1] << 16) | (binary[off+2] << 8) | binary[off+3]
                row = ListingRow(
                    row_id=next_id(),
                    kind=RowKind.POOL4,
                    section=section,
                    addr=addr,
                    bytes_hex=" ".join(f"{binary[off+i]:02X}" for i in range(4)),
                    text=f".4byte 0x{v:08X}",
                    label=f".L_pool_{addr:08X}",
                    indent=0,  # pool data doesn't participate in CFG indent
                    is_attn=is_attn,
                    is_midpoint=is_mid,
                    is_ref_end=is_ref_end,
                    pin_action=pin,
                )
                # Branch arc on a pool row — rare auto-disassembler edge
                # case where a `.4byte` actually decodes to a branch.
                b = branches_at.get(addr)
                if b is not None and b.target is not None and b.internal:
                    row.branch_target = b.target
                    row.branch_direction = b.direction
                    row.branch_type = "cond" if b.mnem in {"bf", "bt", "bf/s", "bt/s"} else "uncond"
                rows.append(row)
                addr += 4
                continue

            # ----- Pool2 row?
            if addr in pool2:
                off = addr - vram
                v = (binary[off] << 8) | binary[off+1]
                row = ListingRow(
                    row_id=next_id(),
                    kind=RowKind.POOL2,
                    section=section,
                    addr=addr,
                    bytes_hex=" ".join(f"{binary[off+i]:02X}" for i in range(2)),
                    text=f".2byte 0x{v:04X}",
                    label=f".L_pool_{addr:08X}",
                    indent=0,
                    is_attn=is_attn,
                    is_midpoint=is_mid,
                    is_ref_end=is_ref_end,
                    pin_action=pin,
                )
                b = branches_at.get(addr)
                if b is not None and b.target is not None and b.internal:
                    row.branch_target = b.target
                    row.branch_direction = b.direction
                    row.branch_type = "cond" if b.mnem in {"bf", "bt", "bf/s", "bt/s"} else "uncond"
                rows.append(row)
                addr += 2
                continue

            # ----- Branch-target label row?  (.L_<addr>: marker)
            if addr in branch_targets and addr != fa.start:
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label=f".L_{addr:08X}:",
                    indent=min(fa.indent_depths.get(addr, 0), MAX_DISPLAY_INDENT),
                    is_attn=is_attn,
                    is_midpoint=is_mid,
                    is_ref_end=is_ref_end,
                    pin_action=pin,
                ))
                # Fall through — emit the instruction row at the same addr too.

            # ----- Instruction row
            off = addr - vram
            if off + 1 >= len(binary):
                break
            op = (binary[off] << 8) | binary[off+1]
            mnem, _ = _decode_sh2(op, addr)
            if mnem is None:
                mnem = f".byte 0x{binary[off]:02X}, 0x{binary[off+1]:02X}"
            symbolized = _symbolize_mnem(mnem, pool4, pool2, mova, branch_targets)
            head = mnem.split()[0] if mnem else ""
            category = _classify_mnem_to_category(mnem)

            row = ListingRow(
                row_id=next_id(),
                kind=RowKind.INSTRUCTION,
                section=section,
                addr=addr,
                bytes_hex=f"{binary[off]:02X} {binary[off+1]:02X}",
                text=symbolized,
                indent=depth,
                category=category,
                is_attn=is_attn,
                is_midpoint=is_mid,
                is_ref_end=is_ref_end,
                pin_action=pin,
            )

            # Prologue / epilogue tinting (only meaningful in current
            # section visually, but flagged for ALL sections so the
            # template can decide).
            if prologue_lo is not None and prologue_lo <= addr <= prologue_hi:
                row.is_prologue = True
            if epi_lo is not None and epi_lo <= addr <= epi_hi:
                row.is_epilogue = True
            if addr == fa.final_exit:
                row.is_final_rts = True
            if addr in fa.conditional_returns:
                row.is_conditional_rts = True

            # Unreachable: bytes decoded as instructions but unreachable
            # from the function entry.  Pool/data handled above; what
            # remains here is genuine dead-or-data that decode_sh2
            # happened to spell as a valid mnemonic.  Zero indent so it
            # doesn't appear nested under live code.
            if addr not in fa.reachable:
                row.is_unreachable = True
                row.indent = 0
                row.tag = "unreach"

            # Branch / direction / arc metadata.
            b = branches_at.get(addr)
            if b is not None and b.target is not None:
                row.branch_target = b.target
                row.branch_direction = b.direction
                if b.internal:
                    row.branch_type = "cond" if b.mnem in {"bf", "bt", "bf/s", "bt/s"} else "uncond"
                if b.internal:
                    row.margin = "↓" if b.target > b.src else "↑"
                else:
                    # External target: tail-call (uncond) or external
                    # conditional exit.
                    row.margin = "→"
                    if head in _UNCOND_HEADS:
                        row.is_tail_call = True
                        row.tag = "⇒ TAIL?"
                    elif head in _COND_HEADS:
                        row.is_tail_call = True
                        row.tag = "↗ external"

            # Indirect calls (jsr @rN / bsrf rN): control returns.  Subtle tag.
            if head in _CALL_HEADS:
                if not row.tag:
                    row.tag = "↩ ret"

            if head in ("jmp", "braf"):
                row.is_indirect_branch = True

            # Indirect-branch target resolution annotation (inline).
            # `FUN_<addr>` if target is a verified subseg start, else `0x<addr>`.
            # For switch dispatches the all-targets listing below overrides
            # this with the full case list.
            if head in ("jmp", "braf", "jsr", "bsrf"):
                resolved = fa.indirect_resolutions.get(addr)
                if resolved is not None:
                    if resolved in self._verified_starts:
                        sym = f"FUN_{resolved:08X}"
                    else:
                        sym = f"0x{resolved:08X}"
                    row.text = f"{symbolized}   ⇒ {sym}"
                    row.indirect_resolved_label = sym

            # Switch-dispatch detection + tag classification.  Runs the
            # detector once and uses the result for both the all-targets
            # text annotation AND the row tag (so we can tell switch
            # dispatches apart from single-target indirect jumps).
            if head in ("jmp", "braf"):
                switch_targets = []
                if b is not None and b.target is not None:
                    binary_arg = self.model.binary
                    vram_arg = self.model.vram
                    if head == "jmp":
                        switch_targets = _detect_mov_l_jmp_switch_targets(
                            binary_arg, vram_arg, addr,
                        )
                    else:
                        pool_priors = self.model.pool_priors_dict()
                        switch_targets = _detect_braf_switch_targets(
                            binary_arg, vram_arg, addr, pool_priors,
                        )
                if switch_targets:
                    targets_str = ", ".join(f"0x{t:08X}" for t in switch_targets)
                    row.text = f"{symbolized}   ⇒ {targets_str}"
                if not row.tag:
                    if switch_targets:
                        row.tag = "⇒ switch"
                    elif b is not None and b.target is not None and b.internal:
                        row.tag = "⇒"          # single-target internal — arrow speaks
                    elif b is not None and b.target is not None:
                        row.tag = "⇒ TAIL?"    # single-target external — tail call
                    else:
                        row.tag = "⇒ exits"    # truly indirect — couldn't resolve

            # Direct unconditional jump with internal target — quiet tag.
            if head == "bra" and b is not None and b.internal:
                if not row.tag:
                    row.tag = "⇒"

            # Returns — explicit EXIT tag.
            if head in _RETURN_HEADS:
                row.tag = "⇒ EXIT"

            rows.append(row)
            addr += 2

    def _emit_raw_rows(self, rows, next_id, start, end, section):
        """Translate `byte_kind` into ListingRows for intermediate / trailing sections.

        SINGLE RESPONSIBILITY: lookup, not decide.  Don't call
        `_decode_sh2`; don't consult `static_callers`, `reference_starts`,
        or `global_reachable` here.  UNKNOWN byte_kind is a bug upstream
        in BinaryModel construction, not something this function patches
        by sniffing.
        """
        binary = self.model.binary
        vram = self.model.vram
        binary_end = self.model.end_addr
        end = min(end, binary_end)
        addr = start
        case_hints = self.outstanding_case_of if section is Section.TRAILING else {}

        while addr <= end:
            off = addr - vram
            if off + 1 >= len(binary):
                break

            # Trailing-zone case-target hint.  When this address is a
            # known outstanding case target of a stamped dispatcher,
            # emit a label suggesting the analyzer's boundary may be
            # too short — the next instruction is actually a switch
            # case body of some already-stamped function.
            hint = case_hints.get(addr)
            if hint:
                # Group by dispatcher; list case indices per dispatcher.
                by_disp: dict = {}
                for disp_start, case_idx in hint:
                    by_disp.setdefault(disp_start, []).append(case_idx)
                parts = []
                for disp_start, idxs in by_disp.items():
                    cases_str = ", ".join(str(i) for i in sorted(set(idxs)))
                    parts.append(f"case {cases_str} of FUN_{disp_start:08X}")
                hint_text = "Possible " + "; ".join(parts) + ":"
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label=hint_text,
                ))

            kind = self.model.byte_kind.get(addr)
            if kind is ByteKind.POOL4 and addr + 3 <= end and off + 3 < len(binary):
                value = (binary[off] << 24) | (binary[off+1] << 16) | (binary[off+2] << 8) | binary[off+3]
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.POOL4,
                    section=section,
                    addr=addr,
                    bytes_hex=" ".join(f"{binary[off+i]:02X}" for i in range(4)),
                    text=f".4byte 0x{value:08X}",
                    label=f".L_pool_{addr:08X}",
                ))
                addr += 4
                continue
            if kind is ByteKind.POOL2 and addr + 1 <= end and off + 1 < len(binary):
                value = (binary[off] << 8) | binary[off+1]
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.POOL2,
                    section=section,
                    addr=addr,
                    bytes_hex=" ".join(f"{binary[off+i]:02X}" for i in range(2)),
                    text=f".2byte 0x{value:04X}",
                    label=f".L_pool_{addr:08X}",
                ))
                addr += 2
                continue

            # Otherwise decode as instruction (best-effort).
            op = (binary[off] << 8) | binary[off+1]
            mnem, _ = _decode_sh2(op, addr)
            if mnem is None:
                mnem = f".byte 0x{binary[off]:02X}, 0x{binary[off+1]:02X}"
            category = _classify_mnem_to_category(mnem)
            rows.append(ListingRow(
                row_id=next_id(),
                kind=RowKind.RAW,
                section=section,
                addr=addr,
                bytes_hex=f"{binary[off]:02X} {binary[off+1]:02X}",
                text=mnem,
                category=category,
            ))
            addr += 2

    # ----- Per-function pool view (with sibling pool refs) -------------

    def _build_per_function_pool_view(self, fa: FunctionAnalysis):
        """Build per-function pool4/pool2/mova sets + branch_targets.

        SINGLE RESPONSIBILITY: gather + filter pre-classified pool
        addresses to fa's range.  (Tangent: source #1 still re-decodes
        reachable to bucket by load width; should consume a typed
        FunctionAnalysis field when one exists.)

        Three sources:
          1. PC-relative load targets WITHIN fa.reachable (function-internal).
          2. Sibling pool refs landing INSIDE fa's range (cross-function).
          3. Reference priors inside fa's range NOT in fa.reachable.

        Mirrors eval_server._pools_and_branches.
        """
        binary = self.model.binary
        vram = self.model.vram
        pool4, pool2, mova = set(), set(), set()

        # Source 1: pool refs FROM fa to any target.
        for addr in fa.reachable:
            off = addr - vram
            if off + 1 >= len(binary):
                continue
            op = (binary[off] << 8) | binary[off + 1]
            mnem, tgt = _decode_sh2(op, addr)
            if tgt is None or mnem is None:
                continue
            if mnem.startswith("mov.l @(0x"):
                pool4.add(tgt)
            elif mnem.startswith("mov.w @(0x"):
                pool2.add(tgt)
            elif mnem.startswith("mova @(0x"):
                mova.add(tgt)

        # Source 2: sibling pool refs landing in fa's range.
        sp4, sp2, spm = self._sibling_pool_targets(fa.start, fa.end)
        pool4 |= sp4
        pool2 |= sp2
        mova  |= spm

        # Source 3: reference priors falling in fa's range AND not in
        # reachable.  Skip addrs analyzer's CFG walk reached as code:
        # auto-disassemblers will sometimes wrap a real branch in a
        # `.4byte` literal, but oracle's in-binary decoding is the
        # ground truth — trust it over the prior.
        for addr, pw in self.model.pool_words.items():
            if fa.start <= addr <= fa.end and addr not in fa.reachable:
                if pw.size == 4:
                    pool4.add(addr)
                elif pw.size == 2:
                    pool2.add(addr)

        branch_targets = {}
        for b in fa.branches:
            if b.internal and b.target is not None:
                branch_targets[b.target] = True
        return pool4, pool2, mova, branch_targets

    def _sibling_pool_targets(self, candidate_start: int, candidate_end: int):
        """For all verified code subsegs (excluding any at candidate_start
        itself), find PC-relative load targets that land INSIDE
        [candidate_start, candidate_end].

        Catches pool entries that physically live in the candidate's
        address range but are referenced from sibling functions in the
        same TU — a common Saturn-era compiler/linker pattern.

        Returns (pool4, pool2, mova) sets of addresses.  Cached on
        self._sibling_pool_cache.

        Mirrors eval_server._sibling_pool_targets.
        """
        binary = self.model.binary
        vram = self.model.vram
        p4, p2, pm = set(), set(), set()

        for sub in self.verified:
            if sub.start == candidate_start:
                continue  # skip the candidate itself

            key = sub.start
            if key not in self._sibling_pool_cache:
                # Compute reachable set for this sibling.  Expensive but
                # once per sibling per SweepState lifetime.
                sib_fa = self.model.analyze_function(sub.start, hint_end=sub.end)
                self._sibling_pool_cache[key] = sib_fa.reachable

            sib_reachable = self._sibling_pool_cache[key]
            for addr in sib_reachable:
                off = addr - vram
                if off + 1 >= len(binary):
                    continue
                op = (binary[off] << 8) | binary[off + 1]
                mnem, tgt = _decode_sh2(op, addr)
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

    def _override_candidate(self) -> Optional[NextCandidate]:
        """Apply ai_override to produce the displayed candidate.

        The override pins candidate_start (and optionally candidate_end).
        When candidate_end is pinned, it's used as the analyze_function
        hint_end AND the displayed end (analyzer may report a shorter
        end if a clean exit is found earlier; we override that for
        display since the AI explicitly asked for the longer range).

        Mirrors eval_server._compute_current's override branch.
        """
        ov = self.ai_override
        model = self.model

        start = _coerce_addr(ov["candidate_start"])
        tu = next((t for t in self.tus if t["start"] <= start <= t["end"]), None)

        # AI may also pin the END explicitly (one-off boundary correction
        # the oracle's heuristics can't reach).  When pinned, use it as
        # hint_end so the ENTIRE analysis (CFG walk, epilogue search,
        # prologue/epilogue mirror, verdict) runs against the override
        # boundary — not against TU end with a post-hoc end mutation,
        # which leaves the verdict reflecting whichever epilogue
        # analyzer's natural walk happened to land on (often a different
        # function's rts past the real end).
        end_override_raw = ov.get("candidate_end")
        if end_override_raw is not None:
            hint_end = _coerce_addr(end_override_raw)
        else:
            hint_end = tu["end"] if tu else None

        fa = model.analyze_function(start, hint_end=hint_end)
        if end_override_raw is not None:
            # analyze_function may have chosen an end < hint_end (a clean
            # exit was found before reaching the cap).  Force the
            # displayed/written boundary to match the AI's pin regardless,
            # so the listing reflects what's been requested.
            fa.end = _coerce_addr(end_override_raw)

        # previous_subseg in override is optional — when present, it's the
        # raw yaml subseg dict shape (start/end accept int or hex string).
        prev_raw = ov.get("previous_subseg")
        prev = None
        if prev_raw:
            prev = VerifiedSubseg(
                start=_coerce_addr(prev_raw["start"]),
                end=_coerce_addr(prev_raw["end"]),
                type=prev_raw.get("type", "code"),
                file=prev_raw.get("file", ""),
            )
        return NextCandidate(previous=prev, function=fa)

    def aligned_listings(self,
                         primary: FunctionAnalysis,
                         natural: FunctionAnalysis,
                         primary_previous: Optional[VerifiedSubseg],
                         natural_previous: Optional[VerifiedSubseg],
                         attn: Optional[list] = None,
                         ) -> tuple:
        """For split-view rendering: produce two equal-length row lists
        aligned by anchor address.  Port of keys.js's alignLines.

        Builds each pane's listing via `listing()`, then interleaves the
        two row sequences so rows for the same VRAM anchor address sit
        at the same index.  When one side has a row at an address the
        other doesn't, a BLANK row goes on the missing side.

        Section-header / label / instruction ordering at the same anchor
        is preserved (kindRank: section < label < instr/pool/raw), so a
        side missing the section-header still aligns its instruction
        with the other side's instruction at the same address.

        Returns (primary_aligned, natural_aligned) — equal-length lists.
        """
        primary_rows = self.listing(primary, previous=primary_previous, attn=attn)
        natural_rows = self.listing(natural, previous=natural_previous, attn=attn)
        return self._align_row_lists(primary_rows, natural_rows)

    @staticmethod
    def _align_row_lists(left_rows: list, right_rows: list):
        """Two-pointer interleave by anchor address.  Pure function over
        ListingRow lists; no side effects.  Mirrors keys.js alignLines.
        """
        def anchor(row):
            if row is None:
                return None
            if row.kind is RowKind.SECTION_HEADER:
                return row.anchor_addr
            # Treat addr=0 as no-anchor to match keys.js (`line.addr !== 0`)
            if row.addr is not None and row.addr != 0:
                return row.addr
            return None

        def kind_rank(row):
            if row.kind is RowKind.SECTION_HEADER:
                return 0
            if row.kind is RowKind.LABEL:
                return 1
            return 2  # instruction / pool / raw

        def blank():
            # row_id=-1 marks BLANK as a placeholder; eval_server2 templates
            # render it as an empty row of matching height.
            return ListingRow(row_id=-1, kind=RowKind.BLANK, section=None)

        out_left, out_right = [], []
        li = ri = 0
        L, R = left_rows, right_rows
        while li < len(L) or ri < len(R):
            l = L[li] if li < len(L) else None
            r = R[ri] if ri < len(R) else None
            if l is None:
                out_left.append(blank())
                out_right.append(r)
                ri += 1
                continue
            if r is None:
                out_left.append(l)
                out_right.append(blank())
                li += 1
                continue
            la = anchor(l)
            ra = anchor(r)
            # Lines without anchor addresses (rare — shouldn't happen with
            # the current emitter since section headers carry anchor_addr)
            # just pass through unaligned.
            if la is None and ra is None:
                out_left.append(l); out_right.append(r); li += 1; ri += 1; continue
            if la is None:
                out_left.append(l); out_right.append(blank()); li += 1; continue
            if ra is None:
                out_left.append(blank()); out_right.append(r); ri += 1; continue
            if la == ra:
                lk = kind_rank(l)
                rk = kind_rank(r)
                if lk == rk:
                    out_left.append(l); out_right.append(r); li += 1; ri += 1
                elif lk < rk:
                    out_left.append(l); out_right.append(blank()); li += 1
                else:
                    out_left.append(blank()); out_right.append(r); ri += 1
            elif la < ra:
                out_left.append(l); out_right.append(blank()); li += 1
            else:
                out_left.append(blank()); out_right.append(r); ri += 1
        return out_left, out_right
