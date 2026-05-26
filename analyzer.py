#!/usr/bin/env python3
"""analyzer.py — single source of truth for code intelligence.

Successor to oracle.py + the analytical half of eval_server.py.  Holds every
decision about "what these bytes mean": pool vs code, function boundaries,
CFG reachability, branch internality, callgraph, reference agreement,
midpoints, indent depths, indirect resolutions, sweep state.

eval_server.py is its only consumer.  Eval server NEVER asks "what is at
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
    # Walker-stop confidence at `target` (only set for uncond branches the
    # walker considered as potential tail-call exits — bra and resolved
    # single-target jmp/braf).  Switch-detected indirect branches don't
    # get this — they're handled by switch absorption.  Used by the
    # renderer to surface a confidence-scored row tag + tooltip on the
    # walker's halt/continue decision.
    stop_confidence: Optional[str] = None   # 'HIGH' / 'MEDIUM' / 'NONE' / None
    stop_reasons: list = field(default_factory=list)


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
    DATA = "DATA"      # synthetic verdict for data subsegs (audit mode)


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
    prologue_restored: list = field(default_factory=list)  # mirror of prologue_saved restored in epilogue
    prologue_restored_extras: list = field(default_factory=list)  # epilogue pops that DON'T match a prologue push (caller-frame unwinds)
    epilogue_range: tuple = (None, None) # (start, end_inclusive) or (None, None)
    final_exit: Optional[int] = None     # addr of rts/jmp/braf/bra whose delay slot is at end-1
    delay_slot: Optional[int] = None     # addr of the delay-slot instruction

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
    green_flags: list = field(default_factory=list)
    flag_tooltips: dict = field(default_factory=dict)  # flag_text -> hover-tooltip
    partner_balanced: bool = False        # set by SweepState.apply_partner_awareness when partners resolve combined frame balance

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

    # ----- Branch metadata (for arc drawing)
    branch_target: Optional[int] = None
    branch_direction: Optional[str] = None  # 'forward' / 'backward'
    branch_type: Optional[str] = None        # 'cond' / 'uncond'
    branch_internal: Optional[bool] = None   # target sits inside this function?  external branches use this to opt out of the normal arc renderer (client-side) while still feeding overlay arcs like the partner-pending leap.

    # ----- Indirect-target resolution annotation ("⇒ FUN_X" inline tail)
    indirect_resolved_label: str = ""    # "FUN_0602AB10" or "0x06037000" — empty if not applicable

    # ----- Tentative instruction decode for pool/raw rows
    # When set, the 16-bit value at this addr decodes as a valid SH-2
    # mnemonic, but the address is currently classified as pool data.
    # Renderer shows this in a pale "preview" color after the .2byte
    # text so the human can peek at whether the bytes might actually
    # be code mis-classified as data.  None when the bytes don't
    # decode to a recognizable mnem (genuinely non-code data).
    tentative_decode: Optional[str] = None

    # ----- Walker-stop confidence (only set on bra/jmp/braf rows the
    # walker considered as potential tail-call exits).  Renderer reads
    # `tag_tooltip` for hover-text and may color/style the tag based on
    # `stop_confidence`.
    stop_confidence: Optional[str] = None    # 'HIGH' / 'MEDIUM' / 'NONE' / None (not applicable)
    tag_tooltip: str = ""                     # multi-line text for hover; reasons behind the tag

    # ----- Decoration flags (precedence already resolved: attn > midpoint > ref_end)
    is_attn: bool = False
    is_midpoint: bool = False
    is_ref_end: bool = False
    is_alt_entry: bool = False           # set on the ENTRY: LABEL row emitted at each declared alt entry addr

    # ----- Action wiring — eval_server reads these to attach click handlers
    pin_action: PinAction = PinAction.NONE
    unpin_action: UnpinAction = UnpinAction.NONE

    # ----- "Called from" structured callers (only set on LABEL rows
    # generated from call_sources_of).  Each entry:
    #   {"addr_hex": "0603AB66", "count": 2, "kind": "stamped" | "partner" | "analyze"}
    # The renderer uses `kind` to color each FUN_<addr> span differently
    # — stamped (pale blue, default), partner (pale lavender, same logical
    # function via yaml partners), analyze (pale green, same logical
    # function via current analyze_mode blocks).  `label` still holds the
    # plain-text rendering for fallback / non-call labels.
    callers: list = field(default_factory=list)


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
    partners: list = field(default_factory=list)   # other subseg start addrs forming the same logical C fn
    entries: list = field(default_factory=list)    # alt entry addrs inside (start, end] — one stamp, shared body


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
    # PR / MACL / MACH push — typical pre-prologue save.
    "sts.l pr, @-r15", "sts.l macl, @-r15", "sts.l mach, @-r15",
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
def _is_mach_push(mnem): return mnem == "sts.l mach, @-r15"
def _is_mach_pop(mnem):  return mnem == "lds.l @r15+, mach"


def _ctrl_push(mnem):
    """If mnem is `stc.l <ctrl>, @-r15` (gbr/vbr/sr) return ctrl name."""
    if not mnem.startswith("stc.l "):
        return None
    parts = mnem.split()
    if len(parts) != 3 or parts[2] != "@-r15":
        return None
    return parts[1].rstrip(",")


def _ctrl_pop(mnem):
    """If mnem is `ldc.l @r15+, <ctrl>` (gbr/vbr/sr) return ctrl name."""
    if not mnem.startswith("ldc.l @r15+, "):
        return None
    parts = mnem.split()
    if len(parts) != 3:
        return None
    return parts[2]


def _stack_pushed_reg(mnem):
    """Unified push-extractor: return the register being pushed onto r15
    by `mnem` (one of mov.l rN, sts.l pr/macl/mach, stc.l gbr/vbr/sr) or
    None.
    """
    if not mnem:
        return None
    if _is_pr_push(mnem): return "pr"
    if _is_macl_push(mnem): return "macl"
    if _is_mach_push(mnem): return "mach"
    r = _push_register(mnem)
    if r is not None: return r
    return _ctrl_push(mnem)


def _stack_popped_reg(mnem):
    """Unified pop-extractor: return the register being popped from r15
    by `mnem` (one of mov.l @r15+, lds.l pr/macl/mach, ldc.l gbr/vbr/sr)
    or None."""
    if not mnem:
        return None
    if _is_pr_pop(mnem): return "pr"
    if _is_macl_pop(mnem): return "macl"
    if _is_mach_pop(mnem): return "mach"
    r = _pop_register(mnem)
    if r is not None: return r
    return _ctrl_pop(mnem)


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


def _count_leading_pushes(binary, vram, addr, *, max_scan=8):
    """Count consecutive `mov.l rN, @-r15` pushes starting at `addr`.

    Used as a "target opens with prologue" signal for walker-stop
    decisions: when a bra/jmp lands on a cluster of stack pushes, the
    target almost certainly is a real function entry — independent of
    static-caller count.

    Encoding: mov.l rm, @-rn = 0010 nnnn mmmm 0110.  We mask the 'n'
    nibble to 15 (stack pointer) and accept any 'm'.
    """
    pushes = 0
    for i in range(max_scan):
        op = _read_opcode(binary, vram, addr + 2 * i)
        if op is None:
            break
        if (op & 0xFF0F) != 0x2F06:
            break
        pushes += 1
    return pushes


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
        elif _is_mach_push(mnem):
            saved.append("mach")
            last_prologue = addr
            consecutive_non_prologue = 0
        elif _ctrl_push(mnem) is not None:
            saved.append(_ctrl_push(mnem))
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


def _walk_epilogue_pops_all(binary, vram, end):
    """Walk backward from `end` (last byte of function) collecting EVERY
    register pop in the epilogue zone, regardless of whether it matches
    the prologue's saved list.

    Complementary to _walk_epilogue_backward which uses strict matching
    and stops the first time a pop doesn't correspond to a prologue
    push.  This helper collects the FULL pop sequence so callers
    (specifically the partner-aware verdict in SweepState) can detect
    pops that unwind a CALLER's stack frame — the canonical signal for
    "this function is half of a multi-block C function whose other
    half pushed these regs."

    Returns a list of register names in BACKWARD walk order (last pop
    in execution first).  Order is informational; the partner-aware
    code consumes it as a set.
    """
    delay_slot = end - 1
    rts_addr = delay_slot - 2
    op_rts = _read_opcode(binary, vram, rts_addr)
    if op_rts is None:
        return []
    mnem_rts, _ = _decode_sh2(op_rts, rts_addr)
    if mnem_rts is None:
        return []
    exit_head = mnem_rts.split()[0]
    if exit_head not in ("rts", "jmp", "braf", "bra"):
        return []

    pops: list = []

    def _pop_reg_of(m):
        return (_pop_register(m)
                or ("pr" if _is_pr_pop(m) else None)
                or ("macl" if _is_macl_pop(m) else None)
                or ("mach" if _is_mach_pop(m) else None)
                or _ctrl_pop(m))

    # Check the delay slot — GCC schedules an epilogue pop here sometimes.
    op_ds = _read_opcode(binary, vram, delay_slot)
    if op_ds is not None:
        mnem_ds, _ = _decode_sh2(op_ds, delay_slot)
        if mnem_ds:
            reg = _pop_reg_of(mnem_ds)
            if reg:
                pops.append(reg)

    # Walk backward from the instruction immediately before rts, picking
    # up consecutive pops + dealloc instructions.  Stop at the first
    # non-pop, non-dealloc — that's the body proper.
    cur = rts_addr - 2
    binary_end = vram + len(binary) - 1
    while cur >= vram and cur <= binary_end:
        op = _read_opcode(binary, vram, cur)
        if op is None:
            break
        m, _ = _decode_sh2(op, cur)
        if m is None:
            break
        reg = _pop_reg_of(m)
        if reg is not None:
            pops.append(reg)
            cur -= 2
            continue
        if _is_stack_dealloc(m):
            cur -= 2
            continue
        break

    return pops


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
                      or ("macl" if _is_macl_pop(mnem_ds) else None)
                      or ("mach" if _is_mach_pop(mnem_ds) else None))
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
                or mnem == "sts.l macl, @-r15"
                or mnem == "sts.l mach, @-r15"):
            break

        # Pop / pr-pop / macl-pop / mach-pop: must match expected sequence.
        reg = _pop_register(mnem)
        is_pr = _is_pr_pop(mnem)
        is_macl = _is_macl_pop(mnem)
        is_mach = _is_mach_pop(mnem)
        dealloc = _is_stack_dealloc(mnem)

        if reg or is_pr or is_macl or is_mach:
            popped = (reg
                      or ("pr" if is_pr else None)
                      or ("macl" if is_macl else None)
                      or ("mach" if is_mach else None))
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
    """Recognize the SH-2 switch-dispatch idiom around `braf_pc`.

    Idiom (within ~12 bytes before braf):
        mova @(disp,PC), r0           ; r0 = table base
        mov.w @(r0, rIdx), rDisp      ; rDisp = sign-extended *(r0 + rIdx)
        braf rDisp                    ; PC += rDisp
        <delay slot>

    `rDisp` is whatever the mov.w writes to and the braf reads from —
    GCC's canonical form uses r0 for both, but compilers also emit
    forms that route through r1 (or any other GP reg).  The detector
    locks `rDisp` to the braf's register and matches a mov.w with
    that same destination.

    Returns list[int] of target addresses (possibly empty).
    """
    if not pool_priors:
        return []

    braf_op = _read_opcode(binary, vram, braf_pc)
    if braf_op is None or (braf_op & 0xF0FF) != 0x0023:
        return []
    braf_reg = (braf_op >> 8) & 0xF

    # Scan back from braf for the dispatch chain: mov.w writing
    # braf_reg, then mova writing r0.  Window is generous (~30 bytes)
    # because compilers often interleave unrelated arithmetic between
    # the table load and the braf — observed in real code with up to
    # ~7 intervening instructions.  Bail on any branch/jump/return
    # encountered going back: the dispatch chain has to be straight-
    # line, so crossing a basic-block boundary means we've left the
    # dispatch and any mov.w/mova found further back is unrelated.
    movw_seen = False
    table_base = None
    for back in range(2, 32, 2):
        addr = braf_pc - back
        if addr < vram:
            break
        op = _read_opcode(binary, vram, addr)
        if op is None:
            continue
        mnem, _ = _decode_sh2(op, addr)
        if mnem is not None:
            head = mnem.split()[0]
            if head in _BRANCH_MNEMONICS or head in {"jmp", "jsr", "braf", "bsrf", "rts", "rte"}:
                break
        # mov.w @(R0, Rm), Rn  encoding 0000 nnnn mmmm 1101 — gate
        # the destination on the braf's register so we don't latch a
        # random mov.w that happens to land within the back-scan.
        if (op & 0xF00F) == 0x000D and ((op >> 8) & 0xF) == braf_reg:
            movw_seen = True
            continue
        # mova @(disp, PC), r0  encoding 11000111 dddddddd.
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
        # SH-2 instructions are 2-byte aligned, so an odd target
        # is impossible — drop those silently.  Helps when the
        # reference disasm over-labels bytes past the real table
        # as `.short` data (Pass-E orphan-pool reclassification);
        # without this filter, instruction bytes decoded as table
        # entries can produce odd-addressed bogus targets.
        if target & 1:
            t += 2
            continue
        if lo <= target <= hi:
            targets.append(target)
        t += 2

    return targets


# ----- Control-flow walk + branch classification + pool extension ----------

def _control_flow_walk(binary, vram, start, hard_limit_addr, pool_priors=None,
                       should_stop=None, extra_starts=None):
    """Walk reachable addresses from `start` via control flow.  Returns
    (reachable, max_reachable, branches, indirect_calls).

    `extra_starts` is an optional iterable of additional worklist seeds
    (used for declared alt entry points that share `start`'s function
    body — see VerifiedSubseg.entries).  Each is treated like a fresh
    walk root; reachable, branches, and indirect calls all get merged
    into the same return tuple as if a single function had multiple
    entries.

    Branches collected as analyzer.Branch records (internal=False initially;
    set later by _classify_branch_internality).

    `should_stop` is an optional callable(target_addr) -> (stop_bool,
    confidence_str, reasons_list).  Called on uncond direct bra and
    resolved single-target indirect jmp/braf.  When stop_bool is True
    the walker treats the branch as a tail-call exit (doesn't push the
    target to worklist).  The returned confidence + reasons get
    attached to the Branch for renderer use regardless of follow/stop
    decision — even NONE-confidence branches get the rank annotation.

    Switch-detected indirect branches DON'T consult should_stop —
    switch absorption is a separate explicit mechanism."""
    reachable = set()
    branches = []
    indirect = []
    worklist = [start]
    if extra_starts:
        worklist.extend(extra_starts)
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

                # Walker-stop check for `bra` only (the canonical tail-
                # call style).  Conditional branches (bf/bt/bf-s/bt-s)
                # and calls (bsr) don't get the stop treatment — they
                # don't transfer control unconditionally.
                #
                # Confidence is ALWAYS computed for `bra` so the row
                # renderer can show the rank tag + tooltip regardless
                # of where the target lands.  walker_stop itself is
                # purely diagnostic for in-range targets — internal
                # branches always get followed (they're real flow
                # inside this function, and inflated static_callers
                # counts from same-function internal bras would
                # otherwise wrongly mark in-range labels as
                # unreachable).  Out-of-range bras are never followed
                # regardless (see the `if in_range` push gate below),
                # so the rank annotation lives purely in the tooltip.
                walker_stop = False
                if head == "bra" and should_stop is not None and tgt is not None:
                    _stop_decision, b.stop_confidence, b.stop_reasons = should_stop(tgt)
                branches.append(b)

                # delay-slot branches: bra, bsr, bf/s, bt/s
                if head in {"bf/s", "bt/s", "bra", "bsr"}:
                    reachable.add(pc + 2)
                    if in_range and tgt not in reachable and not is_call and not walker_stop:
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
                            b = Branch(
                                src=pc, target=resolved, mnem=head, internal=False,
                            )
                            # Rank stays diagnostic; only out-of-range
                            # resolved targets are eligible for stop
                            # gating (internal branches always follow).
                            walker_stop = False
                            resolved_in_range = (start <= resolved <= hard_limit_addr)
                            if should_stop is not None:
                                stop_decision, b.stop_confidence, b.stop_reasons = should_stop(resolved)
                                if not resolved_in_range:
                                    walker_stop = stop_decision
                            branches.append(b)
                            if (not walker_stop
                                    and resolved_in_range
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
    saved_critical = {r for r in saved if r in ("pr", "macl", "mach")}
    restored_critical = {r for r in restored if r in ("pr", "macl", "mach")}
    missing_critical = saved_critical - restored_critical

    saved_gp = [r for r in saved if r not in ("pr", "macl", "mach")]
    restored_gp = [r for r in restored if r not in ("pr", "macl", "mach")]
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
        self.switch_clusters: dict = {}      # dispatcher_pc -> sorted unique case targets
        self.switch_dispatcher_of: dict = {} # case_addr -> [(dispatcher_pc, case_idx)]

        # User-declared alt entry points: addresses that share their
        # owning function's body but are themselves entry points
        # (multiple callable entries, one stamp).  Populated by
        # SweepState before each /state poll via set_alt_entries().
        # `alt_entries` is the set of alt addrs; `alt_entry_main`
        # maps each alt to its owning subseg's start.
        self.alt_entries: set = set()
        self.alt_entry_main: dict = {}

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

        # ----- Prologue-pattern scan -----
        # Binary-wide scan for `sts.l pr, @-r15` (0x4F22) — the
        # near-universal SH-2 function prologue opener.  Records
        # every match as a "suspected function entry."  SweepState
        # filters these against known fn-entry signals at /state
        # time; the residue (matches that have NO known signal AND
        # aren't inside a verified subseg) is surfaced as a hint
        # label in the listing — the user gets a discovery channel
        # for functions the reference disasm mis-classified as data.
        # False-positive rate is low: random 16-bit values match
        # 0x4F22 at 1/65536, so a 1MB binary yields ~7-8 chance
        # matches.  The label says "Suspected" so chance matches
        # read as noise, not authoritative claims.
        bin_data = self.binary
        bin_len = len(bin_data)
        sus: set = set()
        i = 0
        while i + 1 < bin_len:
            if bin_data[i] == 0x4F and bin_data[i + 1] == 0x22:
                sus.add(self.vram + i)
            i += 2
        self.suspected_fn_entries = sus

        # ----- Pool4-pointer-target scan -----
        # Every POOL4 literal whose value falls inside the binary
        # range and is 2-byte aligned is a candidate function
        # pointer (some code does `mov.l @(d,PC),rN; jsr @rN` with
        # this address as the target).  Distinct from the prologue
        # scan above — catches LEAF functions that don't save PR
        # (so they don't start with 0x4F22) but ARE called
        # indirectly through a function-pointer literal.  Surfaced
        # as a separate hint label in the listing.  False-positive
        # mode: a pool4 literal can also point at DATA (string,
        # array, struct, LUT base) rather than code — the hint
        # label says "could be data table" so the user verifies.
        self.pool4_pointer_targets = {
            pw.value for pw in self.pool_words.values()
            if pw.size == 4
            and self.vram <= pw.value < self.vram + bin_len
            and (pw.value & 1) == 0
        }

        # ----- Phase B: re-scan static_callers with enriched pool skip -----
        # Pass E reclassified additional bytes as POOL2/POOL4 (jump
        # tables, lookup tables, orphan runs between known pools).  The
        # Phase-A static_callers scan ran with only the binary mov.l/mova
        # target set, so any phantom bsr/bra decodes inside those
        # newly-classified pool regions are sitting in `static_callers`.
        # Re-scan with the enriched skip set so consumers (walker_stop
        # confidence, midpoint scoring, suggested_partners) see filtered
        # counts.
        self.static_callers = self._scan_static_callers(
            pool_data_addrs=self._pool_data_addrs_from_byte_kind(),
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def set_alt_entries(self, alt_entry_main: dict) -> None:
        """Update the alt-entry view from SweepState's parsed yaml.
        Called per /state poll; cheap (dict swap + targeted cache
        eviction).

        When an alt's mapping changes, only the analyze_function
        entries keyed on the affected main(s) need to be evicted —
        walker output for unrelated functions is still valid.
        Surgical eviction keeps sibling analyses warm so the immediate
        post-/queue-entry /state poll doesn't re-walk hundreds of
        unrelated subsegs.  That's the difference between a snappy
        and a multi-second UI response on alt-entry toggles.
        """
        new_map = dict(alt_entry_main or {})
        if new_map == self.alt_entry_main:
            return
        affected_mains: set = set()
        for alt in set(self.alt_entry_main) | set(new_map):
            old_main = self.alt_entry_main.get(alt)
            new_main = new_map.get(alt)
            if old_main != new_main:
                if old_main is not None:
                    affected_mains.add(old_main)
                if new_main is not None:
                    affected_mains.add(new_main)
        self.alt_entry_main = new_map
        self.alt_entries = set(new_map.keys())
        # Cache keys are (start, hint_end); evict only entries whose
        # start is an affected main.
        if affected_mains:
            self._analyze_cache = {
                k: v for k, v in self._analyze_cache.items()
                if k[0] not in affected_mains
            }

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

    def _sibling_case_bodies(self, start: int, max_reachable: int,
                              hard_limit: int, max_gap: int = 64) -> list:
        """When `start` is a switch case target, return sibling case
        targets in the same dispatch table that are physically
        contiguous (gap ≤ max_gap from the current end-of-walk).

        Iterates outward: each absorbed sibling extends the walk's end,
        which may then bring the NEXT sibling into contiguous range.
        Stops at the first sibling that's too far away (≥ max_gap
        bytes past current end) — physically distant case bodies are
        a different cluster and shouldn't be merged.
        """
        if start not in self.switch_dispatcher_of:
            return []
        # Collect all sibling targets from EVERY dispatcher that hits
        # `start` (rare: same addr hit by multiple dispatchers, but
        # union'ed for safety).  Filter to siblings AFTER `start`.
        all_siblings: set = set()
        for disp_pc, _idx in self.switch_dispatcher_of[start]:
            for t in self.switch_clusters.get(disp_pc, []):
                if t > start and t <= hard_limit:
                    all_siblings.add(t)
        if not all_siblings:
            return []

        # Walk siblings in address order, absorbing each that's
        # contiguous with the current walk end.  Stop on the first gap.
        ordered = sorted(all_siblings)
        absorbed: list = []
        cur_end = max_reachable
        for sib in ordered:
            if sib - cur_end > max_gap:
                break
            absorbed.append(sib)
            # Quick peek: walk this sibling to figure out where IT ends.
            # We can't reuse analyze_function (risk of recursion through
            # _sibling_case_bodies); do a stripped control_flow_walk
            # locally.
            sub_reach, sub_max, _b, _i = _control_flow_walk(
                self.binary, self.vram, sib, hard_limit,
                pool_priors=self.pool_priors_dict(),
            )
            cur_end = max(cur_end, sub_max)
        return absorbed

    def walker_stop_confidence(
        self,
        addr: int,
        *,
        verified_starts: Optional[set] = None,
    ) -> tuple:
        """Score whether a CFG walker should STOP at `addr` when it
        encounters a naked bra/jmp to it (treat the branch as a tail
        call rather than absorbing the body at `addr`).

        Distinct from `function_entry_confidence` — that's the richer
        "is this any kind of entry?" question used for UI labeling.
        This one specifically answers: "should the walker halt?"

        Signal taxonomy for STOP decisions:

          HIGH (strong stop):
            - 2+ distinct static callers (v2 methodology: scan binary
              for bsr/jsr opcodes filtered against pool data — robust,
              not derived from external boundary guesses).  Multiple
              independent call sites converge here, almost certainly
              an externally-callable function being tail-called.
            - User-stamped (only when verified_starts is supplied —
              gates the circular logic for audit use).

          MEDIUM:
            - 1 static caller — ambiguous (could be the walker's own
              function, could be a single external caller).

          NONE: everything else.

        Deliberately excluded as primary signals:
          - switch_dispatcher_of: switch absorption is a separate,
            explicit mechanism for "this case body IS part of this
            function's CFG".  Not a halt signal.
          - runtime_hits: derived from Ghidra-set BPs that inherit
            Ghidra's hallucinated boundaries.  Empirical confirmation
            that execution reached an address != confirmation the
            address is an entry point.  Mentioned in reasons as a
            corroborating signal but doesn't bump the level.
          - reference_starts: Ghidra/auto-disassembler output produces
            false midpoints.  Same treatment — corroborating, not
            primary.
        """
        reasons = []
        order = ["NONE", "MEDIUM", "HIGH"]
        level = "NONE"

        def _bump(new_level: str):
            nonlocal level
            if order.index(new_level) > order.index(level):
                level = new_level

        if verified_starts is not None and addr in verified_starts:
            reasons.append("user-stamped function entry")
            _bump("HIGH")

        if addr in self.alt_entries:
            main = self.alt_entry_main[addr]
            reasons.append(f"user-declared alt entry of FUN_{main:08X}")
            _bump("HIGH")

        sc = self.static_callers.get(addr, 0)
        if sc >= 2:
            reasons.append(f"static callers: {sc}")
            _bump("HIGH")
        elif sc == 1:
            reasons.append("static callers: 1")
            _bump("MEDIUM")

        # Corroborating-but-not-primary signals — shown in tooltip but
        # don't bump the level (both derived from Ghidra-tainted
        # sources).
        rh = self.runtime_hits.get(addr, 0)
        if rh > 0:
            reasons.append(f"runtime hits: {rh} (corroborating)")
        if addr in self.reference_starts:
            reasons.append("reference declares as function (corroborating)")

        return level, reasons

    def function_entry_confidence(
        self,
        addr: int,
        *,
        include_reference: bool = False,
        verified_starts: Optional[set] = None,
    ) -> tuple:
        """Score whether `addr` is a function entry point.  Used for
        UI labeling / navigation — NOT for walker stop decisions
        (see `walker_stop_confidence`).

        Switch case targets count HIGH here because they're definitely
        SOME kind of entry, even though they shouldn't trigger a
        walker stop (switch absorption handles them).

        Levels: HIGH / MEDIUM / LOW / NONE.

        HIGH: switch_dispatcher_of, user-stamped, static_callers >= 2
        MEDIUM: static_callers == 1
        LOW (opt-in): reference_starts
        """
        reasons = []
        order = ["NONE", "LOW", "MEDIUM", "HIGH"]
        level = "NONE"

        def _bump(new_level: str):
            nonlocal level
            if order.index(new_level) > order.index(level):
                level = new_level

        if verified_starts is not None and addr in verified_starts:
            reasons.append("user-stamped function entry")
            _bump("HIGH")
        if addr in self.alt_entries:
            main = self.alt_entry_main[addr]
            reasons.append(f"user-declared alt entry of FUN_{main:08X}")
            _bump("HIGH")
        if addr in self.switch_dispatcher_of:
            disps = self.switch_dispatcher_of[addr]
            unique = sorted({d for d, _ in disps})
            disp_str = ", ".join(f"FUN_{d:08X}" for d in unique[:3])
            extra = "" if len(unique) <= 3 else f" (+{len(unique)-3} more)"
            reasons.append(f"switch case target of {disp_str}{extra}")
            _bump("HIGH")

        sc = self.static_callers.get(addr, 0)
        if sc >= 2:
            reasons.append(f"static callers: {sc}")
            _bump("HIGH")
        elif sc == 1:
            reasons.append("static callers: 1")
            _bump("MEDIUM")

        if include_reference and addr in self.reference_starts:
            reasons.append("reference declares as function")
            _bump("LOW")

        return level, reasons

    def is_address_in_function(self, addr: int, fn: FunctionAnalysis) -> bool:
        """Cheap membership check — used by eval_server to validate pin
        requests without re-analyzing.

        RESERVED — no consumer today; eval_server's /pin-start and
        /pin-end handlers could use this to validate pin addresses
        without re-analyzing."""
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
        #
        # CRITICAL: _classify_branch_internality mutates Branch.internal
        # in place.  fa.branches contains Branch objects shared by
        # reference with the BinaryModel's analyze_function cache —
        # mutating them poisons later analyze_function() calls.  Copy
        # each Branch first so the cache stays clean.
        fa = _dc_replace(
            fa,
            branches=_classify_branch_internality(
                [_dc_replace(b) for b in fa.branches], start, end,
            ),
        )

        return fa

    def analyze_function(self,
                         start: int,
                         hint_end: Optional[int] = None,
                         ) -> FunctionAnalysis:
        """Cached analyze_function.  Returns a copy of the cached
        FunctionAnalysis so callers can safely mutate `end` (the only
        field SweepState mutates post-analysis) without polluting the
        cache.  Cache key is (start, hint_end).

        When `start` is a declared alt entry, redirect to the owning
        function's main start — alt entries share the main's body, so
        there's exactly one analysis per multi-entry function.  The
        redirected call BYPASSES the cache: alt callers typically pass
        a hint_end computed from the alt's natural range (e.g. cap to
        next stamp), which can differ from a normal main-keyed
        hint_end and would otherwise pollute the cache entry that
        normal callers of `main` share.
        """
        main = self.alt_entry_main.get(start)
        if main is not None:
            return _dc_replace(self._analyze_function_uncached(main, hint_end))
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
        # should_stop lets the walker halt at naked bra/jmp/braf whose
        # target has function-entry signals — preventing over-absorption
        # across what are conceptually tail-call boundaries.  Threshold
        # is HIGH only (static_callers >= 2) — MEDIUM (single caller)
        # is too noisy: many real internal branches target addresses
        # with one static caller (the function we're walking).  MEDIUM
        # gets surfaced in the tag tooltip as informational instead.
        def _should_stop(tgt):
            level, reasons = self.walker_stop_confidence(tgt)
            return (level == "HIGH", level, reasons)
        # Declared alt entries that belong to this main get seeded into
        # the walker's worklist so their bodies are part of the
        # reachable set.  Multi-entry functions: one stamp, one walk,
        # multiple roots.
        extra_starts = [a for a, m in self.alt_entry_main.items() if m == start]
        reachable, max_reachable, branches, indirect = _control_flow_walk(
            binary, vram, start, hard_limit, pool_priors=pool_priors,
            should_stop=_should_stop, extra_starts=extra_starts,
        )

        # 2b. Switch-cluster sibling absorption.  When `start` is a
        # known case body of a switch dispatcher, the other case
        # bodies in the same dispatch table that are PHYSICALLY
        # CONTIGUOUS form one logical entity (they share the
        # dispatcher's stack frame).  Walk each contiguous sibling
        # and merge its reachable + branches.  Without this, a pin to
        # case 1 would only get case 1's body, leaving cases 2-N
        # rendered in the trailing zone as "next functions".
        sibling_walks = self._sibling_case_bodies(start, max_reachable, hard_limit)
        for sib_start in sibling_walks:
            sub_reach, sub_max, sub_branches, sub_indirect = _control_flow_walk(
                binary, vram, sib_start, hard_limit, pool_priors=pool_priors,
                should_stop=_should_stop,
            )
            reachable |= sub_reach
            max_reachable = max(max_reachable, sub_max)
            branches.extend(sub_branches)
            indirect.extend(sub_indirect)

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

        # 3b. Complementary "all pops" scan — captures pops the strict
        # walker dismissed (i.e., pops that don't match any prologue
        # push because they unwind the CALLER's stack frame).  Used by
        # partner-aware verdict to detect frames balanced across a
        # multi-block function pair.
        #
        # For multi-block functions (e.g., switch case clusters
        # absorbed via _sibling_case_bodies), each absorbed sibling
        # has its OWN epilogue.  Sample ALL exits (rts/rte/jmp/braf/
        # bra in reachable) and union their pops — otherwise sampling
        # only `code_end` (the final exit) would miss the pops carried
        # by other case bodies' epilogues.
        all_pops_union: set = set()
        for a in sorted(reachable):
            op = _read_opcode(binary, vram, a)
            if op is None:
                continue
            mnem, _ = _decode_sh2(op, a)
            if mnem is None:
                continue
            head = mnem.split()[0]
            if head not in ("rts", "rte", "jmp", "braf", "bra"):
                continue
            # Each exit has a delay slot; pops live just BEFORE the
            # exit instruction.  _walk_epilogue_pops_all expects `end`
            # as the last byte of the function/region — for one exit
            # that's the delay slot's 2nd byte (exit_addr + 3).
            all_pops_union |= set(_walk_epilogue_pops_all(binary, vram, a + 3))
        restored_set = set(restored)
        restored_extras = sorted(all_pops_union - restored_set)

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
        if "mach" in saved and "mach" not in restored:
            for a in reachable:
                op = _read_opcode(binary, vram, a)
                if op is None:
                    continue
                mnem, _ = _decode_sh2(op, a)
                if mnem and _is_mach_pop(mnem):
                    restored.append("mach")
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
        # Suppress the "conditional rts" warning when this function is
        # a switch case body (start is a known case target).  Absorbed
        # sibling case bodies legitimately have one rts each — they're
        # each case's natural exit, not "conditional returns mid-
        # function" the way the flag implies.  Clear the list BEFORE
        # _verdict so the verdict score (and HIGH/MEDIUM bucketing)
        # reflect the suppression.
        if start in self.switch_dispatcher_of:
            conditional_rts_for_verdict = []
        else:
            conditional_rts_for_verdict = conditional_rts
        verdict_str, yellow = _verdict(
            saved, stack_alloc, restored, stack_dealloc,
            final_rts, branches, conditional_rts_for_verdict,
        )
        flags.extend(yellow)
        try:
            verdict_enum = Verdict[verdict_str]
        except KeyError:
            verdict_enum = Verdict.UNKNOWN

        # ----- Phase 4: per-function enrichment -----
        # All fields below were previously computed in the v1 eval_server
        # and bolted onto FunctionEvidence after the fact.  Pulling them
        # into FunctionAnalysis means eval_server just reads them.

        # CFG region depths.  Uses the same fn_start/fn_end as the v1 eval_server:
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

        # Positive frame-balance signal.  Two conditions:
        #   (a) every callee-saved reg pushed in the prologue is popped
        #       somewhere reachable
        #   (b) every "orphan" reachable pop (popped but not in the
        #       prologue's saved set) has a matching push reachable too
        #       — i.e., it's part of a locally-balanced save-around-jsr
        #       or similar body pattern, not a partner-frame unwind
        #
        # Bypasses `restored` / `restored_extras` because those depend on
        # the epilogue walker's contiguity rules — variable-size stack
        # deallocs (`sub rN, r15` interleaved between pops at the drain)
        # split the contiguous sequence and leave some prologue pops
        # uncaptured.  Scanning the full reachable set with the unified
        # push/pop extractors is more permissive but catches the cases
        # the contiguity walker misses, while still rejecting truly
        # imbalanced functions via the orphan-with-no-push check.
        # Frame-balance signal — run two complementary checks and
        # dispatch based on whether they agree:
        #
        #   STRICT: set(saved) == set(restored ∪ restored_extras)
        #     Looks only at pops the epilogue walker captured near each
        #     exit.  Misses pops scattered through the body or hidden
        #     behind non-pop instructions (e.g. `sub rN, r15` variable
        #     dealloc interleaved with the drain pops).
        #
        #   PERMISSIVE: saved ⊆ reachable_pops AND every orphan pop has
        #   a matching push reachable
        #     Scans the full reachable set for pops/pushes.  Catches
        #     central-drain functions the strict check misses.  Loses
        #     register-rename-through-stack patterns the strict check
        #     gets right (push rX + pop rY reading the same slot).
        #
        # Both pass  → green "balanced" flag
        # Both fail  → no flag (genuinely unbalanced)
        # Disagree   → yellow "mixed-signal" flag with a tooltip
        #              explaining which check fired and likely structure
        green_flags: list = []
        flag_tooltips: dict = {}
        if saved:
            strict_balanced = set(saved) == set(restored or []) | set(restored_extras or [])
            reachable_pushes: set = set()
            reachable_pops: set = set()
            for a in sorted(reachable):
                op = _read_opcode(binary, vram, a)
                if op is None: continue
                mn, _ = _decode_sh2(op, a)
                if mn is None: continue
                pushed = _stack_pushed_reg(mn)
                if pushed: reachable_pushes.add(pushed)
                popped = _stack_popped_reg(mn)
                if popped: reachable_pops.add(popped)
            saved_set = set(saved)
            unmatched_orphan_pops = (reachable_pops - saved_set) - reachable_pushes
            permissive_balanced = (
                saved_set <= reachable_pops and not unmatched_orphan_pops
            )
            regs_str = ", ".join(saved)
            if strict_balanced and permissive_balanced:
                green_flags.append(f"prologue/epilogue balanced — saved & restored [{regs_str}]")
            elif strict_balanced and not permissive_balanced:
                tag = "pro/epi mixed-signal (rename or partner unwind?)"
                flags.append(tag)
                flag_tooltips[tag] = (
                    f"Saved set [{regs_str}] matches the near-exit epilogue, "
                    "but the function body has reachable pops without "
                    "matching pushes. Likely register-rename through stack "
                    "(push rX, pop rY reads the same slot) OR a partner-"
                    "style unwind of the caller's frame."
                )
            elif not strict_balanced and permissive_balanced:
                tag = "pro/epi mixed-signal (central drain or split exit?)"
                flags.append(tag)
                flag_tooltips[tag] = (
                    f"All saved registers [{regs_str}] are popped somewhere "
                    "reachable, but not at the function's immediate epilogue. "
                    "Likely a central-drain pattern (shared cleanup section "
                    "in the middle of the function) OR a split exit "
                    "(multiple epilogue paths, each balanced)."
                )

        return FunctionAnalysis(
            start=start,
            end=end,
            prologue_range=prologue_range,
            prologue_saved=saved,
            prologue_stack=stack_alloc,
            prologue_restored=restored,
            prologue_restored_extras=restored_extras,
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
            green_flags=green_flags,
            flag_tooltips=flag_tooltips,
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

    def _scan_static_callers(self, pool_data_addrs: Optional[set] = None) -> dict:
        """Scan THIS binary's bytes for call references to each address.

        Two patterns:
          1. Direct PC-relative branches (`bsr disp`, `bra disp`): top
             nibble 0xA / 0xB, 12-bit signed disp.
          2. Pool-loaded function pointers: `mov.l @(disp,PC),Rn` reads
             a 4-byte pool word; if the word's value lands in vram range
             AND is 2-byte aligned, count it as a function-pointer ref.

        Skips opcode decode on any address in `pool_data_addrs` — pool
        bytes that bit-align as bsr/bra opcodes would otherwise produce
        phantom callers.  Called twice during model init:
          - Phase A: skip set from `_binary_pool_targets` only.  Pass E
            consumes this to gate its orphan-pool safeguard.
          - Phase B: skip set enriched with Pass E's POOL2/POOL4
            classifications.  This is the value consumers see.

        Returns {addr: count}.
        """
        import struct
        binary = self.binary
        vram = self.vram
        end = self.end_addr

        if pool_data_addrs is None:
            # Default: derive from _binary_pool_targets (Phase A semantics).
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

    def _pool_data_addrs_from_byte_kind(self) -> set:
        """Build a pool-byte skip set from `byte_kind` (POOL2/POOL4).
        Includes interior bytes of multi-byte pool words (byte_kind only
        records the start address).  Used by Phase-B static_callers scan
        to skip phantom opcodes inside Pass-E-classified pool regions.
        """
        pool_data_addrs: set = set()
        for addr, kind in self.byte_kind.items():
            if kind is ByteKind.POOL4:
                pool_data_addrs.update((addr, addr + 2))
            elif kind is ByteKind.POOL2:
                pool_data_addrs.add(addr)
        return pool_data_addrs

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
        case body addresses.

        Pattern (within ~8 instructions before the jmp):
            mov.l @(disp,PC), rN     ; rN = *pool — the table start addr
            ...                       ; (shll2 / add / etc.)
            mov.l @rN, rN             ; rN = *rN  — case body at table[index]
            jmp @rN                   ; transfer

        Also populates two reverse maps stored on `self`:
          - self.switch_clusters:    dispatcher_pc -> sorted unique targets
          - self.switch_dispatcher_of: target_addr -> [(dispatcher_pc, idx)]

        These let analyze_function recognize "this candidate is a case
        body of a known switch dispatcher" and auto-absorb the contiguous
        sibling case bodies from the same dispatch table.
        """
        binary = self.binary
        vram = self.vram
        binary_end = self.end_addr

        targets: set = set()
        self.switch_clusters = {}
        self.switch_dispatcher_of = {}
        pool_priors = self.pool_priors_dict()
        for jmp_pc in range(vram, binary_end, 2):
            # mov.l + jmp @rN idiom
            tgts = self._detect_mov_l_jmp_switch_targets(jmp_pc)
            if not tgts:
                # mova + braf rN idiom (alt form)
                tgts = _detect_braf_switch_targets(
                    binary, vram, jmp_pc, pool_priors,
                )
            if not tgts:
                continue
            # Preserve table-order targets in switch_clusters; downstream
            # consumers (renderer, partner suggestions) want the full
            # ordered list, not just unique values.
            self.switch_clusters[jmp_pc] = list(tgts)
            for idx, t in enumerate(tgts):
                targets.add(t)
                self.switch_dispatcher_of.setdefault(t, []).append((jmp_pc, idx))
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
            # Declared alt entry points aren't midpoints — they're
            # entries the user has already accepted as part of this
            # function.  Suppress here so the banner doesn't flag them
            # as "reference disagrees" suggestions.
            if a in self.alt_entries and self.alt_entry_main.get(a) == start:
                continue
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
                 frontier_simulation: bool = False,
                 pending_entries: Optional[dict] = None,
                 pending_partners: Optional[list] = None,
                 ):
        self.model = model
        self.yaml_cfg = yaml_cfg
        self.ai_override = dict(ai_override or {})
        # Frontier simulation: pretend no future stamps exist when capping
        # the walker.  Lets us audit "what would the analyzer do if THIS
        # were the next unswept function?" — the cap would otherwise leak
        # information from stamps that wouldn't exist yet at frontier
        # time, making the walker look smarter than it actually is.
        self.frontier_simulation = bool(frontier_simulation)
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
                partners=[_coerce_addr(p) for p in (s.get("partners") or [])],
                entries=[_coerce_addr(e) for e in (s.get("entries") or [])],
            )
            for s in (yaml_cfg.get("subsegments") or [])
            if s.get("type") == "code"
        ]
        self.verified.sort(key=lambda s: s.start)

        # Data subsegs — declared regions of literal data (LUTs, jump
        # tables, padding) that don't undergo CFG analysis.  Forward-
        # sweep treats them as covered (skips past their end like it
        # does for code stamps); the listing renders them in the prev
        # section with raw row emission rather than function decode.
        # Kept separate from `self.verified` so existing code paths
        # (alt_entry validation, partners, callers, etc.) keep their
        # code-only invariants without per-call type checks.
        self.verified_data = [
            VerifiedSubseg(
                start=s["start"],
                end=s["end"],
                type=s.get("type", "data"),
                file=s.get("file", ""),
                partners=[],
                entries=[],
            )
            for s in (yaml_cfg.get("subsegments") or [])
            if s.get("type") == "data"
        ]
        self.verified_data.sort(key=lambda s: s.start)
        # Unified view of both kinds, sorted by start.  Used anywhere
        # we ask a "coverage" question — is this addr inside any
        # declared subseg? what's the next/previous declared boundary?
        # — without caring which type.  Code-only invariants (partner
        # logic, alt entries, callers) keep using `self.verified`.
        self.all_subsegs = sorted(
            list(self.verified) + list(self.verified_data),
            key=lambda s: s.start,
        )

        # Validate `entries:` lists and derive alt_entry_main.  Each alt
        # entry must sit strictly inside its owning subseg's (start, end]
        # (alt != start, but alt == end is fine — single-instruction
        # entry just before the rts).  An alt can't be claimed by two
        # subsegs.  Bad entries get logged + dropped; valid ones build
        # the alt_entry_main map the BinaryModel consults.
        self.alt_entry_main: dict = {}
        for sub in self.verified:
            kept = []
            for e in sub.entries:
                if not (sub.start < e <= sub.end):
                    continue
                if e in self.alt_entry_main:
                    continue
                # Reject if inside any OTHER verified subseg (code OR
                # data — an alt entry pointing into a declared data
                # range is always a mis-stamp).
                if any(other.start <= e <= other.end
                       for other in self.all_subsegs if other is not sub):
                    continue
                kept.append(e)
                self.alt_entry_main[e] = sub.start
            sub.entries = kept
        # Pending alt entries (queued via /queue-entry, not yet written
        # to yaml).  Stored as `{main_hex: [addr, ...]}` keyed by the
        # function's main start — explicit binding survives candidate-
        # identity changes.  Attach each (main, entry) to alt_entry_main
        # so the analyzer treats them as declared entries during this
        # poll: the walker seeds them, midpoints suppress them,
        # function_entry_confidence scores them HIGH.  Lets the human
        # audit the multi-entry shape before stamping.
        self.pending_entries: dict = dict(pending_entries or {})
        for main_hex, entries in self.pending_entries.items():
            try:
                main = _coerce_addr(main_hex)
            except (ValueError, TypeError):
                continue
            for e in entries or []:
                if e <= main:
                    continue
                if e in self.alt_entry_main:
                    continue
                # Reject if inside any verified subseg (code OR data)
                # that ISN'T the pending main itself.  The main may or
                # may not be in `self.verified` — unstamped candidates
                # aren't.  A pending entry inside a declared data
                # range is always a mis-stamp.
                if any(s.start <= e <= s.end and s.start != main for s in self.all_subsegs):
                    continue
                self.alt_entry_main[e] = main

        # Push the derived view into the BinaryModel so its analyze_function
        # / confidence methods see the current alt entries.  Cheap to
        # call per /state poll: just a dict + set swap, plus cache
        # invalidation if the dict changed.
        self.model.set_alt_entries(self.alt_entry_main)

        # Sibling-pool cache: per-subseg reachable sets are expensive to
        # build (each requires a full analyze_function), so cache and
        # reuse.  Keyed by subseg start; invalidated implicitly because
        # SweepState is rebuilt per /state poll.
        self._sibling_pool_cache: dict = {}

        # Verified-starts set for fast membership tests during listing
        # symbolization (indirect-target resolution renders "FUN_<addr>"
        # vs "0x<addr>" based on whether the resolved target is stamped).
        self._verified_starts = {s.start for s in self.verified}

        # Lazy caches for the per-listing hint maps.  Built on first
        # access (see properties).
        self._outstanding_case_of_cache: Optional[dict] = None
        self._call_sources_of_cache: Optional[dict] = None

        # Active analyze-mode block start addrs — used to flag "Called
        # from" entries that come from another block of the same
        # synthetic mega-function, so the UI can render them with a
        # different color + "(analyze block)" suffix.
        self._analyze_block_starts = {
            int(b["start"]) for b in (self.analyze_mode.get("blocks") or [])
        }
        # Filter `model.suspected_fn_entries` (prologue-pattern matches
        # binary-wide) down to the "interesting" residue: matches that
        # have NO existing function-entry signal AND aren't inside any
        # verified subseg.  These are addresses where the prologue
        # opcode `sts.l pr, @-r15` appears but our reference/caller/
        # switch-target detection didn't recognize them — strong
        # candidates for code that the reference mis-classified as
        # data.  Surfaced as a hint label in row emission.
        _known_fn_entries = set(self.model.reference_starts)
        _known_fn_entries.update(
            a for a, c in self.model.static_callers.items() if c > 0
        )
        _known_fn_entries.update(
            a for a, c in self.model.cross_module_callers.items() if c > 0
        )
        _known_fn_entries.update(self.model.switch_targets)
        # Hint filter: suppress prologue-pattern / pool4-pointer hints
        # whose addr falls inside ANY declared subseg — including data
        # subsegs.  Real data blobs (LUTs etc.) often contain byte
        # patterns that coincidentally match prologue opcodes; without
        # the data check the listing fills with bogus "Suspected
        # function entry" labels inside known literal data.
        _verified_ranges = [(s.start, s.end) for s in self.all_subsegs]
        self.suspected_fn_entry_hints: set = set()
        for a in self.model.suspected_fn_entries:
            if a in _known_fn_entries:
                continue
            if any(s <= a <= e for s, e in _verified_ranges):
                continue
            self.suspected_fn_entry_hints.add(a)
        # Pool4-pointer hints: same residue filter, different signal
        # source.  Surfaces leaf functions (no PR save) that are only
        # called via `mov.l (pool), rN; jsr @rN`.
        self.pool4_target_hints: set = set()
        for a in self.model.pool4_pointer_targets:
            if a in _known_fn_entries:
                continue
            if any(s <= a <= e for s, e in _verified_ranges):
                continue
            # Skip if also a prologue-pattern hit — the prologue label
            # is the more specific signal and we want only one label
            # per addr.
            if a in self.suspected_fn_entry_hints:
                continue
            self.pool4_target_hints.add(a)

        # Session-level pending partner addrs (queued via /queue-partner,
        # not yet committed to yaml).  `_caller_kind` treats them as
        # "partner" relationships when the caller-side is one of them
        # AND the target address falls anywhere inside the current
        # candidate's range (set by `listing()` only when invoked for
        # the live candidate — audit panes pass is_live_candidate=False
        # so the queue isn't mis-attributed to a focused stamp).
        # Range-based, not exact-start, because callers reach mid-
        # function addresses too (switch case bodies, merge points,
        # etc.).
        self.pending_partners = {int(p) for p in (pending_partners or [])}
        self._pending_partner_target_range: Optional[tuple] = None  # (start, end)
        # SweepState is rebuilt per /state poll in eval_server (see
        # _build_sweep), so _call_sources_of_cache and the pending-
        # partner state below are always fresh per request — never
        # reused across pending_partners mutations.

    def _caller_kind(self, caller_start: int, target_addr: int) -> str:
        """Classify a caller for the "Called from" label.

          - "analyze" — caller is one of the active analyze-mode block
            starts (we're exploring a multi-block synthetic function and
            this is another block of it)
          - "partner" — caller and target are paired via the yaml
            partners mechanism OR via a session-queued partnership.
            Four resolution paths, since either side might be the
            one currently being viewed (unstamped candidate):
              (a) target is stamped, caller is listed in target's partners
              (b) caller is stamped, target_addr appears verbatim in
                  caller's partners list
              (c) caller is stamped, target_addr falls inside a stamped
                  subseg whose start is in caller's partners list
              (d) caller is in `pending_partners` AND target falls inside
                  the current candidate's range — previews the partnership
                  before /verdict approve commits it.  The range is set
                  by listing() only when rendering the live candidate
                  (audit panes pass is_live_candidate=False).
          - "stamped" — anything else (regular cross-function call)
        """
        if caller_start in self._analyze_block_starts:
            return "analyze"
        target_sub = next(
            (s for s in self.verified if s.start <= target_addr <= s.end),
            None,
        )
        # (a) forward — caller declared partner of target subseg
        if target_sub is not None and caller_start in (target_sub.partners or []):
            return "partner"
        # (b) and (c) reverse — caller's partners reach the target
        caller_sub = next(
            (s for s in self.verified if s.start == caller_start), None,
        )
        if caller_sub is not None:
            partners = caller_sub.partners or []
            if target_addr in partners:
                return "partner"
            if target_sub is not None and target_sub.start in partners:
                return "partner"
        # (d) pending — caller is queued as partner of the current
        # candidate AND target lands at-or-after the candidate's start.
        # The lower bound excludes prev/intermediate-section labels
        # (those targets are in earlier functions, not this candidate's
        # territory).  There's intentionally NO upper bound so the tag
        # also fires on trailing-section labels (which extend past
        # candidate.end and still belong to the candidate's review
        # context — useful for spotting case-body landings just
        # outside the proposed boundary).
        # Self-recursion guard: skip when the caller IS the candidate
        # (user queued the function with itself).
        if (self._pending_partner_target_range is not None
                and caller_start in self.pending_partners):
            ts, _te = self._pending_partner_target_range
            if target_addr >= ts and caller_start != ts:
                return "partner"
        return "stamped"

    def check_suspected_fn_entries_inside(self, fa: FunctionAnalysis) -> list:
        """Return yellow-flag strings listing any suspected function
        entries (prologue-pattern or pool4-pointer) that fall inside
        the candidate's [start, end] range.  In a runaway candidate
        — say a 17KB over-extended stamp — the hints in the listing
        are easy to miss because the user has to scroll thousands of
        lines.  This surfaces them on the banner with their hex
        addresses so the user can navigate straight to them.

        One flag per hint type; both can fire on the same candidate.
        """
        flags = []
        prologue_in = sorted(
            a for a in self.suspected_fn_entry_hints
            if fa.start <= a <= fa.end and a != fa.start
        )
        pool4_in = sorted(
            a for a in self.pool4_target_hints
            if fa.start <= a <= fa.end and a != fa.start
        )
        if prologue_in:
            addrs = ", ".join(f"0x{a:08X}" for a in prologue_in[:8])
            extra = f" + {len(prologue_in) - 8} more" if len(prologue_in) > 8 else ""
            flags.append(
                f"prologue-pattern hits inside candidate ({len(prologue_in)}): {addrs}{extra}"
            )
        if pool4_in:
            addrs = ", ".join(f"0x{a:08X}" for a in pool4_in[:8])
            extra = f" + {len(pool4_in) - 8} more" if len(pool4_in) > 8 else ""
            flags.append(
                f"pool4-pointer hits inside candidate ({len(pool4_in)}): {addrs}{extra}"
            )
        return flags

    def check_trailing_zone_case_targets(self, fa: FunctionAnalysis,
                                          trailing_window: int = 200) -> list:
        """Scan the trailing window past `fa.end` for addresses that are
        known case targets of an already-stamped switch dispatcher.

        When the analyzer proposes a function boundary and the very next
        addresses are case bodies of an existing dispatcher, the
        boundary is almost certainly too short — case bodies for the
        same switch are physically contiguous and the candidate should
        absorb them.  Returns a list of yellow-flag strings (empty when
        no hint fires).
        """
        hits_by_disp: dict = {}
        for offset in range(1, trailing_window, 2):
            addr = fa.end + offset
            entries = self.outstanding_case_of.get(addr)
            if not entries:
                continue
            for disp_start, case_idx in entries:
                hits_by_disp.setdefault(disp_start, []).append((addr, case_idx))

        flags = []
        for disp_start, hits in hits_by_disp.items():
            addr_str = ", ".join(
                sorted({f"0x{a:08X}" for (a, _) in hits})
            )
            flags.append(
                f"boundary likely short — case targets of FUN_{disp_start:08X} "
                f"in trailing zone ({addr_str}); consider extending end to "
                f"cover all cases"
            )
        return flags

    def apply_partner_awareness(self, fa: FunctionAnalysis) -> FunctionAnalysis:
        """When `fa`'s yaml subseg declares partners, compute the
        UNION of pushes vs pops across the function and all stamped
        partners — using prologue_saved + prologue_restored +
        prologue_restored_extras (the latter catches pops that unwind
        the caller's frame, which the strict epilogue walker
        otherwise ignores).

        If the combined frame balances (pushes set == pops set):
          - imbalance yellow flags get suppressed
          - verdict bumps from MEDIUM to HIGH (when MEDIUM was solely
            driven by the imbalance)
          - fa.partner_balanced becomes True (frontend renders a green
            "✓ balanced via partner" chip)

        Partners not yet stamped are silently skipped.  Returns a
        fresh FunctionAnalysis (via _dc_replace) when changes apply,
        else returns `fa` unchanged.
        """
        own = next((s for s in self.verified if s.start == fa.start), None)
        if own is None or not own.partners:
            return fa

        combined_pushes = set(fa.prologue_saved or [])
        combined_pops = set(fa.prologue_restored or []) | set(fa.prologue_restored_extras or [])
        any_unstamped = False
        for p in own.partners:
            partner_sub = next((s for s in self.verified if s.start == p), None)
            if partner_sub is None:
                any_unstamped = True
                continue
            try:
                partner_fa = self.model.analyze_function(p, hint_end=partner_sub.end)
            except Exception:
                continue
            combined_pushes |= set(partner_fa.prologue_saved or [])
            combined_pops |= (
                set(partner_fa.prologue_restored or [])
                | set(partner_fa.prologue_restored_extras or [])
            )

        if any_unstamped or combined_pushes != combined_pops:
            return fa

        # Combined frame is balanced — suppress imbalance flags, bump
        # verdict, mark as partner-balanced for banner display.
        IMBALANCE_MARKERS = (
            "prologue/epilogue register order mismatch",
            "critical: prologue pushed",
        )
        new_flags = [
            f for f in fa.yellow_flags
            if not any(m in f for m in IMBALANCE_MARKERS)
        ]
        new_verdict = fa.verdict
        if fa.verdict == Verdict.MEDIUM and not new_flags:
            new_verdict = Verdict.HIGH
        return _dc_replace(
            fa,
            yellow_flags=new_flags,
            verdict=new_verdict,
            partner_balanced=True,
        )

    def _cap_from_next_stamp(self, start: int) -> Optional[int]:
        """Sweep / override hint_end cap.  Returns the byte BEFORE the
        next verified subseg's start (when one exists past `start`),
        else None (= binary_max — walker walks until natural CFG
        termination).

        Replaces the old TU-end cap.  Bounds derived from the user's
        own approvals rather than from invented translation-unit
        boundaries — more authentic, and tracks the user's progress
        as they stamp more functions.

        When `frontier_simulation` is on, returns None unconditionally
        — simulates being at the unswept frontier where no future
        stamps exist to constrain the walk.
        """
        if self.frontier_simulation:
            return None
        # Both code AND data subsegs cap the walker — a declared data
        # region is just as much "already classified" as a stamped
        # function for the purpose of "don't walk past here."
        next_start = min(
            (s.start for s in self.verified if s.start > start),
            default=None,
        )
        data_next = min(
            (s.start for s in self.verified_data if s.start > start),
            default=None,
        )
        if data_next is not None and (next_start is None or data_next < next_start):
            next_start = data_next
        return None if next_start is None else next_start - 1

    def suggested_partners(self, fa: FunctionAnalysis) -> list:
        """Suggest partner addresses for `fa` based on stack imbalance +
        transfer signals.

        Suppressed entirely in frontier_simulation mode — partner
        suggestions are computed over whatever range the walker
        produced, which in frontier mode is the wild-walk range
        rather than the real function.  Surfacing partners off a
        deliberately-over-absorbed range produces misleading hints
        (e.g. matching the OVERREACH region's pops against unrelated
        callers).  Frontier is an audit lens; keep it noise-free.

        Returns list of dicts: [{addr, addr_hex, reason}, ...].  Two
        analysis paths combine into the suggestion list:

          1. SAVES WITHOUT RESTORES.  Prologue saved callee-saved regs
             that the local epilogue never pops, AND the function has
             unconditional external exits (bra/jmp/braf out-of-range).
             Pattern: switch dispatchers, tail-call wrappers — control
             leaves the function before the regs are restored, so the
             jmp targets must be the partner block(s).  Targets are
             clustered into contiguous regions; one suggestion per
             cluster (the lowest addr in each cluster).

          2. RESTORES WITHOUT SAVES.  Local epilogue pops regs that the
             prologue never pushed.  Pattern: switch case bodies that
             share a caller's stack frame.  Suggested partners come
             from `call_sources_of` (who transfers control to this
             function's start).

        Empty list means the function is balanced — no partner needed.
        """
        if self.frontier_simulation:
            return []
        saved = set(fa.prologue_saved or [])
        # Include extras so case-body-style functions (which pop the
        # caller's frame regs via epilogue but never push them) get
        # their imbalance detected.  Strict-walker restored only
        # contains pops matching the prologue.
        restored = set(fa.prologue_restored or []) | set(fa.prologue_restored_extras or [])
        saves_without_restores = saved - restored
        restores_without_saves = restored - saved

        suggestions: list = []
        seen_addrs: set = set()

        def _add(addr: int, reason: str):
            if addr in seen_addrs or addr == fa.start:
                return
            seen_addrs.add(addr)
            suggestions.append({
                "addr": addr,
                "addr_hex": f"{addr:08X}",
                "reason": reason,
            })

        # Path 1: collect unconditional external exit destinations.
        # Only count uncond-exit instructions (bra/jmp/braf) — jsr/bsrf
        # are calls that return, so their targets aren't partners.
        if saves_without_restores:
            binary = self.model.binary
            vram = self.model.vram
            pool_priors = self.model.pool_priors_dict()
            exit_targets: set = set()
            for b in (fa.branches or []):
                if b.target is None or b.internal:
                    continue
                if b.mnem in ("bra", "jmp", "braf"):
                    exit_targets.add(b.target)
            for src, tgt in (fa.indirect_resolutions or {}).items():
                if fa.start <= tgt <= fa.end:
                    continue
                op = _read_opcode(binary, vram, src)
                if op is None:
                    continue
                m, _ = _decode_sh2(op, src)
                if m is None:
                    continue
                head = m.split()[0]
                if head not in ("jmp", "braf"):
                    continue   # jsr/bsrf — call returns, not an exit
                exit_targets.add(tgt)
            # Switch-dispatch case targets (full table, no range filter).
            # The walker records only in-range targets in fa.branches;
            # we need the out-of-range ones too — those are precisely
            # the partner block(s) we're trying to find.  Look up the
            # full table from the precomputed switch_clusters map.
            for ind_src in (fa.indirect_calls or []):
                for t in self.model.switch_clusters.get(ind_src, []):
                    if not (fa.start <= t <= fa.end):
                        exit_targets.add(t)
            if exit_targets:
                sorted_tgts = sorted(exit_targets)
                clusters = [[sorted_tgts[0]]]
                for t in sorted_tgts[1:]:
                    if t - clusters[-1][-1] <= 256:
                        clusters[-1].append(t)
                    else:
                        clusters.append([t])
                missing_str = ", ".join(sorted(saves_without_restores))
                for cluster in clusters:
                    _add(
                        cluster[0],
                        f"unconditional exit target — restores [{missing_str}] saved but not popped locally",
                    )

        # Path 2: who transfers control here?
        if restores_without_saves:
            callers = self.call_sources_of.get(fa.start, {})
            missing_str = ", ".join(sorted(restores_without_saves))
            for caller_start in sorted(callers.keys()):
                _add(
                    caller_start,
                    f"transfers control here — pushed [{missing_str}] that this function pops",
                )

        return suggestions

    def _verified_for_hints(self) -> list:
        """Verified subsegs filtered for hint computation.

        Drops two kinds of subseg as redundant:

        1. Subsegs OVERLAPPED by an analyze_mode block.  The user is
           hypothesizing a different (usually wider) function boundary
           that contradicts the existing stamp.

        2. Subsegs ABSORBED by another verified subseg's analyzed
           reachable set.  When the analyzer walks subseg Y and the
           walk reaches subseg X's start (e.g., via switch absorption
           or fall-through), X is structurally part of Y in the
           current analyzer's view.  Keeping X would double-count its
           calls/cases under both X and Y; suppressing X attributes
           everything to the absorbing function.
        """
        blocks = self.analyze_mode.get("blocks") or []
        block_ranges = [(int(b["start"]), int(b["end"])) for b in blocks]

        # Step 1: drop subsegs overlapping any analyze_mode block.
        keep = []
        for sub in self.verified:
            overlapped = any(
                br_start <= sub.end and br_end >= sub.start
                for br_start, br_end in block_ranges
            )
            if not overlapped:
                keep.append(sub)

        # Step 2: drop subsegs absorbed by another in `keep`.  A subseg
        # X is absorbed by Y when X.start ∈ Y.reachable AND X != Y.
        # Single pass: walk each Y once, mark any in-keep subseg whose
        # start falls in Y.reachable.
        keep_starts = {s.start for s in keep}
        absorbed_starts: set = set()
        for y in keep:
            try:
                y_reachable = self.model.analyze_function(
                    y.start, hint_end=y.end,
                ).reachable
            except Exception:
                continue
            for x_start in y_reachable & keep_starts:
                if x_start != y.start:
                    absorbed_starts.add(x_start)

        return [x for x in keep if x.start not in absorbed_starts]

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

        # Union of real verified subsegs (filtered by analyze_mode) and
        # analyze-mode "virtual" blocks.  Read switch dispatchers from
        # BinaryModel.switch_clusters (precomputed once at construction);
        # no per-poll re-scan of every PC.
        ranges = [(s.start, s.end) for s in self._verified_for_hints()]
        for b in (self.analyze_mode.get("blocks") or []):
            ranges.append((int(b["start"]), int(b["end"])))

        result: dict = {}
        for dispatcher_pc, tgts in self.model.switch_clusters.items():
            # Find the containing range (subseg or analyze_mode block).
            r_start = next(
                (rs for rs, re in ranges if rs <= dispatcher_pc <= re),
                None,
            )
            if r_start is None:
                continue
            r_end = next(re for rs, re in ranges if rs == r_start)
            for idx, t in enumerate(tgts):
                if r_start <= t <= r_end:
                    continue  # target lives inside the dispatcher itself
                result.setdefault(t, []).append((r_start, idx))

        self._outstanding_case_of_cache = result
        return result

    @property
    def call_sources_of(self) -> dict:
        """For every stamped (or analyze_mode block) function, collect
        every address it transfers control to that lies OUTSIDE its own
        range.  Covers all flavors of call/transfer:

          - direct bra / bsr / bsrf with statically known target
          - jsr @rN / jmp @rN / braf rN with target resolved via the
            preceding mov.l @(disp,PC), rN load (or mova pattern)

        Returns dict: target_addr -> dict {caller_fn_start: count}.

        Used by the listing renderer to surface "Called from FUN_xxxxxxxx
        (×N):" hints on any address that's a known transfer target from
        one of our stamped functions.  Two concrete benefits:

          1. Mid-function merge points (e.g. an address 8 bytes into
             another function, where multiple call sites converge) are
             surfaced as navigable anchors.
          2. Transfers to addresses that AREN'T inside any stamped
             function expose missing stamps — the hint appears in
             unstamped territory and points at the function we forgot.
        """
        if hasattr(self, "_call_sources_of_cache") and self._call_sources_of_cache is not None:
            return self._call_sources_of_cache

        result: dict = {}

        # Helper: walk one function's analysis, harvest external targets
        # into `result` keyed by target -> {fn_start: count}.  Each call
        # site (src_pc) is counted at most once: a single jmp@rN can be
        # logged BOTH in fa.branches (added by the walker's single-target
        # resolution) AND in fa.indirect_resolutions (added by the
        # post-walk pass), and we don't want to double-count.
        def _harvest(fn_start: int, fn_end: int):
            try:
                fa = self.model.analyze_function(fn_start, hint_end=fn_end)
            except Exception:
                return
            seen_srcs: set = set()
            for b in fa.branches:
                if b.target is None or b.internal:
                    continue
                if b.src in seen_srcs:
                    continue
                seen_srcs.add(b.src)
                tgt = b.target
                result.setdefault(tgt, {}).setdefault(fn_start, 0)
                result[tgt][fn_start] += 1
            for src_pc, tgt in fa.indirect_resolutions.items():
                if src_pc in seen_srcs:
                    continue
                if fa.start <= tgt <= fa.end:
                    continue
                seen_srcs.add(src_pc)
                result.setdefault(tgt, {}).setdefault(fn_start, 0)
                result[tgt][fn_start] += 1
            # Switch case targets — the walker only records in-range
            # ones in fa.branches.  Out-of-range case targets are the
            # interesting ones for cross-function call attribution
            # (e.g., a dispatcher's switch table points at case bodies
            # in another TU).  Look up the precomputed clusters.
            for ind_src in (fa.indirect_calls or []):
                for t in set(self.model.switch_clusters.get(ind_src, [])):
                    if fa.start <= t <= fa.end:
                        continue
                    result.setdefault(t, {}).setdefault(fn_start, 0)
                    result[t][fn_start] += 1

        for sub in self._verified_for_hints():
            _harvest(sub.start, sub.end)
        for b in (self.analyze_mode.get("blocks") or []):
            _harvest(int(b["start"]), int(b["end"]))
        # Pending partners — harvest each queued partner's branches as
        # if it were stamped, so "Called from FUN_X (partner)" hint
        # labels can preview before /verdict approve materializes the
        # partnership.  Mirrors the analyze-mode block harvest above.
        # Range resolution: stamped subseg's end if verified, else CFG
        # walker via model.analyze_function (covers the common case
        # where the queued partner isn't stamped yet — exactly when
        # the preview is most useful).
        binary_end = self.model.vram + len(self.model.binary)
        for p in self.pending_partners:
            # Guard: 2-byte aligned + within binary range.  CFG walker
            # called below trusts `p` is a real function start, so a
            # bogus addr (mis-click, stale yaml, misaligned hex) could
            # produce a runaway walk that harvests garbage branches.
            if (p & 1) or not (self.model.vram <= p < binary_end):
                continue
            # Skip if `p` falls strictly INSIDE another verified
            # subseg (code OR data) — likely a mis-click on a mid-
            # function or mid-data address; the containing subseg is
            # harvested separately for code, and partners aren't
            # meaningful for data anyway.  Allow `p == s.start`
            # (the common back-ref case) since we use the subseg's
            # exact end below.
            if any(s.start < p <= s.end for s in self.all_subsegs):
                continue
            end = next(
                (s.end for s in self.verified if s.start == p), None,
            )
            if end is None:
                try:
                    end = self.model.analyze_function(p).end
                except Exception:
                    continue
            _harvest(p, end)

        self._call_sources_of_cache = result
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
        subsegs (code OR data) PLUS the pending gap between the latest
        verified subseg and the currently-proposed candidate (if any).

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
        # Walk the unified code + data subseg list — both types count
        # as 'covered territory'.  A stamped data range right between
        # two code stamps closes that gap; missing it here would
        # falsely fire the red gap banner.
        all_subsegs = sorted(
            list(self.verified) + list(self.verified_data),
            key=lambda s: s.start,
        )
        gaps = []
        prev = None
        for s in all_subsegs:
            if prev is not None and s.start > prev.end + 1:
                gap_start = prev.end + 1
                gap_end = s.start - 1
                gaps.append(Gap(
                    start=gap_start,
                    end=gap_end,
                    size=gap_end - gap_start + 1,
                    preceding_start=prev.start,
                    preceding_name=(
                        f"DATA_{prev.start:08X}" if prev.type == "data"
                        else f"FUN_{prev.start:08X}"
                    ),
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
                    preceding_name=(
                        f"DATA_{prev.start:08X}" if prev.type == "data"
                        else f"FUN_{prev.start:08X}"
                    ),
                    pending=True,
                ))
        return gaps

    def progress(self) -> Progress:
        """Sum verified subseg bytes (code + data) vs total binary size.
        Data ranges count toward 'done' just as much as code stamps —
        a declared data block is no longer unclassified territory.

        Mirrors eval_server._compute_progress.
        """
        code_bytes = sum(s.end - s.start + 1 for s in self.verified)
        data_bytes = sum(s.end - s.start + 1 for s in self.verified_data)
        verified_bytes = code_bytes + data_bytes
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

        # Unified view of code + data subsegs (sorted by start) — both
        # count as "covered territory" for the forward sweep.  Data
        # subsegs serve as iteration anchors too: the sweep needs to
        # scan past a declared data range to find the next function.
        all_subsegs = sorted(
            self.verified + self.verified_data, key=lambda s: s.start,
        )

        def _covered_by_existing(addr):
            """True if addr falls inside any verified (code OR data)
            subseg's [start, end] range — not just at a start.
            Catches the case where forward sweep latches on a prologue
            inside a function that was ai_overridden to start a few
            bytes earlier, AND prevents the sweep from re-proposing
            addresses inside a declared data region."""
            for s in all_subsegs:
                if s.start <= addr <= s.end:
                    return True
            return False

        # Head-of-binary case: if the binary's first address isn't covered
        # by any declared subseg, look for a function there first.  Handles
        # both the bootstrap case (no anchors yet) and re-review of the
        # very first function after an /unstamp at the binary head.
        if not all_subsegs or all_subsegs[0].start > vram:
            next_start = _scan_for_next_prologue(
                binary, vram, vram, binary_end,
                reference_starts=reference_starts,
                static_callers=static_callers,
                cross_module_callers=cross_module_callers,
            )
            if next_start is not None and not _covered_by_existing(next_start):
                fa = model.analyze_function(
                    next_start, hint_end=self._cap_from_next_stamp(next_start),
                )
                return NextCandidate(previous=None, function=fa)

        for prev in all_subsegs:
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
            # Pick the ACTUAL immediately-preceding subseg (code or data),
            # not the iteration's `prev`.  The scan can walk past an
            # unsignaled-but-verified subseg (e.g. a 4-byte alternate-
            # entry stub with no callers + no reference FUN_<addr>:
            # declaration) and land on a candidate further out.  In
            # that case the `prev` we're iterating from is stale — the
            # real previous-verified-subseg is the one that hugs next_start.
            actual_prev = max(
                (s for s in all_subsegs if s.end < next_start),
                key=lambda s: s.end,
                default=prev,
            )
            fa = model.analyze_function(
                next_start, hint_end=self._cap_from_next_stamp(next_start),
            )
            return NextCandidate(previous=actual_prev, function=fa)

        return None

    # ------------------------------------------------------------------
    # Phase 6 — listing model
    # ------------------------------------------------------------------

    def listing(self,
                candidate: FunctionAnalysis,
                previous: Optional[VerifiedSubseg],
                attn: Optional[list] = None,
                is_live_candidate: bool = True,
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
        # `_caller_kind` consults this range to recognize queued
        # partners whose calls land anywhere inside the candidate
        # (path "(d)" in its docstring).  Only set for the LIVE
        # candidate — audit panes pass is_live_candidate=False since
        # `pending_partners` is global session state but conceptually
        # tied to whatever the next-approve target is, not whichever
        # stamp the audit walk happens to be focused on.
        self._pending_partner_target_range = (
            (candidate.start, candidate.end) if is_live_candidate else None
        )

        # Resolve the candidate's suggested-partner ranges once, so the
        # walker-stop tooltip can disclose when a flagged tail-call target
        # actually lies inside a partner the user is being suggested to
        # absorb.  Surfaces the tension between "HIGH tail call" and
        # "absorb as partner" rather than picking one signal silently.
        partner_ranges = []
        for p in self.suggested_partners(candidate):
            try:
                p_fa = self.model.analyze_function(p["addr"])
                partner_ranges.append((p_fa.start, p_fa.end, p["addr_hex"]))
            except Exception:
                pass

        rows = []
        row_id = [0]  # mutable counter so _emit_* can bump it

        def next_id():
            i = row_id[0]
            row_id[0] += 1
            return i

        # ----- 1. Previous section (if a prev subseg is provided) -----
        if previous is not None:
            size = previous.end - previous.start + 1
            if previous.type == "data":
                # Data subsegs render as raw byte rows — no CFG walk,
                # no prologue/epilogue/reachability decoration.  The
                # bytes are declared literal data; running the
                # analyzer on them would produce nonsense decode.
                self._emit_section_header(
                    rows, next_id, Section.PREV,
                    f"VERIFIED DATA  "
                    f"0x{previous.start:08X} → 0x{previous.end:08X}  ({size} bytes)",
                    anchor_addr=previous.start,
                )
                self._emit_raw_rows(rows, next_id, previous.start, previous.end, Section.PREV)
            else:
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

                self._emit_section_header(
                    rows, next_id, Section.PREV,
                    f"VERIFIED  FUN_{previous.start:08X}  "
                    f"0x{previous.start:08X} → 0x{previous.end:08X}  ({size} bytes)",
                    anchor_addr=previous.start,
                )
                self._emit_function_rows(rows, next_id, prev_fa, Section.PREV, attn_set, candidate, partner_ranges)

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
        # Extend the candidate's reachable set + branch metadata with
        # what a CFG walk from queued-partner call targets reaches /
        # collects.  Without this, code reached only via a partner-side
        # dispatch shows up as `unreach` AND its bras lose their branch
        # metadata (no partner-leap arcs) — distracting noise when the
        # user has explicitly queued the partnership and the
        # relationship is exactly what reaches the code.
        # Synthetic data candidates (audit mode focused on a data
        # subseg) skip the CFG walk entirely — they're declared
        # literal bytes, not code.  Header + raw rows only.
        size = candidate.end - candidate.start + 1
        if candidate.verdict == Verdict.DATA:
            self._emit_section_header(
                rows, next_id, Section.CURRENT,
                f"DATA  0x{candidate.start:08X} → 0x{candidate.end:08X}  ({size} bytes)",
                anchor_addr=candidate.start,
            )
            self._emit_raw_rows(rows, next_id, candidate.start, candidate.end, Section.CURRENT)
        else:
            extra_reach, extra_branches = self._partner_extended_walk(candidate)
            extended_reachable = set(candidate.reachable) | extra_reach if extra_reach else candidate.reachable
            self._emit_section_header(
                rows, next_id, Section.CURRENT,
                f"PROPOSED  FUN_{candidate.start:08X}  "
                f"0x{candidate.start:08X} → 0x{candidate.end:08X}  ({size} bytes)  "
                f"verdict: {candidate.verdict.value}",
                anchor_addr=candidate.start,
            )
            self._emit_function_rows(
                rows, next_id, candidate, Section.CURRENT, attn_set,
                candidate, partner_ranges,
                reachable_set=extended_reachable,
                extra_branches=extra_branches,
            )

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

    def _partner_extended_walk(self, candidate: FunctionAnalysis):
        """Return (reachable, branches) augmenting `candidate.reachable`
        and `candidate.branches` with what a CFG walk reaches/collects
        from queued-partner call targets that land inside the candidate.

        Without this, switch case bodies and direct-call landing pads
        reached only via a queued partner's outgoing flow show up as
        `unreach` rows AND lose their branch metadata (no partner-leap
        arcs on their bras) — the local walker seeded only from
        candidate.start never visited them.  Treating queued-partner
        targets as additional walker seeds gives the same visual
        effect as if the user had pre-declared them as alt entries.

        Single _control_flow_walk pass with all extra seeds, so
        transitive reach (target → its internal flow → next exit) is
        included naturally.  Returns (empty_set, empty_list) when
        there are no in-range partner targets so the caller can skip
        the union.
        """
        extra_seeds: list = []
        for p in self.pending_partners:
            try:
                p_fa = self.model.analyze_function(p)
            except Exception:
                continue
            for b in p_fa.branches:
                if b.target is not None and not b.internal:
                    if candidate.start <= b.target <= candidate.end:
                        extra_seeds.append(b.target)
            # Walk switch_clusters by ADDRESS RANGE, not via
            # p_fa.indirect_calls — the latter only contains dispatchers
            # the local walker actually reached from p.start, which
            # excludes dispatchers reached only via alt entries (common
            # on unstamped partners where no alt entries are declared
            # yet).  Range-based catches every dispatcher inside the
            # partner's body.
            for dispatcher_pc, tgts in self.model.switch_clusters.items():
                if not (p <= dispatcher_pc <= p_fa.end):
                    continue
                for t in tgts:
                    if candidate.start <= t <= candidate.end:
                        extra_seeds.append(t)
        if not extra_seeds:
            return set(), []
        extra_seeds = list(set(extra_seeds))
        extra_reach, _, extra_branches, _ = _control_flow_walk(
            self.model.binary, self.model.vram,
            start=extra_seeds[0],
            hard_limit_addr=candidate.end,
            pool_priors=self.model.pool_priors_dict(),
            extra_starts=extra_seeds[1:] if len(extra_seeds) > 1 else None,
        )
        return extra_reach, extra_branches

    def _emit_function_rows(self, rows, next_id, fa, section, attn_set, candidate, partner_ranges=None,
                             reachable_set=None, extra_branches=None):
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
        # Merge in any extra branches the caller collected (e.g. from
        # a partner-extended walk): keys not already in branches_at
        # get added so partner-walked bras get their branch metadata
        # and the client can draw partner-leap arcs on them.
        if extra_branches:
            for b in extra_branches:
                if b.src not in branches_at and b.target is not None:
                    branches_at[b.src] = b

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

            # ----- Suspected function entry (prologue-pattern hint)
            # When this address matches `sts.l pr, @-r15` and our
            # standard fn-entry signals didn't flag it, surface as a
            # candidate function start.  Useful for finding code
            # that the reference disasm mis-classified as data.
            if addr in self.suspected_fn_entry_hints:
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label="Suspected function entry (prologue pattern — verify):",
                ))
            elif addr in self.pool4_target_hints:
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label="Suspected function entry (pool4 pointer — could be data table):",
                ))

            # ----- Alt entry label
            # When this address is a declared alt entry of the function
            # being rendered, emit an ENTRY: marker so the multi-entry
            # structure is visible in the listing.  Marked with a
            # dedicated bool so CSS can style it distinctly.
            if (addr != fa.start
                    and self.model.alt_entry_main.get(addr) == fa.start):
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label=f"ENTRY FUN_{addr:08X}:",
                    is_alt_entry=True,
                ))

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

            # ----- Call-source hint label
            # When this address is a known transfer target FROM any of
            # our stamped functions (or analyze-mode blocks), surface
            # who calls/jumps here.  Useful for navigating into shared
            # merge points AND for detecting missing stamps when the
            # hint appears in unstamped territory.
            call_src = self.call_sources_of.get(addr)
            if call_src:
                parts = []
                callers_struct = []
                for caller_start, count in sorted(call_src.items()):
                    kind = self._caller_kind(caller_start, addr)
                    kind_tag = {"partner": ", partner", "analyze": ", analyze block"}.get(kind, "")
                    count_str = f"×{count}" if count > 1 else ""
                    inside = ", ".join(p for p in (count_str, kind_tag.lstrip(", ")) if p)
                    suffix = f" ({inside})" if inside else ""
                    parts.append(f"FUN_{caller_start:08X}{suffix}")
                    callers_struct.append({
                        "addr_hex": f"{caller_start:08X}",
                        "count": count,
                        "kind": kind,
                    })
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label="Called from " + ", ".join(parts) + ":",
                    callers=callers_struct,
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
                tent_mnem, _ = _decode_sh2(v, addr)
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
                    tentative_decode=tent_mnem,
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
                # Suppress the machine-generated .L_<addr>: label when
                # a "Called from" label was emitted just above for the
                # same addr — the call-source label conveys the same
                # branch-target info plus identifies the caller.
                if not self.call_sources_of.get(addr):
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
            # doesn't appear nested under live code.  `reachable_set`
            # overrides `fa.reachable` when caller wants extended reach
            # (e.g. current section seeds from queued-partner call
            # targets); defaults to fa.reachable for prev section.
            reach = reachable_set if reachable_set is not None else fa.reachable
            if addr not in reach:
                row.is_unreachable = True
                row.indent = 0
                row.tag = "unreach"

            # Branch / direction / arc metadata.
            b = branches_at.get(addr)
            if b is not None and b.target is not None:
                row.branch_target = b.target
                row.branch_direction = b.direction
                # branch_type reflects the mnemonic itself (cond vs
                # uncond) regardless of whether the target lands inside
                # or outside the function — external branches still
                # need the metadata so client-side overlays (e.g. the
                # green partner-pending leap arc) can recognize them.
                # branch_internal lets the client opt those externals
                # out of the normal arc renderer.
                row.branch_type = "cond" if b.mnem in {"bf", "bt", "bf/s", "bt/s"} else "uncond"
                row.branch_internal = b.internal
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

            # Switch-dispatch tag classification + all-targets text
            # annotation.  Looks up the precomputed switch_clusters map
            # on BinaryModel — populated once at construction by
            # _scan_all_switch_targets.  Row emission stays pure
            # lookup (no decoder calls per row).
            if head in ("jmp", "braf"):
                switch_targets = self.model.switch_clusters.get(addr, [])
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

            # Walker-stop confidence annotation.  For bra and resolved
            # single-target jmp/braf, the walker recorded stop_confidence
            # on the Branch.  Suffix the row tag with the rank so the
            # user can see the walker's tail-call decision inline, and
            # populate tag_tooltip with the reasoning for hover.
            if (b is not None and b.stop_confidence is not None
                    and head in ("bra", "jmp", "braf")):
                row.stop_confidence = b.stop_confidence
                rank_suffix = f" ({b.stop_confidence})"
                if rank_suffix not in row.tag:
                    row.tag = row.tag + rank_suffix
                tooltip_parts = [
                    f"walker stop confidence: {b.stop_confidence}",
                    f"target: 0x{b.target:08X}" if b.target is not None else "",
                ]
                if b.stop_reasons:
                    tooltip_parts.append("signals:")
                    for r in b.stop_reasons:
                        tooltip_parts.append(f"  - {r}")
                else:
                    tooltip_parts.append("signals: (none)")
                # Cross-reference with candidate's suggested partners.
                # When a HIGH tail-call target lands inside a suggested
                # partner range, the "external callers" count includes
                # callers that are actually inside the same logical
                # function — disclose this so the user can interpret the
                # rank with the partner context.
                if b.target is not None and partner_ranges:
                    for ps, pe, ph in partner_ranges:
                        if ps <= b.target <= pe:
                            tooltip_parts.append(
                                f"note: target is inside suggested partner "
                                f"FUN_{ph} (0x{ps:08X}→0x{pe:08X}) — "
                                f"some 'static callers' may be in-partner"
                            )
                            break
                # Target-prologue signal: if the next few instructions at
                # the branch target are stack pushes, the target looks
                # like a real function entry — the walker should probably
                # have stopped here regardless of static-caller count.
                if b.target is not None:
                    pushes = _count_leading_pushes(
                        self.model.binary, self.model.vram, b.target
                    )
                    if pushes >= 2:
                        tooltip_parts.append(
                            f"note: target opens with {pushes} stack pushes "
                            f"(mov.l rN, @-r15) — looks like a function prologue"
                        )
                # Frame-imbalance signal for the CURRENT function: if the
                # epilogue pops registers that the prologue never pushed,
                # this function is structurally unbalanced — strong hint
                # that the walker absorbed code from another function.
                extras = list(fa.prologue_restored_extras or [])
                if extras and not (fa.prologue_saved or []):
                    tooltip_parts.append(
                        f"note: this function pops [{', '.join(sorted(extras))}] "
                        f"that were never pushed at start — frame imbalance "
                        f"suggests the walker overran a real boundary"
                    )
                row.tag_tooltip = "\n".join(p for p in tooltip_parts if p)

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
        # Hint maps used in trailing zone only (where they catch wrong
        # boundary detection — "the analyzer ended the function here
        # but downstream addresses are known case targets / call
        # targets of our stamped functions").  Intermediate zones are
        # pool/padding by definition and unlikely to host these signals.
        emit_hints = section is Section.TRAILING
        case_hints = self.outstanding_case_of if emit_hints else {}
        call_hints = self.call_sources_of if emit_hints else {}

        while addr <= end:
            off = addr - vram
            if off + 1 >= len(binary):
                break

            # Suspected function entry (prologue-pattern hint).  Same
            # check as in _emit_function_rows — surfaces in trailing /
            # intermediate sections too so reference-mis-classified
            # functions sitting in pool zones get flagged.
            if addr in self.suspected_fn_entry_hints:
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label="Suspected function entry (prologue pattern — verify):",
                ))
            elif addr in self.pool4_target_hints:
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label="Suspected function entry (pool4 pointer — could be data table):",
                ))

            # Trailing-zone case-target hint.  When this address is a
            # known outstanding case target of a stamped dispatcher,
            # emit a label suggesting the analyzer's boundary may be
            # too short — the next instruction is actually a switch
            # case body of some already-stamped function.
            hint = case_hints.get(addr)
            if hint:
                by_disp: dict = {}
                for disp_start, case_idx in hint:
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

            # Trailing-zone call-source hint (same rationale).
            csrc = call_hints.get(addr)
            if csrc:
                parts = []
                callers_struct = []
                for caller_start, count in sorted(csrc.items()):
                    kind = self._caller_kind(caller_start, addr)
                    kind_tag = {"partner": ", partner", "analyze": ", analyze block"}.get(kind, "")
                    count_str = f"×{count}" if count > 1 else ""
                    inside = ", ".join(p for p in (count_str, kind_tag.lstrip(", ")) if p)
                    suffix = f" ({inside})" if inside else ""
                    parts.append(f"FUN_{caller_start:08X}{suffix}")
                    callers_struct.append({
                        "addr_hex": f"{caller_start:08X}",
                        "count": count,
                        "kind": kind,
                    })
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.LABEL,
                    section=section,
                    addr=addr,
                    label="Called from " + ", ".join(parts) + ":",
                    callers=callers_struct,
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
                tent_mnem, _ = _decode_sh2(value, addr)
                rows.append(ListingRow(
                    row_id=next_id(),
                    kind=RowKind.POOL2,
                    section=section,
                    addr=addr,
                    bytes_hex=" ".join(f"{binary[off+i]:02X}" for i in range(2)),
                    text=f".2byte 0x{value:04X}",
                    label=f".L_pool_{addr:08X}",
                    tentative_decode=tent_mnem,
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

        # AI may also pin the END explicitly (one-off boundary correction
        # the oracle's heuristics can't reach).  When pinned, use it as
        # hint_end so the ENTIRE analysis (CFG walk, epilogue search,
        # prologue/epilogue mirror, verdict) runs against the override
        # boundary — not with a post-hoc end mutation, which leaves the
        # verdict reflecting whichever epilogue analyzer's natural walk
        # happened to land on (often a different function's rts past
        # the real end).
        end_override_raw = ov.get("candidate_end")
        if end_override_raw is not None:
            hint_end = _coerce_addr(end_override_raw)
        else:
            hint_end = self._cap_from_next_stamp(start)

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
            # row_id=-1 marks BLANK as a placeholder; eval_server templates
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
