"""Raw-binary static-caller scan + comparison harness.

v2 of the static-caller analysis.  Doesn't trust reference's
`FUN_<addr>:` / `DAT_<addr>` annotations — scans the actual binary
bytes for caller patterns:

  1. Direct PC-relative branches:  `bsr disp` and `bra disp`
     The opcode encodes the displacement; target = PC + 4 + disp*2.
     Decodable from raw bytes.

  2. Pool-loaded function pointers: `mov.l @(disp,PC), Rn` followed
     (eventually) by `jsr @Rn`.  The mov.l instruction's target is a
     4-byte pool word.  If that word's value is a code address, it
     was almost certainly going to be jsr'd via Rn.  Decodable from
     raw bytes — never reads `.4byte DAT_<addr>` text.

This is a diagnostic harness — runs against a yaml + binary and
reports, per verified function start, what the raw scan finds vs
what the text-based static_callers loader finds, surfacing
discrepancies so we can spot:

  - False negatives in text scan (real callers reference's
    misclassification caused us to miss — the FUN_0602CC84 case)
  - False positives in raw scan (4-byte words that happen to equal
    a function address but aren't actually function pointers —
    e.g., math constants, interior offsets)
"""

import argparse
import re
import struct
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib.sh2_decode import decode_sh2


def scan_raw(binary, vram, code_ranges):
    """Walk every 2-byte-aligned address in declared code ranges.
    Returns (direct_callers, pool_callers): each {target_addr: [(src_addr, kind), ...]}.

    code_ranges is a list of (start, end) inclusive byte ranges that yaml
    says are code.  Restricting to declared code avoids decoding data
    bytes that happen to look like valid branch opcodes.
    """
    direct = {}   # target -> list of (src, "bsr" | "bra")
    pool   = {}   # target -> list of (mov_src, pool_addr)

    for rng_start, rng_end in code_ranges:
        addr = rng_start
        while addr <= rng_end - 1:
            off = addr - vram
            if off + 1 >= len(binary):
                break
            op = (binary[off] << 8) | binary[off + 1]
            hi = (op >> 12) & 0xF

            # Direct unconditional branches (12-bit signed disp, ±4KB range)
            if hi in (0xA, 0xB):
                disp = op & 0xFFF
                if disp > 0x7FF:
                    disp -= 0x1000
                target = addr + 4 + disp * 2
                kind = "bsr" if hi == 0xB else "bra"
                direct.setdefault(target, []).append((addr, kind))

            # mov.l @(disp,PC), Rn — read the 4-byte pool word
            elif hi == 0xD:
                disp = op & 0xFF
                pool_addr = (addr & 0xFFFFFFFC) + 4 + disp * 4
                poff = pool_addr - vram
                if 0 <= poff + 3 < len(binary):
                    v = struct.unpack(">I", binary[poff:poff + 4])[0]
                    # Only consider as a function-pointer candidate if the
                    # value sits in vram-mapped range and is 2-byte aligned
                    # (SH-2 instructions are 16-bit aligned, so a function
                    # entry can never be at an odd address).
                    if vram <= v <= vram + len(binary) - 1 and (v & 1) == 0:
                        pool.setdefault(v, []).append((addr, pool_addr))

            addr += 2

    return direct, pool


def scan_text(scan_dir, this_module_dir, reference_starts):
    """Replicates eval_server._load_static_callers — same regex, same
    same-vs-cross-module classification."""
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
    same, cross = {}, {}
    for s_file in scan_dir.glob("**/*.s"):
        try:
            in_same = s_file.resolve().is_relative_to(this_module_dir.resolve())
        except (AttributeError, ValueError):
            in_same = str(s_file.resolve()).startswith(str(this_module_dir.resolve()))
        bucket = same if in_same else cross
        for line in s_file.read_text(errors="replace").splitlines():
            for m in branch_re.finditer(line):
                a = int(m.group(1), 16); bucket[a] = bucket.get(a, 0) + 1
            for m in pool_re_fun.finditer(line):
                a = int(m.group(1), 16); bucket[a] = bucket.get(a, 0) + 1
            for m in pool_re_dat.finditer(line):
                a = int(m.group(1), 16)
                if a in reference_starts:
                    bucket[a] = bucket.get(a, 0) + 1
    return same, cross


def load_reference_starts(reference_dir):
    fun_re = re.compile(r"^FUN_([0-9A-Fa-f]{8}):\s*$")
    starts = set()
    for s_file in reference_dir.glob("*.s"):
        for line in s_file.read_text(errors="replace").splitlines():
            m = fun_re.match(line)
            if m:
                starts.add(int(m.group(1), 16))
    return starts


def main():
    p = argparse.ArgumentParser()
    p.add_argument("yaml_path")
    p.add_argument("--project-root", default=None,
                   help="Defaults to yaml's parent's parent (config/x.yaml ->../)")
    args = p.parse_args()

    yaml_path = Path(args.yaml_path).resolve()
    project_root = Path(args.project_root).resolve() if args.project_root \
        else yaml_path.parent.parent
    cfg = yaml.safe_load(yaml_path.read_text())
    opts = cfg.get("options") or {}
    vram = int(opts["vram"])
    binary = (project_root / opts["target_path"]).read_bytes()
    reference_dir = (project_root / opts["reference_dir"]).resolve()
    scan_dir = (project_root / (opts.get("reference_scan_dir") or opts["reference_dir"])).resolve()

    code_subsegs = [s for s in (cfg.get("subsegments") or []) if s.get("type") == "code"]
    verified_starts = {s["start"] for s in code_subsegs}
    # Scan the entire binary — limiting to verified subsegs misses callers
    # that live in unverified code (most of race is unverified at this
    # stage).  Direct branches and PC-relative pool loads are specific
    # enough opcodes that scanning data won't produce many false branches;
    # we accept some noise for completeness.
    code_ranges = [(vram, vram + len(binary) - 1)]

    print(f"binary: {opts['target_path']}  ({len(binary)} bytes, vram=0x{vram:08X})")
    print(f"verified code subsegs: {len(code_subsegs)}")
    print()

    reference_starts = load_reference_starts(reference_dir)
    print(f"reference_starts (FUN_<addr>: in {reference_dir.name}): {len(reference_starts)}")

    direct, pool = scan_raw(binary, vram, code_ranges)
    text_same, text_cross = scan_text(scan_dir, reference_dir, reference_starts)
    print(f"raw scan: {sum(len(v) for v in direct.values())} direct branches, "
          f"{sum(len(v) for v in pool.values())} pool-loaded refs")
    print()

    # ─── Per-verified-function comparison ───────────────────────────
    print("=" * 78)
    print("PER-FUNCTION COMPARISON (verified stamps only)")
    print("=" * 78)
    print(f"{'FUN_addr':<12}  {'text':>5}  {'raw':>5}  {'delta':>5}  notes")
    print("-" * 78)
    interesting = []
    for start in sorted(verified_starts):
        text_n = text_same.get(start, 0)
        raw_direct = len(direct.get(start, []))
        raw_pool   = len(pool.get(start, []))
        raw_n = raw_direct + raw_pool
        delta = raw_n - text_n
        if delta != 0 or raw_n > 0:
            notes = []
            if raw_direct: notes.append(f"{raw_direct} branch")
            if raw_pool:   notes.append(f"{raw_pool} pool")
            if delta > 0:  notes.append(f"raw +{delta}")
            if delta < 0:  notes.append(f"text +{-delta} (raw missed)")
            print(f"FUN_{start:08X}  {text_n:>5}  {raw_n:>5}  {delta:>+3}  {', '.join(notes)}")
            if delta != 0:
                interesting.append((start, text_n, raw_n, raw_direct, raw_pool))

    # ─── Discrepancy detail ─────────────────────────────────────────
    print()
    print("=" * 78)
    print("DISCREPANCY DETAIL")
    print("=" * 78)
    for start, text_n, raw_n, raw_direct, raw_pool in interesting:
        print(f"\nFUN_{start:08X}: text={text_n}  raw={raw_n} (direct={raw_direct} pool={raw_pool})")
        for src, kind in direct.get(start, []):
            print(f"   direct {kind:<3}  0x{src:08X} ->0x{start:08X}")
        for mov_src, pool_addr in pool.get(start, []):
            print(f"   pool        0x{mov_src:08X} mov.l @(pc)->0x{pool_addr:08X} = 0x{start:08X}")

    # ─── Raw scan false-positive hunt ───────────────────────────────
    # For every raw caller pointing at an address that is NOT a
    # verified function start AND NOT inside any verified subseg's
    # body — that's a target outside human-validated code.  These
    # are the strongest false-positive candidates: words that look
    # like function pointers but don't actually reach a known
    # function.
    print()
    print("=" * 78)
    print("RAW-SCAN OUTPUTS POINTING OUTSIDE VERIFIED CODE")
    print("(low-confidence — likely false positives or unverified functions)")
    print("=" * 78)
    def in_any_subseg(a):
        return any(s["start"] <= a <= s["end"] for s in code_subsegs)
    suspect_pool = {}
    suspect_direct = {}
    for tgt, srcs in pool.items():
        if tgt not in verified_starts and not in_any_subseg(tgt):
            suspect_pool[tgt] = srcs
    for tgt, srcs in direct.items():
        if tgt not in verified_starts and not in_any_subseg(tgt):
            suspect_direct[tgt] = srcs
    print(f"\n{len(suspect_pool)} pool-targets land outside verified code")
    for tgt in sorted(suspect_pool)[:20]:
        print(f"   0x{tgt:08X}  ({len(suspect_pool[tgt])} ref(s))")
    if len(suspect_pool) > 20:
        print(f"   ... and {len(suspect_pool) - 20} more")
    print(f"\n{len(suspect_direct)} direct-branch-targets land outside verified code")
    for tgt in sorted(suspect_direct)[:20]:
        print(f"   0x{tgt:08X}  ({len(suspect_direct[tgt])} ref(s))")


if __name__ == "__main__":
    main()
