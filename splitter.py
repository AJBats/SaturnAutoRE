#!/usr/bin/env python3
"""splitter.py — produce one combined .s file + linker script from a binary
and a yaml boundary database.

Reads a yaml describing TU ranges and verified function subsegments, plus the
raw binary it describes. Emits TWO outputs into the output directory:

  - <module>.s       — all 39 TUs concatenated, each in its own .section.
                        Declared code subsegments get decoded SH-2 mnemonics.
                        Undeclared regions get raw .byte pairs.
  - <module>.bin.ld  — simple linker script placing the .text at the load
                        address. Single .o is the unit (sotn-style).

Cross-references (bsr/bra/bf/bt targets outside a declared subseg) get
neutral `xref_XXXXXXXX:` labels inserted at the target address — no
identity claim, just "this address is referenced from somewhere."

Usage:
    python splitter.py <yaml_path> <binary_project_root> <output_dir>
"""

import os
import sys
import argparse
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR / "lib"))

from sh2_decode import decode_sh2

BRANCH_MNEMONICS = {"bra", "bsr", "bf", "bt", "bf/s", "bt/s"}


# ---------------------------------------------------------------------------
# Per-subseg label analysis
# ---------------------------------------------------------------------------

def _pool_kind(mnem):
    """Determine pool-load kind from a decoded mnemonic.

    Returns one of:
      'mov.l' — 4-byte pool constant
      'mov.w' — 2-byte pool constant
      'mova'  — label-only target (mova @(disp,PC),r0 — points at table start)
      None    — not a pool-loading instruction
    """
    if mnem is None:
        return None
    if mnem.startswith("mov.l @(0x"):
        return "mov.l"
    if mnem.startswith("mov.w @(0x"):
        return "mov.w"
    if mnem.startswith("mova @(0x"):
        return "mova"
    return None


def analyze_subseg(binary, vram, sub_start, sub_end):
    """Decode a code subseg, iterate until label sets stabilize.

    Pool targets are data regions, NOT instructions — skipping them across
    iterations prunes bogus targets extracted from decoding pool bytes.

    Returns:
        pool4:        dict {addr: None} of 4-byte mov.l pool constants within subseg
        pool2:        dict {addr: None} of 2-byte mov.w pool constants within subseg
        mova_targets: set of addrs targeted by mova (label only, unknown size)
        branch_local: set of addrs targeted by branches whose target is INSIDE subseg
        cross_refs:   set of addrs targeted by branches/loads whose target is OUTSIDE subseg

    (pool4/pool2 are dicts not sets so we know the size at each address; the
    value is currently unused but reserved for future per-pool metadata.)
    """
    pool4 = set()
    pool2 = set()
    mova_targets = set()
    branch_local = set()
    cross_refs = set()

    for _ in range(8):
        new_pool4, new_pool2, new_mova = set(), set(), set()
        new_branch, new_cross = set(), set()
        addr = sub_start
        while addr <= sub_end:
            if addr in pool4:
                addr += 4
                continue
            if addr in pool2:
                addr += 2
                continue
            if addr % 2 != 0:
                addr += 1
                continue
            off = addr - vram
            if off + 1 > len(binary):
                break
            opcode = (binary[off] << 8) | binary[off + 1]
            mnem, pool_target = decode_sh2(opcode, addr)

            kind = _pool_kind(mnem)
            if pool_target is not None:
                if sub_start <= pool_target <= sub_end:
                    if kind == "mov.l":
                        new_pool4.add(pool_target)
                    elif kind == "mov.w":
                        new_pool2.add(pool_target)
                    elif kind == "mova":
                        new_mova.add(pool_target)
                else:
                    new_cross.add(pool_target)

            head = mnem.split()[0] if mnem else ""
            if head in BRANCH_MNEMONICS:
                parts = mnem.split()
                if len(parts) >= 2:
                    try:
                        target = int(parts[1].rstrip(","), 16)
                        if sub_start <= target <= sub_end:
                            new_branch.add(target)
                        else:
                            new_cross.add(target)
                    except ValueError:
                        pass

            addr += 2

        if (new_pool4, new_pool2, new_mova, new_branch, new_cross) == (pool4, pool2, mova_targets, branch_local, cross_refs):
            break
        pool4, pool2, mova_targets, branch_local, cross_refs = new_pool4, new_pool2, new_mova, new_branch, new_cross

    return pool4, pool2, mova_targets, branch_local, cross_refs


# ---------------------------------------------------------------------------
# Global label map (cross-section references)
# ---------------------------------------------------------------------------

def build_global_labels(binary, vram, subsegs):
    """Walk all declared code subsegs and build address → label_name map for
    targets that need a globally-visible label (cross-section references).

    Declared subseg starts get FUN_XXXXXXXX names; other cross-ref targets
    get neutral sym_XXXXXXXX names.
    """
    subseg_name_at = {}
    for s in subsegs:
        if s.get("type") == "code":
            name = s.get("name") or f"FUN_{s['start']:08X}"
            subseg_name_at[s["start"]] = name

    global_labels = {}
    for sub in subsegs:
        if sub.get("type") != "code":
            continue
        _, _, _, _, cross_refs = analyze_subseg(binary, vram, sub["start"], sub["end"])
        for addr in cross_refs:
            if addr in subseg_name_at:
                global_labels[addr] = subseg_name_at[addr]
            elif addr not in global_labels:
                global_labels[addr] = f"xref_{addr:08X}"

    # Also expose declared subseg starts as global labels regardless of cross-refs
    for addr, name in subseg_name_at.items():
        global_labels.setdefault(addr, name)

    return global_labels


# ---------------------------------------------------------------------------
# Mnemonic symbolization
# ---------------------------------------------------------------------------

def symbolize(mnem, pool4, pool2, mova_targets, branch_local, global_labels):
    """Replace absolute target addresses in a mnemonic with label references."""
    parts = mnem.split(None, 1)
    if not parts:
        return mnem
    head = parts[0]
    tail = parts[1] if len(parts) > 1 else ""

    # PC-relative load: replace @(0xADDR) with label
    if "@(0x" in tail and head in ("mov.l", "mov.w", "mova"):
        before, _, after = tail.partition("@(0x")
        hex_str, _, rest = after.partition(")")
        try:
            addr = int(hex_str, 16)
            if addr in pool4 or addr in pool2 or addr in mova_targets:
                return f"{head} {before}.L_pool_{addr:08X}{rest}".strip()
            if addr in global_labels:
                return f"{head} {before}{global_labels[addr]}{rest}".strip()
        except ValueError:
            pass

    # Branch: prefer local section label, then global
    if head in BRANCH_MNEMONICS:
        try:
            target = int(tail.rstrip(","), 16)
            if target in branch_local:
                return f"{head} .L_{target:08X}"
            if target in global_labels:
                return f"{head} {global_labels[target]}"
        except ValueError:
            pass

    return mnem


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

def emit_subseg_code(binary, vram, sub, global_labels, out):
    """Emit a declared code subseg: prologue, instructions, pool data, branch labels."""
    start, end = sub["start"], sub["end"]
    name = sub.get("name") or f"FUN_{start:08X}"

    pool4, pool2, mova_targets, branch_local, _ = analyze_subseg(binary, vram, start, end)

    out.append("")
    out.append(f"    .global {name}")
    out.append(f"    .type {name}, @function")
    out.append(f"{name}:")

    addr = start
    while addr <= end:
        # 4-byte mov.l pool constant
        if addr in pool4:
            off = addr - vram
            value = (binary[off] << 24) | (binary[off + 1] << 16) | (binary[off + 2] << 8) | binary[off + 3]
            out.append(f".L_pool_{addr:08X}:")
            out.append(f"    .4byte 0x{value:08X}")
            addr += 4
            continue
        # 2-byte mov.w pool constant
        if addr in pool2:
            off = addr - vram
            value = (binary[off] << 8) | binary[off + 1]
            out.append(f".L_pool_{addr:08X}:")
            out.append(f"    .2byte 0x{value:04X}")
            addr += 2
            continue
        # mova target — label only, treat following bytes as instructions/data per linear walk
        if addr in mova_targets:
            out.append(f".L_pool_{addr:08X}:")
            # fall through — let the instruction decoder handle bytes from here

        if addr in branch_local:
            out.append(f".L_{addr:08X}:")
        # A cross-ref target landing inside this subseg's body is rare but possible
        if addr != start and addr in global_labels:
            out.append(f"{global_labels[addr]}:")

        off = addr - vram
        if off + 1 > len(binary):
            break
        opcode = (binary[off] << 8) | binary[off + 1]
        mnem, _ = decode_sh2(opcode, addr)
        if mnem is None:
            out.append(f"    .byte 0x{binary[off]:02X}, 0x{binary[off+1]:02X}")
        else:
            out.append(f"    {symbolize(mnem, pool4, pool2, mova_targets, branch_local, global_labels)}")
        addr += 2


def emit_undeclared_range(binary, vram, start, end, global_labels, out):
    """Emit raw .byte pairs for an undeclared address range, with cross-ref labels."""
    addr = start
    while addr <= end:
        if addr in global_labels:
            out.append(f"{global_labels[addr]}:")
        off = addr - vram
        if off >= len(binary):
            break
        if off + 1 < len(binary) and addr + 1 <= end:
            out.append(f"    .byte 0x{binary[off]:02X}, 0x{binary[off+1]:02X}")
            addr += 2
        else:
            out.append(f"    .byte 0x{binary[off]:02X}")
            addr += 1


def emit_tu(binary, vram, tu, subsegs, global_labels, out):
    """Emit one TU's worth of content into the combined .s output."""
    tu_start, tu_end, tu_name = tu["start"], tu["end"], tu["name"]
    declared = sorted(
        [s for s in subsegs if tu_start <= s["start"] <= tu_end],
        key=lambda s: s["start"],
    )

    out.append("")
    out.append(f"/* === {tu_name}  0x{tu_start:08X}-0x{tu_end:08X} === */")
    out.append(f"    .section .text.{tu_name}")

    cursor = tu_start
    for sub in declared:
        if cursor < sub["start"]:
            out.append("")
            out.append(f"/* undeclared 0x{cursor:08X}-0x{sub['start']-1:08X} */")
            emit_undeclared_range(binary, vram, cursor, sub["start"] - 1, global_labels, out)
            cursor = sub["start"]

        if sub.get("type") == "code":
            emit_subseg_code(binary, vram, sub, global_labels, out)
        elif sub.get("type") == "data":
            out.append("")
            out.append(f"/* declared data 0x{sub['start']:08X}-0x{sub['end']:08X} */")
            emit_undeclared_range(binary, vram, sub["start"], sub["end"], global_labels, out)
        cursor = sub["end"] + 1

    if cursor <= tu_end:
        out.append("")
        out.append(f"/* undeclared 0x{cursor:08X}-0x{tu_end:08X} */")
        emit_undeclared_range(binary, vram, cursor, tu_end, global_labels, out)


# ---------------------------------------------------------------------------
# Linker script generation
# ---------------------------------------------------------------------------

LD_TEMPLATE = """/* {module}.bin.ld — generated from {module}.bin.yaml. Do not edit by hand. */

OUTPUT_FORMAT("elf32-sh")
OUTPUT_ARCH(sh)

SECTIONS
{{
    . = 0x{vram:08X};

    .text : {{
        {module}.o(.text*)
    }}

    /DISCARD/ : {{
        *(.comment)
        *(.note*)
        *(.eh_frame)
    }}
}}
"""


def write_ld(out_path, module, vram):
    with open(out_path, "w") as f:
        f.write(LD_TEMPLATE.format(module=module, vram=vram))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Split a binary into one combined .s + ld script per a yaml boundary database.")
    parser.add_argument("yaml_path", help="path to the boundary yaml (e.g. race.bin.yaml)")
    parser.add_argument("project_root", help="project root for resolving yaml's target_path")
    parser.add_argument("output_dir", help="where to write the .s and .ld files")
    args = parser.parse_args()

    with open(args.yaml_path, "r") as f:
        cfg = yaml.safe_load(f)

    vram = int(cfg["options"]["vram"])
    target_rel = cfg["options"]["target_path"]
    binary_path = Path(args.project_root) / target_rel
    with open(binary_path, "rb") as f:
        binary = f.read()

    tus = cfg.get("tus", [])
    subsegs = cfg.get("subsegments", [])

    # Module name = yaml filename stem (e.g. "race.bin" from "race.bin.yaml")
    module = Path(args.yaml_path).stem  # "race.bin.yaml" -> "race.bin"
    module = module.rsplit(".", 1)[0]   # "race.bin" -> "race"

    os.makedirs(args.output_dir, exist_ok=True)

    # Pass 1: build global label map (cross-section references)
    global_labels = build_global_labels(binary, vram, subsegs)

    # Pass 2: emit combined .s
    out_lines = [
        f"/* {module}.s — generated from {Path(args.yaml_path).name}. Do not edit by hand. */",
    ]
    for tu in tus:
        emit_tu(binary, vram, tu, subsegs, global_labels, out_lines)
    out_lines.append("")

    s_path = Path(args.output_dir) / f"{module}.s"
    with open(s_path, "w") as f:
        f.write("\n".join(out_lines))

    # Pass 3: emit linker script
    ld_path = Path(args.output_dir) / f"{module}.bin.ld"
    write_ld(ld_path, module, vram)

    print(f"Wrote {s_path}")
    print(f"Wrote {ld_path}")
    print(f"TUs: {len(tus)}    declared subsegments: {len(subsegs)}    cross-ref labels: {len(global_labels) - sum(1 for s in subsegs if s.get('type') == 'code')}")


if __name__ == "__main__":
    main()
