#!/usr/bin/env python3
"""extract_pool_priors.py — extract pool/data address priors from archive .s files.

Walks each `.s` file with a per-function address counter so we can record
EVERY data directive's address, not just the ones inside an explicit
`.L_pool_*:` block.  This catches trailing data tables that the archive's
disassembler chose not to label as a pool — e.g., FUN_0602A370 ends with
~412 bytes of bare `.byte 0x??, 0x??` lines that store a coordinate lookup
table.

Output format:

    0x06028E18 4
    0x06029922 2
    ...

The eval tool and splitter use these priors to render bytes as proper
`.2byte`/`.4byte` data with `.L_pool_*` labels, and to extend function
boundaries forward through contiguous data zones.

Address-tracking model
----------------------
- Track `current_addr` across an entire function body, starting from each
  `FUN_<addr>:` label.
- For each subsequent line:
    * `FUN_<addr2>:` — switch to new function context.
    * `.L_<hex>:` (any prefix: pool / wpool / jt / bare) — RE-SYNC to that
      address.  Labels are authoritative; if our counter disagrees we trust
      the label.
    * `.section`, `.global`, `.type`, `.size`, `.text` — non-data
      directives, do not advance.
    * `.4byte` / `.long`              — advance 4, record prior.
    * `.2byte` / `.short` / `.hword`  — advance 2, record prior.
    * `.byte X, Y, …`                 — advance N (one per value); record
      a 2-byte prior at the start if N==2 and current_addr is even.
    * Generic label `xxx:`            — keep tracking (labels don't advance
      addr).
    * Anything else — assume an SH-2 instruction (2 bytes), advance 2.

If the counter ever becomes "unsure" (an unknown directive that we can't
size), reset to None and wait for the next address-bearing label to
re-sync.

Usage:
    python extract_pool_priors.py <archive_src_dir> <output_file>
"""

import argparse
import re
from pathlib import Path

FUN_LABEL_RE = re.compile(r"^FUN_([0-9A-Fa-f]{8}):\s*$")
# Any .L_<addr>: label where <addr> is an 8-hex address (with optional prefix).
ADDR_LABEL_RE = re.compile(r"^\.L_(?:pool_|wpool_|jt_)?([0-9A-Fa-f]{8}):\s*$")
GENERIC_LABEL_RE = re.compile(r"^[\.A-Za-z_][\w\.]*:\s*$")

# Directives that don't emit any bytes (and therefore don't advance addr).
NON_DATA_DIRECTIVES = frozenset({
    ".section", ".global", ".type", ".size", ".weak", ".local", ".extern",
    ".text", ".data", ".bss", ".rodata",
    ".equ", ".set",
    ".ident", ".file", ".loc",
    ".end",
})


def extract(archive_dir, output_file):
    archive_dir = Path(archive_dir)
    priors = {}
    files_scanned = 0
    for s_file in archive_dir.glob("*.s"):
        files_scanned += 1
        current_addr = None
        for raw_line in s_file.read_text(errors="replace").splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            # Skip full-line comments
            if stripped.startswith("/*") or stripped.startswith("//") or stripped.startswith("#"):
                continue

            # FUN_<addr>: starts a new function context.
            m = FUN_LABEL_RE.match(stripped)
            if m:
                current_addr = int(m.group(1), 16)
                continue

            # .L_<hex>: (any prefix) — re-sync.  Trust the label's hex over
            # our counter; the label is authoritative.
            m = ADDR_LABEL_RE.match(stripped)
            if m:
                current_addr = int(m.group(1), 16)
                continue

            # Other generic labels (e.g. ".L_done:", "xxx:") — keep tracking
            # without resyncing; they don't carry an address in their name.
            if GENERIC_LABEL_RE.match(stripped):
                continue

            # If we don't know our address yet, skip until next label.
            if current_addr is None:
                continue

            # Strip trailing inline comment for cleaner directive matching.
            code = stripped.split("/*")[0].strip()
            if not code:
                continue

            first_token = code.split()[0]

            # Non-data directives — no address advance.
            if first_token in NON_DATA_DIRECTIVES:
                continue

            # Data directives — record prior and advance.  Only record
            # priors when the address is naturally aligned for the size
            # (SH-2 data alignment); an odd counter would mean we drifted
            # somewhere upstream (e.g. a `.byte X` single-byte directive
            # earlier), and recording a 2/4-byte prior at an odd address
            # would corrupt downstream consumers.
            if first_token in (".4byte", ".long"):
                if (current_addr & 3) == 0:
                    priors.setdefault(current_addr, 4)
                current_addr += 4
                continue
            if first_token in (".2byte", ".short", ".hword"):
                # All emit 2 bytes on SH-2.  Archive uses `.short` for
                # jump-table offsets (Ghidra convention), `.2byte`/`.hword`
                # for general halfwords; bytes are identical.
                if (current_addr & 1) == 0:
                    priors.setdefault(current_addr, 2)
                current_addr += 2
                continue
            if first_token == ".byte":
                body = code[len(".byte"):]
                n_bytes = body.count(",") + 1 if body.strip() else 0
                if n_bytes == 2 and (current_addr & 1) == 0:
                    # 2-byte `.byte` run at aligned addr = a 2-byte data
                    # value the disassembler chose not to call a `.2byte`
                    # (common for raw trailing data tables like the
                    # coordinate-lookup table after FUN_0602A370's body).
                    priors.setdefault(current_addr, 2)
                current_addr += n_bytes
                continue

            # Unknown directive (`.align`, `.string`, etc.) — can't size
            # safely.  Drop tracking; we'll re-sync at the next labeled
            # address.
            if first_token.startswith("."):
                current_addr = None
                continue

            # Anything else is an SH-2 instruction (2 bytes, fixed-width).
            current_addr += 2

    with open(output_file, "w") as f:
        f.write("# Pool/data address priors extracted from archive_src .s files.\n")
        f.write("# Format: <hex_address> <size_in_bytes>\n")
        for addr in sorted(priors):
            f.write(f"0x{addr:08X} {priors[addr]}\n")

    print(f"Scanned {files_scanned} .s files")
    print(f"Wrote {len(priors)} pool priors to {output_file}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("archive_dir", help="path to archive_src/src/<module>/")
    p.add_argument("output_file", help="output prior file")
    args = p.parse_args()
    extract(args.archive_dir, args.output_file)


if __name__ == "__main__":
    main()
