#!/usr/bin/env python3
"""extract_pool_priors.py — extract pool labels from archive_src .s files.

Scans the archive's `.s` files for pool data and writes addresses with sizes:

    0x06028E18 4
    0x06029922 2
    ...

These act as "pool address priors" for the eval tool and splitter — addresses
the archive correctly identified as pool data, even when the referencing
function hasn't been verified yet in our new yaml.

Handles two layout patterns:
    .L_pool_XXXXXXXX:                       (explicit address label)
        .4byte VALUE
                                            (sequential entry — implicit addr)
        .4byte VALUE
    .L_pool_YYYYYYYY:                       (new explicit label)
        ...

For sequential entries, address is tracked: starts at the explicit label,
advances by the byte count of each data directive seen, resets when a
non-pool label or instruction interrupts.

Usage:
    python extract_pool_priors.py <archive_src_dir> <output_file>
"""

import argparse
import re
from pathlib import Path

POOL_LABEL_RE = re.compile(r"^\.L_(pool|wpool)_([0-9A-Fa-f]{8}):\s*$")
LABEL_RE = re.compile(r"^[\.A-Za-z_][\w\.]*:\s*$")


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
            # Pool label sets the current address
            m = POOL_LABEL_RE.match(stripped)
            if m:
                current_addr = int(m.group(2), 16)
                continue
            # Any other label resets the sequence — we're no longer in a pool block
            if LABEL_RE.match(stripped):
                current_addr = None
                continue

            if current_addr is None:
                continue

            # Strip trailing comments to make directive matching cleaner
            code = stripped.split("/*")[0].strip()
            if not code:
                continue

            if code.startswith(".4byte"):
                priors.setdefault(current_addr, 4)
                current_addr += 4
                continue
            if code.startswith(".2byte"):
                priors.setdefault(current_addr, 2)
                current_addr += 2
                continue
            if code.startswith(".byte"):
                # Count comma-separated bytes
                body = code[len(".byte"):]
                n_bytes = body.count(",") + 1 if body.strip() else 0
                if n_bytes == 2 and (current_addr & 1) == 0:
                    # Treat 2-byte .byte sequence at aligned addr as a 2-byte pool
                    priors.setdefault(current_addr, 2)
                current_addr += n_bytes
                continue
            # Anything else (section directive, instruction, etc.) ends the sequence
            current_addr = None

    with open(output_file, "w") as f:
        f.write("# Pool address priors extracted from archive_src .s files.\n")
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
