#!/usr/bin/env python3
"""Dependency recon for function deletion.

Given a function symbol, reports all references that would break if the
function were removed. Run this BEFORE deleting any assembly file.

Usage:
    python del_recon.py FUN_06012345 -s reimpl/src -s reimpl/retail
    python del_recon.py FUN_06012345 -s src/race -p D:/Projects/MyGame

Checks:
  1. Direct call/branch sites and register-load references
  2. Pool constant references (.4byte, .long directives with the symbol)
  3. Linker aliases (PROVIDE/HIDDEN assignments in .ld files)
  4. Shared epilogues (adjacent functions that fall through without rts)
  5. Pointer tables (symbol address in data sections — best effort)
  6. C source references (extern declarations, function calls)
"""

import os
import re
import sys
import argparse


# SH-2 assembly comment character
COMMENT_CHARS = ('!', '#', ';')


def _strip_comment(line):
    """Remove assembly comment from a line."""
    for ch in COMMENT_CHARS:
        idx = line.find(ch)
        if idx >= 0:
            line = line[:idx]
    return line


def _is_rts_instruction(line):
    """Check if a line is an rts instruction (not a substring match)."""
    stripped = _strip_comment(line).strip().lower()
    return stripped == 'rts'


def _scan_files(src_dirs, extensions=('.s',)):
    """Yield (filepath, lines) for all files with matching extensions."""
    for src_dir in src_dirs:
        if not os.path.exists(src_dir):
            continue
        for root, dirs, files in os.walk(src_dir):
            # Skip .git and build directories
            dirs[:] = [d for d in dirs if d not in ('.git', 'build', '__pycache__')]
            for f in files:
                if any(f.endswith(ext) for ext in extensions):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            lines = fh.readlines()
                        yield fpath, lines
                    except (IOError, PermissionError):
                        pass


def find_direct_calls(symbol, src_dirs):
    """Find jsr/bsr/bra/jmp and register-load references to the symbol."""
    hits = []
    # Branch/call instructions with symbol name in operand
    branch_pattern = re.compile(
        rf'\b(jsr|bsr|bra|jmp|bt/s|bf/s|bt|bf)\b.*\b{re.escape(symbol)}\b',
        re.IGNORECASE
    )
    # Register loads referencing the symbol (mov.l FUN_X, Rn)
    load_pattern = re.compile(
        rf'\b(mov\.l|mov)\b.*\b{re.escape(symbol)}\b',
        re.IGNORECASE
    )
    for fpath, lines in _scan_files(src_dirs):
        for i, line in enumerate(lines, 1):
            code = _strip_comment(line)
            if branch_pattern.search(code):
                hits.append({
                    'file': os.path.relpath(fpath),
                    'line': i,
                    'text': line.strip(),
                })
            elif load_pattern.search(code):
                hits.append({
                    'file': os.path.relpath(fpath),
                    'line': i,
                    'text': line.strip(),
                    'type': 'register_load',
                })
    return hits


def find_pool_constants(symbol, src_dirs):
    """Find .4byte/.long references (pool constants, jump tables)."""
    hits = []
    pattern = re.compile(
        rf'^\s*\.(4byte|long|data\.l)\s+.*\b{re.escape(symbol)}\b',
        re.IGNORECASE
    )
    for fpath, lines in _scan_files(src_dirs):
        for i, line in enumerate(lines, 1):
            code = _strip_comment(line)
            if pattern.match(code):
                hits.append({
                    'file': os.path.relpath(fpath),
                    'line': i,
                    'text': line.strip(),
                })
    return hits


def find_linker_aliases(symbol, project_dir):
    """Find PROVIDE()/HIDDEN() or symbol assignments in linker scripts."""
    hits = []
    # Something depends on our symbol: PROVIDE(alias = our_symbol)
    provides_pattern = re.compile(
        rf'\b(PROVIDE|HIDDEN)\s*\(\s*\w+\s*=\s*{re.escape(symbol)}\b',
        re.IGNORECASE
    )
    # Our symbol is an alias: PROVIDE(our_symbol = target) or HIDDEN(our_symbol = target)
    alias_pattern = re.compile(
        rf'\b(PROVIDE|HIDDEN)\s*\(\s*{re.escape(symbol)}\s*=\s*(\w+)\)',
        re.IGNORECASE
    )
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ('.git', 'build', 'node_modules', '__pycache__')]
        for f in files:
            if not f.endswith('.ld'):
                continue
            fpath = os.path.join(root, f)
            try:
                with open(fpath, encoding='utf-8', errors='replace') as fh:
                    for i, line in enumerate(fh, 1):
                        if provides_pattern.search(line):
                            hits.append({
                                'file': os.path.relpath(fpath),
                                'line': i,
                                'text': line.strip(),
                                'type': 'provides_this',
                            })
                        m = alias_pattern.search(line)
                        if m:
                            hits.append({
                                'file': os.path.relpath(fpath),
                                'line': i,
                                'text': line.strip(),
                                'type': 'alias_of',
                                'target': m.group(2),
                            })
            except (IOError, PermissionError):
                pass
    return hits


def check_shared_epilogue(symbol, src_dirs):
    """Check if a function has fall-through neighbors.

    Searches file CONTENTS for the symbol label, not filenames.
    Finds the closest preceding label (not the first in file) to detect
    fall-through correctly in multi-function files.
    """
    warnings = []

    for fpath, lines in _scan_files(src_dirs):
        # Search for our symbol as a label in the file contents
        our_label_line = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == f'{symbol}:':
                our_label_line = i
                break

        if our_label_line is None:
            continue

        # Find the closest preceding label and check for rts between it and us
        closest_neighbor = None
        has_rts_between = False
        for j in range(our_label_line - 1, -1, -1):
            stripped = lines[j].strip()
            if _is_rts_instruction(lines[j]):
                has_rts_between = True
                break
            # Check for a function label (not local .L labels, not directives)
            if (stripped.endswith(':') and
                    not stripped.startswith('.') and
                    not stripped.startswith('#')):
                label = stripped.rstrip(':')
                if not label.startswith('.L'):
                    closest_neighbor = label
                    break

        if closest_neighbor and not has_rts_between:
            warnings.append({
                'file': os.path.relpath(fpath),
                'message': f'{closest_neighbor} falls through into {symbol} (no rts between them)',
                'neighbor': closest_neighbor,
            })

        # Check if OUR function ends without rts (falls through to next)
        # Scan from our label to end of file or next function label
        next_func_label = None
        last_instruction = ''
        for j in range(our_label_line + 1, len(lines)):
            stripped = lines[j].strip()
            # Check for next function label
            if (stripped.endswith(':') and
                    not stripped.startswith('.') and
                    not stripped.startswith('#')):
                label = stripped.rstrip(':')
                if not label.startswith('.L'):
                    next_func_label = label
                    break
            # Track last real instruction
            code = _strip_comment(lines[j]).strip()
            if code and not code.startswith('.'):
                last_instruction = code

        if last_instruction and not _is_rts_instruction(
                last_instruction + ' '):  # fake line for the check
            # More direct check
            if last_instruction.lower().strip() != 'rts':
                msg = f'{symbol} does NOT end with rts'
                if next_func_label:
                    msg += f' — falls through to {next_func_label}'
                warnings.append({
                    'file': os.path.relpath(fpath),
                    'message': msg,
                })

    return warnings


def find_pointer_table_refs(symbol, src_dirs):
    """Best-effort: find the symbol's raw hex address in data directives.

    This catches some pointer tables but NOT runtime-computed addresses.
    Those require emulator investigation (call traces, breakpoints).
    """
    hits = []
    addr_match = re.match(r'(?:FUN_|sym_)([0-9A-Fa-f]+)', symbol)
    if not addr_match:
        return hits

    addr_hex = addr_match.group(1)
    # Normalize: search with and without leading zeros
    addr_int = int(addr_hex, 16)
    addr_variants = [
        f'0x{addr_int:08X}',
        f'0x{addr_int:X}',
        f'0x{addr_int:08x}',
        f'0x{addr_int:x}',
    ]
    # Deduplicate
    addr_variants = list(dict.fromkeys(addr_variants))

    pattern = re.compile(
        rf'^\s*\.(4byte|long|data\.l)\s+(' +
        '|'.join(re.escape(v) for v in addr_variants) +
        r')\b',
        re.IGNORECASE
    )

    for fpath, lines in _scan_files(src_dirs):
        for i, line in enumerate(lines, 1):
            code = _strip_comment(line)
            if pattern.match(code):
                hits.append({
                    'file': os.path.relpath(fpath),
                    'line': i,
                    'text': line.strip(),
                })
    return hits


def find_c_references(symbol, src_dirs):
    """Find references in C source files (extern declarations, calls)."""
    hits = []
    pattern = re.compile(rf'\b{re.escape(symbol)}\b')
    for fpath, lines in _scan_files(src_dirs, extensions=('.c', '.h')):
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                hits.append({
                    'file': os.path.relpath(fpath),
                    'line': i,
                    'text': line.strip(),
                })
    return hits


def main():
    parser = argparse.ArgumentParser(
        description='Dependency recon for function deletion'
    )
    parser.add_argument('symbol', help='Function symbol (e.g. FUN_06012345)')
    parser.add_argument('--src-dir', '-s', required=True, action='append',
                        help='Source directory to scan (repeatable, e.g. -s reimpl/src -s reimpl/retail)')
    parser.add_argument('--project', '-p', default=None,
                        help='Project directory for linker script search (default: current dir)')
    args = parser.parse_args()

    project_dir = args.project or os.getcwd()
    symbol = args.symbol
    src_dirs = [os.path.abspath(d) for d in args.src_dir]

    for d in src_dirs:
        if not os.path.exists(d):
            print(f"ERROR: Source directory does not exist: {d}")
            return 1

    print(f"=== Deletion Recon: {symbol} ===")
    print(f"Project: {project_dir}")
    print(f"Source dirs: {', '.join(src_dirs)}")
    print()

    total_issues = 0

    # 1. Direct calls and register loads
    calls = find_direct_calls(symbol, src_dirs)
    branch_calls = [h for h in calls if h.get('type') != 'register_load']
    reg_loads = [h for h in calls if h.get('type') == 'register_load']
    print(f"--- 1. Direct references ({len(calls)} found: {len(branch_calls)} branch, {len(reg_loads)} register load) ---")
    if calls:
        for h in calls:
            prefix = "[reg]" if h.get('type') == 'register_load' else "[call]"
            print(f"  {prefix} {h['file']}:{h['line']}: {h['text']}")
        total_issues += len(calls)
    else:
        print("  None found.")
        print("  Note: SH-2 indirect calls (jsr @Rn) won't appear here.")
        print("  Check pool constants below for indirect call references.")
    print()

    # 2. Pool constants
    pools = find_pool_constants(symbol, src_dirs)
    print(f"--- 2. Pool constant references ({len(pools)} found) ---")
    if pools:
        for h in pools:
            print(f"  {h['file']}:{h['line']}: {h['text']}")
        total_issues += len(pools)
    else:
        print("  None found.")
    print()

    # 3. Linker aliases
    aliases = find_linker_aliases(symbol, project_dir)
    print(f"--- 3. Linker aliases ({len(aliases)} found) ---")
    if aliases:
        for h in aliases:
            if h.get('type') == 'alias_of':
                print(f"  {h['file']}:{h['line']}: {symbol} is an ALIAS for {h['target']}")
                print(f"    WARNING: Deleting {symbol} may require updating references to {h['target']}")
            else:
                print(f"  {h['file']}:{h['line']}: {h['text']}")
        total_issues += len(aliases)
    else:
        print("  None found.")
    print()

    # 4. Shared epilogues
    epilogues = check_shared_epilogue(symbol, src_dirs)
    print(f"--- 4. Shared epilogue warnings ({len(epilogues)} found) ---")
    if epilogues:
        for w in epilogues:
            print(f"  {w['file']}: {w['message']}")
        total_issues += len(epilogues)
    else:
        print("  None found.")
    print()

    # 5. Pointer table references
    ptrs = find_pointer_table_refs(symbol, src_dirs)
    print(f"--- 5. Pointer table references ({len(ptrs)} found) ---")
    if ptrs:
        for h in ptrs:
            print(f"  {h['file']}:{h['line']}: {h['text']}")
        total_issues += len(ptrs)
    else:
        print("  None found (note: runtime pointer tables cannot be detected statically).")
    print()

    # 6. C source references
    c_refs = find_c_references(symbol, src_dirs)
    print(f"--- 6. C source references ({len(c_refs)} found) ---")
    if c_refs:
        for h in c_refs:
            print(f"  {h['file']}:{h['line']}: {h['text']}")
        total_issues += len(c_refs)
    else:
        print("  None found.")
    print()

    # Summary
    print(f"=== Summary: {total_issues} issue(s) found ===")
    if total_issues == 0:
        print(f"No static references found. {symbol} may be safe to remove.")
        print(f"CAUTION: Pointer tables and runtime references cannot be detected")
        print(f"by static analysis. Verify with emulator call traces if uncertain.")
    else:
        print(f"Resolve all issues above before removing {symbol}.")
        if epilogues:
            print(f"CRITICAL: Shared epilogue detected — removing this function")
            print(f"will break its neighbor's stack cleanup.")

    return 0 if total_issues == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
