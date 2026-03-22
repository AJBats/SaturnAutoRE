"""Memory differential analysis.

Compares binary memory dumps to find input-responsive regions,
active memory areas, and unknown data structures.
"""

import os
import struct


def load_dump(path):
    """Load a binary memory dump file."""
    with open(path, "rb") as f:
        return f.read()


def diff_dumps(dump_a, dump_b, base_addr=0x06000000):
    """Compare two memory dumps byte-by-byte.

    Returns a list of (address, old_byte, new_byte) for every difference.
    """
    if len(dump_a) != len(dump_b):
        size = min(len(dump_a), len(dump_b))
    else:
        size = len(dump_a)

    diffs = []
    for i in range(size):
        if dump_a[i] != dump_b[i]:
            diffs.append((base_addr + i, dump_a[i], dump_b[i]))
    return diffs


def block_heatmap(diffs, base_addr=0x06000000, block_size=256):
    """Group diffs into blocks and count changes per block.

    Returns list of (block_start_addr, change_count) sorted by count.
    """
    blocks = {}
    for addr, _, _ in diffs:
        block_start = ((addr - base_addr) // block_size) * block_size + base_addr
        blocks[block_start] = blocks.get(block_start, 0) + 1
    return sorted(blocks.items(), key=lambda x: -x[1])


def classify_regions(heatmap, known_structs=None):
    """Classify active blocks against known data structures.

    known_structs: list of {base, stride, count, notes} from config.yaml
    Returns list of (block_addr, count, classification) tuples.
    """
    classified = []
    for block_addr, count in heatmap:
        label = "unknown"
        if known_structs:
            for name, info in known_structs.items():
                struct_base = info.get("base", 0)
                if isinstance(struct_base, str):
                    struct_base = int(struct_base, 16)
                stride = info.get("stride", 0)
                struct_count = info.get("count", 1)
                if stride > 0 and struct_count > 0:
                    struct_end = struct_base + stride * struct_count
                else:
                    struct_end = struct_base + 0x1000  # default 4KB

                if struct_base <= block_addr < struct_end:
                    if stride > 0:
                        idx = (block_addr - struct_base) // stride
                        offset = (block_addr - struct_base) % stride
                        label = f"{name}[{idx}]+0x{offset:X}"
                    else:
                        offset = block_addr - struct_base
                        label = f"{name}+0x{offset:X}"
                    break
        classified.append((block_addr, count, label))
    return classified


def format_diff_report(diffs, heatmap, classified, dump_size,
                       label_a="A", label_b="B"):
    """Format a human-readable diff report."""
    lines = []

    lines.append(f"Memory diff: {label_a} vs {label_b}")
    lines.append(f"Dump size: {dump_size:,} bytes")
    lines.append(f"Total differences: {len(diffs)} bytes")
    lines.append(f"Active blocks: {len(heatmap)} (of {dump_size // 256})")
    lines.append("")

    if not diffs:
        lines.append("No differences found. The two dumps are identical.")
        return "\n".join(lines)

    # Top active blocks
    lines.append("TOP ACTIVE REGIONS (by changed byte count):")
    lines.append("")
    for block_addr, count, label in classified[:30]:
        lines.append(f"  0x{block_addr:08X}: {count:3d} bytes changed  ({label})")
    if len(classified) > 30:
        lines.append(f"  ... and {len(classified) - 30} more regions")
    lines.append("")

    # Summary by classification
    by_class = {}
    for _, count, label in classified:
        category = label.split("[")[0].split("+")[0]
        by_class[category] = by_class.get(category, 0) + count
    lines.append("SUMMARY BY REGION:")
    lines.append("")
    for category, total in sorted(by_class.items(), key=lambda x: -x[1]):
        lines.append(f"  {category}: {total} bytes changed")

    return "\n".join(lines)


def format_value_changes(diffs, base_addr=0x06000000, word_size=4):
    """Format individual value changes as 32-bit words.

    Groups consecutive byte diffs into word-aligned changes.
    """
    if not diffs:
        return "No differences."

    # Group by word-aligned address
    words = {}
    for addr, old_b, new_b in diffs:
        word_addr = (addr // word_size) * word_size
        if word_addr not in words:
            words[word_addr] = {"old": [None] * word_size, "new": [None] * word_size}
        offset = addr - word_addr
        words[word_addr]["old"][offset] = old_b
        words[word_addr]["new"][offset] = new_b

    lines = []
    lines.append(f"VALUE CHANGES ({len(words)} words):")
    lines.append("")
    for addr in sorted(words.keys())[:100]:
        w = words[addr]
        # Show only the changed bytes, rest as dots
        old_str = ""
        new_str = ""
        for i in range(word_size):
            if w["old"][i] is not None:
                old_str += f"{w['old'][i]:02X}"
                new_str += f"{w['new'][i]:02X}"
            else:
                old_str += ".."
                new_str += ".."
        lines.append(f"  0x{addr:08X}: {old_str} -> {new_str}")

    if len(words) > 100:
        lines.append(f"  ... and {len(words) - 100} more")

    return "\n".join(lines)
