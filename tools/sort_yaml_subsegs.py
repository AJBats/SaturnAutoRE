"""Sort an autofunc yaml's `subsegments:` blocks by start address.

Text-based — preserves the file's head (options, top-level comments)
and only reorders the subseg list.  Also drops the now-vestigial
`file:` field from each subseg block (no analytical consumer reads it
since TU retirement).

Usage:
    python tools/sort_yaml_subsegs.py path/to/foo.yaml

Writes back in-place.  Idempotent.
"""
import sys
from pathlib import Path


def main(yaml_path: Path):
    text = yaml_path.read_text()
    lines = text.splitlines(keepends=True)

    # Find the `subsegments:` line — everything before it is the head
    # and we leave it untouched.
    subseg_header_idx = None
    for i, line in enumerate(lines):
        if line.rstrip("\r\n") == "subsegments:":
            subseg_header_idx = i
            break
    if subseg_header_idx is None:
        sys.exit("error: no 'subsegments:' line found")

    head = lines[: subseg_header_idx + 1]
    body = lines[subseg_header_idx + 1 :]

    # Parse body into subseg blocks.  A block starts at "  - start: 0x..."
    # and runs until the next such line or EOF.  Lines outside any block
    # (e.g. trailing blank lines) are preserved separately.
    blocks: list[tuple[int, list[str]]] = []  # (start_addr, lines)
    trailing: list[str] = []
    i = 0
    while i < len(body):
        line = body[i]
        stripped = line.rstrip("\r\n")
        if stripped.startswith("  - start: 0x"):
            try:
                start_addr = int(stripped.split("0x", 1)[1], 16)
            except (ValueError, IndexError):
                trailing.append(line)
                i += 1
                continue
            block_lines = [line]
            i += 1
            while i < len(body):
                nxt = body[i].rstrip("\r\n")
                if nxt.startswith("  - "):
                    break
                if nxt and not nxt.startswith("    "):
                    break
                # Drop the vestigial file: field while we're rewriting.
                if nxt.lstrip().startswith("file:"):
                    i += 1
                    continue
                block_lines.append(body[i])
                i += 1
            blocks.append((start_addr, block_lines))
        else:
            # Blank lines / stray content between blocks — preserve at
            # the end so we don't lose anything.
            trailing.append(line)
            i += 1

    blocks.sort(key=lambda b: b[0])

    out = list(head)
    for _, block_lines in blocks:
        out.extend(block_lines)
    out.extend(trailing)

    yaml_path.write_text("".join(out))
    print(f"sorted {len(blocks)} subsegs in {yaml_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tools/sort_yaml_subsegs.py path/to/foo.yaml")
    main(Path(sys.argv[1]).resolve())
