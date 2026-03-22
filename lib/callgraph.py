"""Call graph capture and analysis.

Captures per-frame call traces from Mednafen, parses them into
caller->callee edges, builds trees, and produces differential analysis
across scenarios.
"""

import os
import re
import bisect
from collections import Counter, defaultdict


def parse_call_trace(path):
    """Parse a raw call trace file into a list of call records.

    Each line: <timestamp> <cpu> <caller_addr> <target_addr>
    Returns list of (timestamp, cpu, caller_hex, target_hex).
    """
    calls = []
    if not os.path.exists(path):
        return calls
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4:
                # Validate addresses are hex
                try:
                    int(parts[2], 16)
                    int(parts[3], 16)
                except ValueError:
                    continue
                calls.append((parts[0], parts[1], parts[2], parts[3]))
    return calls


class FunctionTable:
    """Fast address-to-function lookup using sorted array + bisect."""

    # Maximum offset from a function start to still attribute an address
    # to that function. Prevents sparse tables from misattributing distant
    # addresses to the nearest known function.
    MAX_FUNCTION_SIZE = 0x4000  # 16KB

    def __init__(self, addr_to_name=None):
        if addr_to_name:
            pairs = sorted(addr_to_name.items())
            self.addrs = [a for a, _ in pairs]
            self.names = [n for _, n in pairs]
        else:
            self.addrs = []
            self.names = []

    @classmethod
    def from_assembly_dir(cls, asm_dir):
        """Build a function table from assembly source files.

        Supports two layouts:
        1. One file per function (FUN_06012345.s) — filename IS the function
        2. Multi-function files (disassembly.s) — scans contents for labels

        Recurses into subdirectories.
        """
        addr_to_name = {}
        if not asm_dir or not os.path.exists(asm_dir):
            return cls()

        # Pattern for function labels inside .s files
        # Matches: "FUN_060a0480:" or "sym_06012345:" at start of line
        label_pattern = re.compile(r"^((?:FUN_|sym_)[0-9A-Fa-f]{6,8})\s*:", re.MULTILINE)
        # Also matches: "; Entry: 060a0480" comment headers from Ghidra exports
        entry_pattern = re.compile(r";\s*Entry:\s*([0-9A-Fa-f]{6,8})", re.MULTILINE)

        for dirpath, _dirnames, filenames in os.walk(asm_dir):
            for f in filenames:
                if not f.endswith(".s"):
                    continue
                name = f[:-2]  # strip .s

                # Try filename-as-function first (one file per function)
                m = re.match(r"^(?:FUN_|sym_)([0-9A-Fa-f]{6,8})$", name)
                if m:
                    try:
                        addr = int(m.group(1), 16)
                        addr_to_name[addr] = name
                    except ValueError:
                        pass
                    continue

                # Filename doesn't match — scan contents for function labels
                filepath = os.path.join(dirpath, f)
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except (IOError, OSError):
                    continue

                # Find labels like "FUN_060a0480:"
                for lm in label_pattern.finditer(content):
                    label = lm.group(1)
                    addr_hex = re.match(r"(?:FUN_|sym_)([0-9A-Fa-f]+)", label)
                    if addr_hex:
                        try:
                            addr = int(addr_hex.group(1), 16)
                            addr_to_name[addr] = label
                        except ValueError:
                            pass

                # Also find "; Entry: XXXXXXXX" headers
                for em in entry_pattern.finditer(content):
                    try:
                        addr = int(em.group(1), 16)
                        if addr not in addr_to_name:
                            addr_to_name[addr] = f"FUN_{em.group(1)}"
                    except ValueError:
                        pass

        return cls(addr_to_name)

    @classmethod
    def from_map_file(cls, map_path):
        """Build a function table from a linker map file."""
        addr_to_name = {}
        if not os.path.exists(map_path):
            return cls()
        with open(map_path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    raw = parts[0]
                    if raw.startswith("0x") or raw.startswith("0X"):
                        raw = raw[2:]
                    try:
                        addr = int(raw, 16)
                        addr_to_name[addr] = parts[1]
                    except ValueError:
                        pass
        return cls(addr_to_name)

    def name_at(self, addr):
        """Find the function containing this address.

        Returns the function name if the address is within MAX_FUNCTION_SIZE
        of a known function start. Otherwise returns a hex string.
        """
        if isinstance(addr, str):
            try:
                addr = int(addr.replace("0x", "").replace("0X", ""), 16)
            except ValueError:
                return f"0x{addr}"
        idx = bisect.bisect_right(self.addrs, addr) - 1
        if idx >= 0:
            offset = addr - self.addrs[idx]
            if offset <= self.MAX_FUNCTION_SIZE:
                return self.names[idx]
        return f"0x{addr:08X}"


def _normalize_addr(hex_str):
    """Normalize a hex address string to consistent uppercase format."""
    try:
        val = int(hex_str, 16)
        return f"0x{val:08X}"
    except ValueError:
        return f"0x{hex_str}"


def analyze_calls(raw_calls, ftable=None, master_only=True):
    """Analyze raw call trace into structured edge data."""
    edges = Counter()
    functions = set()
    callers_of = defaultdict(set)
    callees_of = defaultdict(set)

    for _, cpu, caller_hex, target_hex in raw_calls:
        if master_only and cpu != "M":
            continue

        if ftable and len(ftable.addrs) > 0:
            caller_name = ftable.name_at(caller_hex)
            target_name = ftable.name_at(target_hex)
        else:
            # Normalize to consistent format when no symbol table
            caller_name = _normalize_addr(caller_hex)
            target_name = _normalize_addr(target_hex)

        edge = (caller_name, target_name)
        edges[edge] += 1
        functions.add(caller_name)
        functions.add(target_name)
        callers_of[target_name].add(caller_name)
        callees_of[caller_name].add(target_name)

    # Find roots: functions that call others but aren't called
    all_callers = set(callees_of.keys())
    all_callees = set(callers_of.keys())
    roots = all_callers - all_callees

    # If no roots (pure cycles), pick the highest-call-count function
    if not roots and edges:
        func_counts = Counter()
        for (caller, _), count in edges.items():
            func_counts[caller] += count
        roots = {func_counts.most_common(1)[0][0]}

    return {
        "edges": dict(edges),
        "functions": functions,
        "callers_of": dict(callers_of),
        "callees_of": dict(callees_of),
        "roots": roots,
    }


def format_tree(analysis):
    """Format the call graph as an ASCII tree string."""
    edges = analysis["edges"]
    roots = analysis["roots"]

    if not edges:
        return "(empty call graph)"

    # Build adjacency list sorted by call count (most called first)
    children = defaultdict(list)
    for (caller, callee), count in edges.items():
        children[caller].append((callee, count))
    for k in children:
        children[k].sort(key=lambda x: -x[1])

    lines = []
    visited = set()

    def _render(node, count=0, prefix="", is_last=True, depth=0):
        """Render a node and all its descendants recursively."""
        # Build this node's line
        if depth == 0:
            # Root node — no connector
            lines.append(node)
        else:
            connector = "`-- " if is_last else "|-- "
            count_str = f" (x{count})" if count > 1 else ""
            if node in visited:
                lines.append(f"{prefix}{connector}{node}{count_str} (*)")
                return
            lines.append(f"{prefix}{connector}{node}{count_str}")

        visited.add(node)

        # Render children
        kids = children.get(node, [])
        for i, (child, child_count) in enumerate(kids):
            is_child_last = (i == len(kids) - 1)
            if depth == 0:
                child_prefix = "    "
            else:
                child_prefix = prefix + ("    " if is_last else "|   ")
            _render(child, child_count, child_prefix, is_child_last, depth + 1)

    for i, root in enumerate(sorted(roots)):
        if i > 0:
            lines.append("")
        _render(root, depth=0)

    return "\n".join(lines)


def format_edge_list(analysis):
    """Format edges as a sorted list with counts."""
    lines = []
    for (caller, callee), count in sorted(
        analysis["edges"].items(), key=lambda x: -x[1]
    ):
        count_str = f"  (x{count})" if count > 1 else ""
        lines.append(f"  {caller} -> {callee}{count_str}")
    return "\n".join(lines)


def diff_analyses(baseline, with_input):
    """Compare two call graph analyses. Returns new and increased edges."""
    new_edges = {}
    increased = {}

    for edge, count in with_input["edges"].items():
        base_count = baseline["edges"].get(edge, 0)
        if count > base_count:
            if base_count == 0:
                new_edges[edge] = count
            else:
                increased[edge] = (count, base_count)

    gone_edges = {}
    for edge, count in baseline["edges"].items():
        if edge not in with_input["edges"]:
            gone_edges[edge] = count

    return {
        "new": new_edges,
        "increased": increased,
        "gone": gone_edges,
    }


def cross_reference(scenario_analyses):
    """Cross-reference multiple scenario analyses."""
    if not scenario_analyses:
        return {"common": set(), "unique": {}}

    all_edge_sets = {
        label: set(a["edges"].keys())
        for label, a in scenario_analyses.items()
    }

    common = set.intersection(*all_edge_sets.values())

    unique = {}
    for label, edges in all_edge_sets.items():
        others = set()
        for other_label, other_edges in all_edge_sets.items():
            if other_label != label:
                others |= other_edges
        unique[label] = edges - others

    all_edges = set()
    for edges in all_edge_sets.values():
        all_edges |= edges

    func_scenarios = defaultdict(set)
    for label, a in scenario_analyses.items():
        for func in a["functions"]:
            func_scenarios[func].add(label)

    return {
        "common": common,
        "unique": unique,
        "all_edges": all_edges,
        "func_scenarios": dict(func_scenarios),
    }


def find_gaps(analysis, observations_dir):
    """Find functions in the call graph that have no observation file.

    Returns list of (function_name, call_count) sorted by call count.
    Checks both callees and callers (root functions that only call others).
    """
    # Count total calls per function (as callee + as caller)
    func_calls = Counter()
    for (caller, callee), count in analysis["edges"].items():
        func_calls[callee] += count
        if caller not in func_calls:
            func_calls[caller] = 0  # ensure roots appear

    # Check which have observations
    observed = set()
    if os.path.exists(observations_dir):
        for f in os.listdir(observations_dir):
            if f.endswith("_obs.md"):
                name = f[:-7]  # strip "_obs.md" (7 chars)
                observed.add(name)

    gaps = []
    for func, count in func_calls.most_common():
        if func not in observed and not func.startswith("0x"):
            gaps.append((func, count))

    return gaps
