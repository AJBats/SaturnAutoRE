"""Call graph capture and analysis.

Captures per-frame call traces from Mednafen, parses them into
caller→callee edges, builds trees, and produces differential analysis
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
                calls.append((parts[0], parts[1], parts[2], parts[3]))
    return calls


class FunctionTable:
    """Fast address-to-function lookup using sorted array + bisect."""

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
        """Build a function table from assembly source filenames.

        Expects files named like FUN_06012345.s or sym_06012345.s.
        Each filename maps to a function at that address.
        """
        addr_to_name = {}
        if not asm_dir or not os.path.exists(asm_dir):
            return cls()
        for f in os.listdir(asm_dir):
            if not f.endswith(".s"):
                continue
            name = f[:-2]  # strip .s
            # Extract address from filename
            m = re.match(r"(?:FUN_|sym_|)([0-9A-Fa-f]{6,8})", name)
            if m:
                try:
                    addr = int(m.group(1), 16)
                    addr_to_name[addr] = name
                except ValueError:
                    pass
        return cls(addr_to_name)

    @classmethod
    def from_map_file(cls, map_path):
        """Build a function table from a linker map file.

        Parses lines like: 0x06012345 function_name
        """
        addr_to_name = {}
        if not os.path.exists(map_path):
            return cls()
        with open(map_path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        addr = int(parts[0].replace("0x", ""), 16)
                        addr_to_name[addr] = parts[1]
                    except ValueError:
                        pass
        return cls(addr_to_name)

    def name_at(self, addr):
        """Find the function containing this address."""
        if isinstance(addr, str):
            addr = int(addr.replace("0x", ""), 16)
        idx = bisect.bisect_right(self.addrs, addr) - 1
        if idx >= 0:
            return self.names[idx]
        return f"0x{addr:08X}"


def analyze_calls(raw_calls, ftable=None, master_only=True):
    """Analyze raw call trace into structured edge data.

    Returns dict with edges, functions, callers_of, callees_of, roots.
    """
    edges = Counter()
    functions = set()
    callers_of = defaultdict(set)
    callees_of = defaultdict(set)

    for _, cpu, caller_hex, target_hex in raw_calls:
        if master_only and cpu != "M":
            continue

        if ftable:
            caller_name = ftable.name_at(caller_hex)
            target_name = ftable.name_at(target_hex)
        else:
            caller_name = f"0x{caller_hex}"
            target_name = f"0x{target_hex}"

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

    # Build adjacency list
    children = defaultdict(list)
    for (caller, callee), count in sorted(edges.items()):
        children[caller].append((callee, count))

    # Sort children by count (most called first)
    for k in children:
        children[k].sort(key=lambda x: -x[1])

    lines = []
    visited = set()

    def _render(node, prefix="", is_last=True):
        if node in visited:
            lines.append(f"{prefix}{'`-- ' if is_last else '|-- '}{node} (recursive)")
            return
        visited.add(node)

        connector = "`-- " if is_last else "|-- "
        lines.append(f"{prefix}{connector}{node}")

        kids = children.get(node, [])
        for i, (child, count) in enumerate(kids):
            is_child_last = (i == len(kids) - 1)
            child_prefix = prefix + ("    " if is_last else "|   ")
            count_str = f" (x{count})" if count > 1 else ""

            if child in visited:
                child_connector = "`-- " if is_child_last else "|-- "
                lines.append(f"{child_prefix}{child_connector}{child}{count_str} (recursive)")
            else:
                visited.add(child)
                child_connector = "`-- " if is_child_last else "|-- "
                lines.append(f"{child_prefix}{child_connector}{child}{count_str}")

                grandkids = children.get(child, [])
                for j, (gc, gc_count) in enumerate(grandkids):
                    is_gc_last = (j == len(grandkids) - 1)
                    gc_prefix = child_prefix + ("    " if is_child_last else "|   ")
                    _render(gc, gc_prefix, is_gc_last)

    for i, root in enumerate(sorted(roots)):
        if i > 0:
            lines.append("")
        lines.append(root)
        kids = children.get(root, [])
        for j, (child, count) in enumerate(kids):
            is_last_child = (j == len(kids) - 1)
            count_str = f" (x{count})" if count > 1 else ""
            if child in visited:
                connector = "`-- " if is_last_child else "|-- "
                lines.append(f"    {connector}{child}{count_str} (recursive)")
            else:
                visited.add(child)
                connector = "`-- " if is_last_child else "|-- "
                lines.append(f"    {connector}{child}{count_str}")
                grandkids = children.get(child, [])
                for k, (gc, gc_count) in enumerate(grandkids):
                    is_gc_last = (k == len(grandkids) - 1)
                    _render(gc, "    " + ("    " if is_last_child else "|   "), is_gc_last)

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
    """Cross-reference multiple scenario analyses.

    scenario_analyses: dict of label -> analysis dict
    Returns common core edges and per-scenario unique edges.
    """
    if not scenario_analyses:
        return {"common": set(), "unique": {}}

    all_edge_sets = {
        label: set(a["edges"].keys())
        for label, a in scenario_analyses.items()
    }

    # Common core: edges in ALL scenarios
    common = set.intersection(*all_edge_sets.values()) if all_edge_sets else set()

    # Unique per scenario
    unique = {}
    for label, edges in all_edge_sets.items():
        others = set()
        for other_label, other_edges in all_edge_sets.items():
            if other_label != label:
                others |= other_edges
        unique[label] = edges - others

    # All edges
    all_edges = set()
    for edges in all_edge_sets.values():
        all_edges |= edges

    # Function reach: which scenarios call each function
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
    """
    # Count total calls per function (as callee)
    func_calls = Counter()
    for (caller, callee), count in analysis["edges"].items():
        func_calls[callee] += count

    # Check which have observations
    observed = set()
    if os.path.exists(observations_dir):
        for f in os.listdir(observations_dir):
            if f.endswith("_obs.md"):
                observed.add(f.replace("_obs.md", ""))

    gaps = []
    for func, count in func_calls.most_common():
        if func not in observed and not func.startswith("0x"):
            gaps.append((func, count))

    return gaps
