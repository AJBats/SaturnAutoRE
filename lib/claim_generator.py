"""Generate claim YAML from observation data.

Replaces the Verifier's reasoning — reads structured observation data
and produces mechanical claims. The agent doesn't need to reason about
what claims to write; this script derives them from the data.
"""

import os
import re
import yaml


def extract_observation_data(obs_path):
    """Parse an observation file into structured data.

    Returns a dict with:
    - function: str
    - address: str
    - address_end: str
    - reachable: bool
    - scenarios_tested: list
    - call_frequency: dict of scenario -> count
    - watchpoint_hits: list of {target, hits, pcs, sample}
    - field_analysis: list of {offset, idle, input, category}
    """
    with open(obs_path) as f:
        content = f.read()

    data = {"raw": content}

    # Parse YAML frontmatter
    fm_match = re.match(r"---\n(.*?)\n---", content, re.DOTALL)
    if fm_match:
        try:
            fm = yaml.safe_load(fm_match.group(1))
            data.update(fm)
        except yaml.YAMLError:
            pass

    # Parse call frequency table
    freq = {}
    freq_match = re.search(
        r"## Call Frequency.*?\n\|.*?\n\|[-\s|]+\n((?:\|.*\n)*)",
        content
    )
    if freq_match:
        for line in freq_match.group(1).strip().split("\n"):
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2:
                try:
                    freq[parts[0]] = int(parts[1])
                except ValueError:
                    pass
    data["call_frequency"] = freq

    # Parse watchpoint hits table
    hits = []
    hits_match = re.search(
        r"## Memory Writes.*?\n\|.*?\n\|[-\s|]+\n((?:\|.*\n)*)",
        content
    )
    if hits_match:
        for line in hits_match.group(1).strip().split("\n"):
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3:
                hits.append({
                    "target": parts[0],
                    "hits": parts[1],
                    "pcs": parts[2],
                    "sample": parts[3] if len(parts) > 3 else "",
                })
    data["watchpoint_hits"] = hits

    # Check for field analysis
    data["has_field_analysis"] = "## Per-Frame Field Analysis" in content
    data["field_analysis_deferred"] = (
        data["has_field_analysis"] and
        ("deferred" in content[content.index("## Per-Frame Field Analysis"):
         content.index("## Per-Frame Field Analysis") + 300].lower())
    )

    return data


def generate_claims(obs_data, config):
    """Generate claim dicts from parsed observation data.

    Returns a list of claim dicts ready to write as YAML.
    Each claim is mechanical — derived directly from observation data.
    """
    claims = []
    func = obs_data.get("function", "")
    addr = obs_data.get("address", "")
    addr_end = obs_data.get("address_end", "")
    scenarios = obs_data.get("scenarios_tested", [])

    if not func or not addr:
        return claims

    # 1. Call count claims — from call frequency table
    for scenario, count in obs_data.get("call_frequency", {}).items():
        # Map observation scenario names to test runner scenario names
        claim = {
            "id": f"call_count_{scenario}",
            "description": f"{func} called {count} times/frame in {scenario}",
            "type": "call_count_per_frame",
            "function": func,
            "address": addr,
            "scenario": scenario,
            "expected_count": count,
            "tolerance": max(1, count // 10),  # 10% tolerance, min 1
        }
        claims.append(claim)

    # 2. writes_to claims — from watchpoint hits
    func_start = int(addr, 16) if isinstance(addr, str) else addr
    func_end_int = int(addr_end, 16) if isinstance(addr_end, str) and addr_end else None

    for hit in obs_data.get("watchpoint_hits", []):
        pcs_str = hit.get("pcs", "")
        # Extract hex PCs from the string
        pcs = re.findall(r"0x([0-9A-Fa-f]+)", pcs_str)
        for pc_hex in pcs:
            pc = int(pc_hex, 16)
            # Check if PC is within function range
            in_range = (pc >= func_start and
                        (func_end_int is None or pc < func_end_int))
            if in_range:
                target = hit.get("target", "unknown")
                # Pick the first tested scenario
                scenario = scenarios[0] if scenarios else "straight_throttle"
                claim = {
                    "id": f"writes_{target.replace('+', '').replace('0x', '')}",
                    "description": f"{func} writes to {target} at PC 0x{pc_hex}",
                    "type": "writes_to",
                    "function": func,
                    "function_end": addr_end,
                    "address": target,
                    "scenario": scenario,
                    "frames": 60,
                }
                claims.append(claim)
                break  # One writes_to claim per target

    return claims


def write_claim_file(claims, obs_data, output_path):
    """Write claims to a YAML file."""
    doc = {
        "function": obs_data.get("function", "unknown"),
        "address": obs_data.get("address", ""),
        "function_end": obs_data.get("address_end", ""),
        "source_file": obs_data.get("source_file", ""),
        "claims": claims,
    }
    with open(output_path, "w") as f:
        yaml.dump(doc, f, default_flow_style=False, sort_keys=False)
