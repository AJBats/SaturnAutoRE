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
    - field_changes: list of {offset, input, direction} (from field analysis)
    """
    with open(obs_path, encoding="utf-8", errors="replace") as f:
        content = f.read()

    data = {}

    # Parse YAML frontmatter
    fm_match = re.match(r"---\n(.*?)\n---", content, re.DOTALL)
    if fm_match:
        try:
            fm = yaml.safe_load(fm_match.group(1))
            if isinstance(fm, dict):
                data.update(fm)
        except yaml.YAMLError:
            pass

    # Parse call frequency table — tolerant of blank lines between heading and table
    freq = {}
    freq_match = re.search(
        r"## Call Frequency.*?\n(?:\s*\n)*(\|.*?\n\|[-\s|]+\n(?:\|.*\n)*)",
        content
    )
    if freq_match:
        table_text = freq_match.group(1)
        for line in table_text.strip().split("\n"):
            if line.startswith("|") and "---" not in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2 and parts[0] not in ("Scenario",):
                    try:
                        freq[parts[0]] = int(parts[1])
                    except ValueError:
                        pass
    data["call_frequency"] = freq

    # Parse watchpoint hits table — tolerant of blank lines
    hits = []
    hits_match = re.search(
        r"## Memory Writes.*?\n(?:\s*\n)*(\|.*?\n\|[-\s|]+\n(?:\|.*\n)*)",
        content
    )
    if hits_match:
        table_text = hits_match.group(1)
        for line in table_text.strip().split("\n"):
            if line.startswith("|") and "---" not in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 3 and parts[0] not in ("Target",):
                    hits.append({
                        "target": parts[0],
                        "hits": parts[1],
                        "pcs": parts[2],
                        "sample": parts[3] if len(parts) > 3 else "",
                    })
    data["watchpoint_hits"] = hits

    # Parse field analysis table for input-responsive fields
    field_changes = []
    fa_match = re.search(
        r"## Per-Frame Field Analysis.*?\n(?:\s*\n)*(\|.*?\n\|[-\s|]+\n(?:\|.*\n)*)",
        content
    )
    if fa_match:
        table_text = fa_match.group(1)
        for line in table_text.strip().split("\n"):
            if line.startswith("|") and "---" not in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 4 and parts[0] not in ("Offset",):
                    offset = parts[0]
                    idle_behavior = parts[1].lower() if len(parts) > 1 else ""
                    input_behavior = parts[2].lower() if len(parts) > 2 else ""
                    category = parts[3].lower() if len(parts) > 3 else ""

                    if "input-responsive" in category or "monotonic" in category:
                        # Determine direction
                        direction = None
                        if "increase" in input_behavior or "monotonic_up" in input_behavior:
                            direction = "increases"
                        elif "decrease" in input_behavior or "monotonic_down" in input_behavior:
                            direction = "decreases"
                        elif "changing" in input_behavior and "static" in idle_behavior:
                            direction = "increases"  # default assumption for active-vs-static

                        if direction:
                            field_changes.append({
                                "offset": offset,
                                "direction": direction,
                                "idle": idle_behavior,
                                "input": input_behavior,
                            })
    data["field_changes"] = field_changes

    # Check for field analysis presence
    data["has_field_analysis"] = "## Per-Frame Field Analysis" in content
    if data["has_field_analysis"]:
        idx = content.index("## Per-Frame Field Analysis")
        first_200 = content[idx:idx + 200].lower()
        data["field_analysis_deferred"] = (
            "deferred" in first_200 or
            bool(re.search(r'\bn/a\b', first_200))
        )
    else:
        data["field_analysis_deferred"] = True

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

    # Validate address is parseable
    try:
        if isinstance(addr, str):
            int(addr, 16)
    except ValueError:
        return claims

    # Determine default scenario from config or observation
    config_scenarios = list(config.get("save_states", {}).keys())
    if scenarios:
        default_scenario = scenarios[0]
    elif config_scenarios:
        default_scenario = config_scenarios[0]
    else:
        default_scenario = None

    # 1. Call count claims — from call frequency table
    for scenario, count in obs_data.get("call_frequency", {}).items():
        claim = {
            "id": f"call_count_{scenario}",
            "description": f"{func} called {count} times/frame in {scenario}",
            "type": "call_count_per_frame",
            "function": func,
            "address": addr,
            "scenario": scenario,
            "expected_count": count,
            "tolerance": max(1, count // 10),
        }
        claims.append(claim)

    # 2. writes_to claims — from watchpoint hits
    func_start = int(addr, 16) if isinstance(addr, str) else addr
    func_end_int = int(addr_end, 16) if isinstance(addr_end, str) and addr_end else None

    for hit in obs_data.get("watchpoint_hits", []):
        pcs_str = hit.get("pcs", "")
        pcs = re.findall(r"0x([0-9A-Fa-f]+)", pcs_str)
        for pc_hex in pcs:
            pc = int(pc_hex, 16)
            in_range = (pc >= func_start and
                        (func_end_int is None or pc < func_end_int))
            if in_range and default_scenario:
                target = hit.get("target", "unknown")
                claim = {
                    "id": f"writes_{target.replace('+', '').replace('0x', '').replace('[', '').replace(']', '')}",
                    "description": f"{func} writes to {target} at PC 0x{pc_hex}",
                    "type": "writes_to",
                    "function": func,
                    "function_end": addr_end,
                    "address": target,
                    "scenario": default_scenario,
                    "frames": 60,
                }
                claims.append(claim)
                break  # One writes_to claim per target

    # 3. value_changes_with_input claims — from field analysis
    # Determine which button to test with: use the first input from the
    # default scenario, or fall back to the first control in the config
    scenario_inputs = config.get("save_states", {}).get(default_scenario, {}).get("inputs", []) if default_scenario else []
    if scenario_inputs:
        test_button = scenario_inputs[0]  # first button held in the scenario
    else:
        controls = config.get("controls", {})
        test_button = next(iter(controls.values()), "") if controls else ""

    for fc in obs_data.get("field_changes", []):
        offset_str = fc.get("offset", "")
        direction = fc.get("direction")
        if not offset_str or not direction or not test_button:
            continue
        if not default_scenario:
            continue

        # Resolve offset to absolute address
        targets = config.get("targets", {})
        base_addr = 0
        for t in targets.values():
            base = t.get("base", 0)
            if isinstance(base, str):
                base = int(base, 16)
            if base > 0:
                base_addr = base
                break

        if base_addr == 0:
            continue

        # Parse offset like "+0x0C" or "0x0C"
        offset_clean = offset_str.replace("+", "").strip()
        try:
            offset_val = int(offset_clean, 16)
        except ValueError:
            continue

        abs_addr = f"0x{base_addr + offset_val:08X}"

        claim = {
            "id": f"field_{offset_clean}_changes_{direction}",
            "description": f"{offset_str} {direction} with {test_button} held",
            "type": "value_changes_with_input",
            "address": abs_addr,
            "input": test_button,
            "direction": direction,
            "scenario": default_scenario,
            "frames": 60,
        }
        claims.append(claim)

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
