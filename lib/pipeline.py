"""Pipeline state derived from filesystem.

No separate state file — everything comes from observations/, claims/,
results.tsv, and explorer_priorities.md.
"""

import os
import re
import yaml


# Observation files must match these patterns to be treated as function
# observations. This filters out non-function observations like
# "brake_scenario_obs.md" or "collision_detection_obs.md".
FUNCTION_OBS_PATTERN = re.compile(r"^(FUN_|sym_)[0-9A-Fa-f]+$")


def _is_function_name(name):
    """Check if a name looks like a function (FUN_XXXXXXXX or sym_XXXXXXXX)."""
    return bool(FUNCTION_OBS_PATTERN.match(name))


def scan_observations(auto_re_dir, functions_only=True):
    """Return dict of function -> observation file path.

    If functions_only is True (default), only return entries that look like
    function names (FUN_* or sym_*). Non-function observations like
    "brake_scenario_obs.md" are excluded from pipeline tracking.
    """
    obs_dir = os.path.join(auto_re_dir, "observations")
    if not os.path.exists(obs_dir):
        return {}
    result = {}
    for f in os.listdir(obs_dir):
        if f.endswith("_obs.md"):
            name = f.replace("_obs.md", "")
            if functions_only and not _is_function_name(name):
                continue
            result[name] = os.path.join(obs_dir, f)
    return result


def scan_claims(auto_re_dir):
    """Return dict of function -> claim file path."""
    claims_dir = os.path.join(auto_re_dir, "claims")
    if not os.path.exists(claims_dir):
        return {}
    result = {}
    for f in os.listdir(claims_dir):
        if f.endswith(".yaml"):
            func = f.replace(".yaml", "")
            result[func] = os.path.join(claims_dir, f)
    return result


def scan_questions(auto_re_dir):
    """Return dict of function -> question file path.

    Filters out questions that have a corresponding _answers.md file,
    since those have been addressed by the Explorer.
    """
    obs_dir = os.path.join(auto_re_dir, "observations")
    if not os.path.exists(obs_dir):
        return {}
    result = {}
    for f in os.listdir(obs_dir):
        if f.endswith("_questions.md"):
            func = f.replace("_questions.md", "")
            # Check if an answers file exists — if so, question is resolved
            answers_file = os.path.join(obs_dir, f"{func}_answers.md")
            if os.path.exists(answers_file):
                continue
            # Also check if the observation has a ## Follow-Up section
            obs_file = os.path.join(obs_dir, f"{func}_obs.md")
            if os.path.exists(obs_file):
                try:
                    with open(obs_file, encoding="utf-8", errors="replace") as fh:
                        if "## Follow-Up" in fh.read():
                            continue
                except (IOError, OSError):
                    pass
            result[func] = os.path.join(obs_dir, f)
    return result


def parse_results(results_path):
    """Parse results.tsv into list of dicts."""
    if not os.path.exists(results_path):
        return []
    results = []
    with open(results_path) as f:
        header = None
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if header is None:
                header = parts
                continue
            row = {}
            for i, col in enumerate(header):
                row[col] = parts[i] if i < len(parts) else ""
            results.append(row)
    return results


def _observation_is_unreachable(content):
    """Check if an observation's YAML frontmatter marks it as unreachable."""
    fm_match = re.match(r"---\n(.*?)\n---", content, re.DOTALL)
    if fm_match:
        # Quick check without full YAML parse
        if "reachable: false" in fm_match.group(1).lower():
            return True
    # Also check for "unreachable" in the field analysis section itself
    if "## Per-Frame Field Analysis" in content:
        idx = content.index("## Per-Frame Field Analysis")
        section = content[idx:idx + 300].lower()
        if "unreachable" in section:
            return True
    return False


def observation_has_field_analysis(obs_path):
    """Check if an observation file has a populated Per-Frame Field Analysis.

    Returns True if:
    - The function is unreachable (N/A is the correct analysis)
    - The field analysis section has actual data rows with field offsets
    """
    try:
        with open(obs_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (IOError, OSError):
        return False

    # Unreachable functions don't need field analysis — the observation
    # that they're unreachable IS the finding
    if _observation_is_unreachable(content):
        return True

    if "## Per-Frame Field Analysis" not in content:
        return False

    idx = content.index("## Per-Frame Field Analysis")
    # Find the next ## heading to bound the section
    next_heading = content.find("\n## ", idx + 1)
    if next_heading == -1:
        section = content[idx:]
    else:
        section = content[idx:next_heading]

    section_lower = section.lower()

    # Check for explicit deferral
    first_200 = section_lower[:200]
    if "deferred" in first_200:
        return False

    # N/A is valid IF the function is unreachable (handled above).
    # For reachable functions, N/A means the analysis was skipped.
    if re.search(r'\bn/a\b', first_200):
        return False

    # Check for actual data rows — need at least one pipe-delimited row
    # that isn't a header or separator. A data row has content between pipes
    # that isn't just dashes/spaces.
    lines = section.split("\n")
    data_rows = 0
    for line in lines:
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if not cells:
            continue
        # Skip header separator rows (all dashes)
        if all(re.match(r"^[-:]+$", c) for c in cells):
            continue
        # Skip header rows (check if any cell looks like a field offset)
        if any(re.match(r"^\+?0x[0-9A-Fa-f]+", c) for c in cells):
            data_rows += 1
        elif any(c[0].isdigit() or c.startswith("+") for c in cells if c):
            data_rows += 1

    return data_rows > 0


def get_function_status(func, auto_re_dir, results_path):
    """Get the pipeline status of a function.

    Returns one of:
    - "unexplored"  — no observation file
    - "explored"    — observation exists with field analysis, no claims
    - "incomplete"  — observation missing field analysis
    - "claimed"     — claims written but not yet tested
    - "verified"    — claims exist and have been tested
    - "questioned"  — verifier filed a question (unanswered)
    """
    observations = scan_observations(auto_re_dir)
    claims = scan_claims(auto_re_dir)
    questions = scan_questions(auto_re_dir)
    results = parse_results(results_path)

    if func in questions:
        return "questioned"

    result_funcs = {r.get("function", ""): r for r in results}
    if func in result_funcs:
        return "verified"

    if func in claims:
        return "claimed"

    if func in observations:
        obs_path = observations[func]
        if observation_has_field_analysis(obs_path):
            return "explored"
        else:
            return "incomplete"

    return "unexplored"


def pipeline_summary(auto_re_dir, results_path):
    """Return a summary dict of pipeline state."""
    observations = scan_observations(auto_re_dir)
    claims = scan_claims(auto_re_dir)
    questions = scan_questions(auto_re_dir)
    results = parse_results(results_path)

    # Tier distribution
    tiers = {0: 0, 1: 0, 2: 0}
    for r in results:
        try:
            tier = int(r.get("tier", 0))
            tiers[tier] = tiers.get(tier, 0) + 1
        except ValueError:
            pass

    # Incomplete observations (missing field analysis)
    # Exclude functions that already have results — they went through
    # verification under a prior workflow and shouldn't block new work
    result_funcs = {r.get("function", "") for r in results}
    incomplete = []
    for func, path in observations.items():
        if func in result_funcs:
            continue  # already verified, don't block on field analysis
        if not observation_has_field_analysis(path):
            incomplete.append(func)

    # Functions explored but not verified (and not claimed)
    result_funcs = {r.get("function", "") for r in results}
    explored_not_verified = [
        f for f in observations
        if f not in result_funcs and f not in claims
    ]

    # Functions with claims but no results (claimed but untested)
    claimed_not_tested = [
        f for f in claims
        if f not in result_funcs
    ]

    return {
        "observations": len(observations),
        "claims": len(claims),
        "results": len(results),
        "questions": len(questions),
        "tiers": tiers,
        "incomplete_observations": incomplete,
        "explored_not_verified": explored_not_verified,
        "claimed_not_tested": claimed_not_tested,
    }
