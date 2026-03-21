"""Pipeline state derived from filesystem.

No separate state file — everything comes from observations/, claims/,
results.tsv, and explorer_priorities.md.
"""

import os
import re
import yaml


def scan_observations(auto_re_dir):
    """Return dict of function -> observation file path."""
    obs_dir = os.path.join(auto_re_dir, "observations")
    if not os.path.exists(obs_dir):
        return {}
    result = {}
    for f in os.listdir(obs_dir):
        if f.endswith("_obs.md"):
            func = f.replace("_obs.md", "")
            result[func] = os.path.join(obs_dir, f)
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
    """Return dict of function -> question file path."""
    obs_dir = os.path.join(auto_re_dir, "observations")
    if not os.path.exists(obs_dir):
        return {}
    result = {}
    for f in os.listdir(obs_dir):
        if f.endswith("_questions.md"):
            func = f.replace("_questions.md", "")
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


def observation_has_field_analysis(obs_path):
    """Check if an observation file has a Per-Frame Field Analysis table."""
    with open(obs_path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    if "## Per-Frame Field Analysis" not in content:
        return False
    # Check it's not just "deferred" or "N/A"
    idx = content.index("## Per-Frame Field Analysis")
    section = content[idx:idx + 500]
    if "deferred" in section.lower() or "n/a" in section.lower()[:100]:
        return False
    # Check for at least one table row (pipe-delimited)
    return bool(re.search(r"\|.*\|.*\|.*\|", section))


def get_function_status(func, auto_re_dir, results_path):
    """Get the pipeline status of a function.

    Returns one of:
    - "unexplored"  — no observation file
    - "explored"    — observation exists, no claims
    - "incomplete"  — observation missing field analysis
    - "verified"    — claims exist and have been tested
    - "questioned"  — verifier filed a question
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
        return "claimed"  # claims written but not yet tested

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
    incomplete = []
    for func, path in observations.items():
        if not observation_has_field_analysis(path):
            incomplete.append(func)

    # Functions explored but not verified
    result_funcs = {r.get("function", "") for r in results}
    explored_not_verified = [f for f in observations if f not in result_funcs and f not in claims]

    return {
        "observations": len(observations),
        "claims": len(claims),
        "results": len(results),
        "questions": len(questions),
        "tiers": tiers,
        "incomplete_observations": incomplete,
        "explored_not_verified": explored_not_verified,
    }
