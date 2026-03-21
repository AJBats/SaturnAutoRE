#!/usr/bin/env python3
"""auto_re — Autonomous RE pipeline CLI.

Run from a project directory that has workstreams/auto_re/config.yaml.
Reads project state from the filesystem and tells the agent what to do next.

Usage:
    python /path/to/SaturnAutoRE/auto_re.py status
    python /path/to/SaturnAutoRE/auto_re.py pick
    python /path/to/SaturnAutoRE/auto_re.py explore-check FUN_0602D814
    python /path/to/SaturnAutoRE/auto_re.py verify FUN_0602D814
    python /path/to/SaturnAutoRE/auto_re.py integrate
"""

import os
import sys
import argparse

# Add our lib to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from lib.config import load_config, get_button, get_car_struct_base, get_assembly_dir
from lib.pipeline import (
    scan_observations, scan_claims, scan_questions, parse_results,
    pipeline_summary, get_function_status, observation_has_field_analysis,
)
from lib.claim_generator import extract_observation_data, generate_claims, write_claim_file


def cmd_status(config):
    """Show pipeline status and what to do next."""
    auto_re_dir = config["_auto_re_dir"]
    results_path = config["_results_path"]

    summary = pipeline_summary(auto_re_dir, results_path)
    observations = scan_observations(auto_re_dir)
    questions = scan_questions(auto_re_dir)

    print(f"=== {config.get('game_name', 'Unknown Game')} — auto_re status ===")
    print()
    print(f"Observations:  {summary['observations']}")
    print(f"Claims:        {summary['claims']}")
    print(f"Results:       {summary['results']}")
    print(f"Questions:     {summary['questions']}")
    print()
    print(f"Tier 0: {summary['tiers'].get(0, 0)}")
    print(f"Tier 1: {summary['tiers'].get(1, 0)}")
    print(f"Tier 2: {summary['tiers'].get(2, 0)}")

    if summary["incomplete_observations"]:
        print()
        print(f"INCOMPLETE observations (missing field analysis):")
        for func in summary["incomplete_observations"]:
            print(f"  - {func}")

    if summary["explored_not_verified"]:
        print()
        print(f"Explored but not verified:")
        for func in summary["explored_not_verified"]:
            print(f"  - {func}")

    if questions:
        print()
        print(f"Pending questions (answer before new exploration):")
        for func in questions:
            print(f"  - {func}")

    # What to do next
    print()
    print("--- NEXT ACTION ---")
    print()

    if questions:
        func = list(questions.keys())[0]
        print(f"Answer the Verifier's question for {func}.")
        print(f"Read: workstreams/auto_re/observations/{func}_questions.md")
        print(f"Then re-investigate with the debugger and append a ## Follow-Up section.")
        print()
        print(f"Next, run: auto_re.py explore-check {func}")
    elif summary["incomplete_observations"]:
        func = summary["incomplete_observations"][0]
        print(f"Complete the observation for {func} — field analysis is missing.")
        print(f"Read the sample CSVs in build/samples/ and classify field behavior.")
        print()
        print(f"Next, run: auto_re.py explore-check {func}")
    elif summary["explored_not_verified"]:
        func = summary["explored_not_verified"][0]
        print(f"Verify {func} — observation exists but no claims tested.")
        print()
        print(f"Next, run: auto_re.py verify {func}")
    else:
        print(f"All current observations are verified. Pick a new function to explore.")
        print()
        print(f"Next, run: auto_re.py pick")


def cmd_pick(config):
    """Pick the next function to investigate."""
    auto_re_dir = config["_auto_re_dir"]
    priorities_path = config["_priorities_path"]
    mission_path = config["_mission_path"]
    asm_dir = get_assembly_dir(config)

    print(f"=== {config.get('game_name', 'Unknown Game')} — pick next target ===")
    print()

    # Check for mission context
    if os.path.exists(mission_path):
        with open(mission_path) as f:
            mission = f.read().strip()
        if mission:
            print(f"Current mission (from mission.md):")
            # Show first 5 lines
            for line in mission.split("\n")[:5]:
                print(f"  {line}")
            print()

    # Check for priorities file
    if os.path.exists(priorities_path):
        with open(priorities_path) as f:
            priorities = f.read()
        # Find first unresolved priority
        lines = priorities.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("### ") and "RESOLVED" not in line:
                # Found an active priority
                # Gather the block until next ### or ##
                block = [line]
                for j in range(i + 1, min(i + 20, len(lines))):
                    if lines[j].startswith("### ") or lines[j].startswith("## "):
                        break
                    block.append(lines[j])
                print("PRIORITY from explorer_priorities.md:")
                print()
                for bl in block:
                    print(f"  {bl}")
                print()
                print(f"Investigate this function using the debugger. When done, write the")
                print(f"observation report to workstreams/auto_re/observations/")
                print()
                print(f"Next, run: auto_re.py explore-check <FUNCTION_NAME>")
                return

    # No priorities — suggest assembly dir scan
    print(f"No active priorities found. Explore by call-chain or CDL coverage.")
    print(f"Assembly source: {asm_dir}")
    print()

    # Show controls for reference
    controls = config.get("controls", {})
    if controls:
        ctrl_str = ", ".join(f"{role}={btn}" for role, btn in controls.items())
        print(f"Game controls: {ctrl_str}")
    print()
    print(f"After investigating a function, write the observation report and run:")
    print(f"  auto_re.py explore-check <FUNCTION_NAME>")


def cmd_explore_check(config, func_name):
    """Validate an observation file before moving to verification."""
    auto_re_dir = config["_auto_re_dir"]
    obs_path = os.path.join(auto_re_dir, "observations", f"{func_name}_obs.md")

    print(f"=== Checking observation: {func_name} ===")
    print()

    if not os.path.exists(obs_path):
        print(f"FAIL: No observation file found at:")
        print(f"  {obs_path}")
        print()
        print(f"Write the observation report first, then run this check again.")
        return

    # Check required sections
    with open(obs_path) as f:
        content = f.read()

    checks = {
        "YAML frontmatter": content.startswith("---"),
        "Call Frequency": "## Call Frequency" in content,
        "Register Context": "## Register Context" in content,
        "Memory Writes": "## Memory Writes" in content,
        "Per-Frame Field Analysis": "## Per-Frame Field Analysis" in content,
        "Field analysis populated": observation_has_field_analysis(obs_path),
    }

    all_pass = True
    for check, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {check}")
        if not passed:
            all_pass = False

    print()

    if not all_pass:
        print(f"Observation is INCOMPLETE. Fix the failing checks above.")
        print()
        if not checks["Per-Frame Field Analysis"]:
            print(f"The Per-Frame Field Analysis section is required. Read the sample")
            print(f"CSVs in build/samples/ and classify each field this function touches.")
        if not checks["Field analysis populated"]:
            print(f"The Per-Frame Field Analysis section exists but appears empty or deferred.")
            print(f"Fill in the behavior classification table with data from the CSVs.")
        print()
        print(f"After fixing, run: auto_re.py explore-check {func_name}")
    else:
        print(f"Observation is COMPLETE. Ready for verification.")
        print()
        print(f"Next, run: auto_re.py verify {func_name}")


def cmd_verify(config, func_name):
    """Generate claims from observation and run oracle."""
    auto_re_dir = config["_auto_re_dir"]
    obs_path = os.path.join(auto_re_dir, "observations", f"{func_name}_obs.md")
    claim_path = os.path.join(auto_re_dir, "claims", f"{func_name}.yaml")
    results_path = config["_results_path"]

    print(f"=== Verify: {func_name} ===")
    print()

    if not os.path.exists(obs_path):
        print(f"FAIL: No observation file for {func_name}.")
        print(f"Run: auto_re.py explore-check {func_name}")
        return

    # Extract observation data
    obs_data = extract_observation_data(obs_path)

    if obs_data.get("field_analysis_deferred"):
        print(f"WARNING: Field analysis is deferred in this observation.")
        print(f"Claims will be limited to call_count only (Tier 1 max).")
        print()

    # Generate claims
    claims = generate_claims(obs_data, config)

    if not claims:
        print(f"No claims could be derived from the observation data.")
        print(f"The observation may need richer data (watchpoints, field analysis).")
        print()
        print(f"Re-investigate and run: auto_re.py explore-check {func_name}")
        return

    print(f"Generated {len(claims)} claim(s):")
    for c in claims:
        print(f"  [{c['id']}] {c['type']}: {c.get('description', '')}")
    print()

    # Write claim file
    os.makedirs(os.path.dirname(claim_path), exist_ok=True)
    write_claim_file(claims, obs_data, claim_path)
    print(f"Claims written to: {claim_path}")
    print()

    # Tell the agent to run the oracle
    test_runner = os.path.join(config["_project_dir"], "tools", "test_claim.py")
    print(f"Now run the oracle to test these claims:")
    print()
    print(f"  python {test_runner} {claim_path} -v")
    print()
    print(f"After the oracle runs, record the results in results.tsv and run:")
    print(f"  auto_re.py integrate")


def cmd_integrate(config):
    """Check results and suggest next steps."""
    auto_re_dir = config["_auto_re_dir"]
    results_path = config["_results_path"]

    print(f"=== Integrate results ===")
    print()

    results = parse_results(results_path)
    if not results:
        print(f"No results in results.tsv yet.")
        print(f"Run: auto_re.py status")
        return

    # Show latest results
    print(f"Latest results ({len(results)} functions tested):")
    print()

    tier_2_count = 0
    tier_1_count = 0
    for r in results:
        tier = r.get("tier", "?")
        func = r.get("function", "?")
        passed = r.get("passed", "?")
        total = r.get("total", "?")
        print(f"  {func}: {passed}/{total} passed — Tier {tier}")
        try:
            if int(tier) >= 2:
                tier_2_count += 1
            elif int(tier) == 1:
                tier_1_count += 1
        except ValueError:
            pass

    print()
    print(f"Summary: {tier_2_count} at Tier 2, {tier_1_count} at Tier 1")

    # Check for Tier 1 functions that might reach Tier 2
    if tier_1_count > 0:
        print()
        print(f"{tier_1_count} function(s) at Tier 1 — may need deeper observation")
        print(f"for function-specific claims (writes_to, value_changes_with_input).")

    # Suggest struct map update
    struct_map = config.get("struct_map_path")
    if struct_map:
        print()
        print(f"Update the struct map with any new confirmed writers:")
        print(f"  {struct_map}")

    print()
    print(f"--- NEXT ACTION ---")
    print()
    print(f"Run: auto_re.py status")
    print(f"to see what needs doing next.")


def main():
    parser = argparse.ArgumentParser(
        description="auto_re — Autonomous RE pipeline CLI",
        epilog="Run from a project directory with workstreams/auto_re/config.yaml",
    )
    parser.add_argument(
        "--project", "-p", default=None,
        help="Project directory (default: current directory)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Show pipeline status and next action")
    sub.add_parser("pick", help="Pick the next function to investigate")

    explore_check = sub.add_parser("explore-check", help="Validate an observation")
    explore_check.add_argument("function", help="Function name (e.g. FUN_0602D814)")

    verify = sub.add_parser("verify", help="Generate claims and run oracle")
    verify.add_argument("function", help="Function name (e.g. FUN_0602D814)")

    sub.add_parser("integrate", help="Check results and suggest next steps")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    config = load_config(args.project)
    if config is None:
        print(f"ERROR: No config.yaml found at workstreams/auto_re/config.yaml")
        print(f"  in {args.project or os.getcwd()}")
        print()
        print(f"Create a config.yaml for your project. See SaturnAutoRE/templates/")
        return 1

    if args.command == "status":
        cmd_status(config)
    elif args.command == "pick":
        cmd_pick(config)
    elif args.command == "explore-check":
        cmd_explore_check(config, args.function)
    elif args.command == "verify":
        cmd_verify(config, args.function)
    elif args.command == "integrate":
        cmd_integrate(config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
