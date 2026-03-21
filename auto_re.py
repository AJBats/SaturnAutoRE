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
import re
import argparse
import yaml

# Add our lib to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from lib.config import load_config, get_assembly_dir, get_controls_display
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

    if summary.get("claimed_not_tested"):
        print()
        print(f"Claims written but NOT YET TESTED (run oracle!):")
        for func in summary["claimed_not_tested"]:
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

    # What to do next — priority order
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
    elif summary.get("claimed_not_tested"):
        func = summary["claimed_not_tested"][0]
        claim_path = os.path.join(auto_re_dir, "claims", f"{func}.yaml")
        test_runner = os.path.join(SCRIPT_DIR, "test_claim.py")
        local_runner = os.path.join(config["_project_dir"], "tools", "test_claim.py")
        if os.path.exists(local_runner):
            test_runner = local_runner
        print(f"Test the untested claims for {func}.")
        print()
        print(f"  python {test_runner} {claim_path} -v")
        print()
        print(f"Record results in results.tsv, then run: auto_re.py integrate")
    elif summary["incomplete_observations"]:
        func = summary["incomplete_observations"][0]
        print(f"Complete the observation for {func} — field analysis is missing.")
        samples_dir = config["_samples_dir"]
        print(f"Read the sample CSVs in {samples_dir}/ and classify field behavior.")
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

    print(f"=== {config.get('game_name', 'Unknown Game')} — pick next target ===")
    print()

    # Check for mission context
    if os.path.exists(mission_path):
        with open(mission_path, encoding="utf-8", errors="replace") as f:
            mission = f.read().strip()
        if mission:
            print(f"Current mission (from mission.md):")
            for line in mission.split("\n")[:5]:
                print(f"  {line}")
            print()

    # Check for priorities file
    if os.path.exists(priorities_path):
        with open(priorities_path, encoding="utf-8", errors="replace") as f:
            priorities = f.read()
        lines = priorities.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("### ") and "RESOLVED" not in line:
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

    # No priorities — give context-aware guidance based on project state
    observations = scan_observations(auto_re_dir)
    asm_dir = get_assembly_dir(config)
    knowledge_base = config.get("_knowledge_base_path", "")

    if len(observations) == 0:
        # Greenfield — no observations yet
        print(f"No priorities and no observations yet. This is a fresh project.")
        print()
        print(f"STEP 1: Do static analysis to identify investigation targets.")
        print(f"  - Read mission.md for the RE objective and phases")
        if asm_dir:
            print(f"  - Read disassembly/source in {asm_dir}")
        print(f"  - Identify 3-5 candidate functions to investigate")
        print(f"  - Consider: what does the mission need? What functions are likely")
        print(f"    to touch the data structures described in the mission?")
        print()
        print(f"STEP 2: Write your targets to explorer_priorities.md")
        print(f"  For each target, document:")
        print(f"  - WHY this function matters for the mission")
        print(f"  - WHAT to do (which breakpoints, watchpoints, scenarios)")
        print(f"  - WHAT it unblocks (what becomes possible after this)")
        print()
        print(f"STEP 3: COMMIT your priorities:")
        print(f"  git add workstreams/auto_re/explorer_priorities.md")
        print(f"  git commit -m \"Set explorer priorities\"")
        print()
        print(f"STEP 4: Run auto_re.py pick again — it will find your priorities.")
        print()
        print(f"Alternatively, if you already know a function to investigate,")
        print(f"go ahead and explore it with the debugger, then run:")
        print(f"  auto_re.py explore-check <FUNCTION_NAME>")
    elif len(observations) < 10:
        # Early stage — some observations but still building up
        print(f"No priorities set. {len(observations)} observations exist.")
        print()
        print(f"Review what's been explored and identify the next best targets:")
        print(f"  1. Read existing observations in workstreams/auto_re/observations/")
        print(f"  2. Follow call chains from observed functions — callees and callers")
        print(f"     are the highest-ROI targets (you already have context)")
        if asm_dir:
            print(f"  3. Read assembly in {asm_dir} to trace data flow from known functions")
        if knowledge_base and os.path.exists(knowledge_base):
            print(f"  4. Check the knowledge base for gaps: {knowledge_base}")
        print()
        print(f"Write your targets to explorer_priorities.md, then run:")
        print(f"  auto_re.py pick")
        print()
        print(f"Or investigate a function directly and run:")
        print(f"  auto_re.py explore-check <FUNCTION_NAME>")
    else:
        # Mature project — many observations, need strategic direction
        print(f"No priorities set. {len(observations)} observations exist.")
        print()
        print(f"Time for strategic analysis:")
        print(f"  1. Re-read mission.md — are we still focused on the objective?")
        if knowledge_base and os.path.exists(knowledge_base):
            print(f"  2. Review the knowledge base for unmapped fields or pipeline gaps:")
            print(f"     {knowledge_base}")
        print(f"  3. Check results.tsv — any Tier 1 functions that could reach Tier 2?")
        print(f"  4. Look for NOP test opportunities — any confirmed writers with")
        print(f"     clear behavioral roles that haven't been NOP-tested?")
        print()
        print(f"Write updated priorities to explorer_priorities.md, then run:")
        print(f"  auto_re.py pick")

    print()
    controls = get_controls_display(config)
    if controls:
        print(f"Game controls: {controls}")


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

    with open(obs_path, encoding="utf-8", errors="replace") as f:
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
        samples_dir = config["_samples_dir"]
        if not checks.get("Per-Frame Field Analysis"):
            print(f"The Per-Frame Field Analysis section is required. Read the sample")
            print(f"CSVs in {samples_dir}/ and classify each field this function touches.")
        if not checks.get("Field analysis populated"):
            print(f"The Per-Frame Field Analysis section exists but appears empty or deferred.")
            print(f"Fill in the behavior classification table with data from the CSVs.")
        print()
        print(f"After fixing, run: auto_re.py explore-check {func_name}")
    else:
        print(f"Observation is COMPLETE. Ready for verification.")
        print()
        print(f"COMMIT your observation now:")
        print(f"  git add workstreams/auto_re/observations/{func_name}_obs.md")
        print(f"  git commit -m \"Add observation for {func_name}\"")
        print()
        print(f"Next, run: auto_re.py verify {func_name}")


def cmd_verify(config, func_name):
    """Generate claims from observation and prepare for oracle testing."""
    auto_re_dir = config["_auto_re_dir"]
    obs_path = os.path.join(auto_re_dir, "observations", f"{func_name}_obs.md")
    claim_path = os.path.join(auto_re_dir, "claims", f"{func_name}.yaml")

    print(f"=== Verify: {func_name} ===")
    print()

    if not os.path.exists(obs_path):
        print(f"FAIL: No observation file for {func_name}.")
        print(f"Run: auto_re.py explore-check {func_name}")
        return

    obs_data = extract_observation_data(obs_path)

    if obs_data.get("field_analysis_deferred"):
        print(f"WARNING: Field analysis is deferred in this observation.")
        print(f"Claims will be limited to call_count only (Tier 1 max).")
        print()

    claims = generate_claims(obs_data, config)

    if not claims:
        print(f"No claims could be derived from the observation data.")
        print(f"The observation may need richer data (watchpoints, field analysis).")
        print()
        print(f"Re-investigate and run: auto_re.py explore-check {func_name}")
        return

    # Show claim summary with types
    type_counts = {}
    for c in claims:
        t = c["type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    print(f"Generated {len(claims)} claim(s):")
    for t, count in type_counts.items():
        print(f"  {t}: {count}")
    print()
    for c in claims:
        print(f"  [{c['id']}] {c['type']}: {c.get('description', '')}")
    print()

    # Write claim file
    os.makedirs(os.path.dirname(claim_path), exist_ok=True)
    write_claim_file(claims, obs_data, claim_path)
    print(f"Claims written to: {claim_path}")
    print()

    # Tell the agent to run the oracle — use central test_claim.py
    test_runner = os.path.join(SCRIPT_DIR, "test_claim.py")
    # Fall back to project-local test_claim.py if it exists
    local_runner = os.path.join(config["_project_dir"], "tools", "test_claim.py")
    if os.path.exists(local_runner):
        test_runner = local_runner
    print(f"Now run the oracle to test these claims:")
    print()
    print(f"  python {test_runner} {claim_path} -v")
    print()
    print(f"After the oracle runs, record results in results.tsv, then COMMIT:")
    print(f"  git add workstreams/auto_re/claims/{func_name}.yaml workstreams/auto_re/results.tsv")
    print(f"  git commit -m \"Verify {func_name}: N/M passed, Tier T\"")
    print()
    print(f"Then run:")
    print(f"  auto_re.py integrate")


def _find_nop_candidates(auto_re_dir, results):
    """Scan results and claims for NOP-test-ready functions.

    A candidate has:
    - Tier 2 (enough evidence to be confident)
    - At least one passing writes_to claim (confirmed writer)
    - No existing NOP test (not already documented)
    """
    candidates = []
    claims_dir = os.path.join(auto_re_dir, "claims")

    # Check for existing NOP experiments file
    nop_file = os.path.join(auto_re_dir, "nop_experiments.md")
    existing_nops = set()
    if os.path.exists(nop_file):
        try:
            with open(nop_file, encoding="utf-8", errors="replace") as f:
                content = f.read()
            # Extract function names mentioned in NOP experiments
            for m in re.findall(r"(FUN_[0-9A-Fa-f]+|sym_[0-9A-Fa-f]+)", content):
                existing_nops.add(m)
        except (IOError, OSError):
            pass

    for r in results:
        func = r.get("function", "")
        try:
            tier = int(r.get("tier", 0))
        except ValueError:
            continue

        if tier < 2:
            continue
        if func in existing_nops:
            continue

        # Check claim file for writes_to claims that passed
        claim_path = os.path.join(claims_dir, f"{func}.yaml")
        if not os.path.exists(claim_path):
            continue

        try:
            with open(claim_path) as f:
                claim_data = yaml.safe_load(f)
        except (yaml.YAMLError, IOError):
            continue

        for claim in claim_data.get("claims", []):
            if claim.get("type") != "writes_to":
                continue

            # Extract target address and writer PC from description
            raw_target = claim.get("address", "unknown")
            # Format target as hex if it's an integer
            if isinstance(raw_target, int):
                target = f"0x{raw_target:08X}"
            else:
                target = str(raw_target)
            writer_pc = None
            desc = claim.get("description", "")
            pc_match = re.search(r"PC\s+0x([0-9A-Fa-f]+)", desc)
            if pc_match:
                writer_pc = f"0x{pc_match.group(1)}"

            candidates.append({
                "function": func,
                "target": target,
                "writer_pc": writer_pc,
                "claim_id": claim.get("id", ""),
            })

    return candidates


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

    print(f"Results ({len(results)} functions tested):")
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

    if tier_1_count > 0:
        print()
        print(f"{tier_1_count} function(s) at Tier 1 — may need deeper observation")
        print(f"for function-specific claims (writes_to, value_changes_with_input).")

    # Suggest knowledge base update
    kb_path = config.get("_knowledge_base_path", "")
    if kb_path:
        print()
        print(f"Update the knowledge base with any new confirmed writers:")
        print(f"  {kb_path}")

    # NOP test candidate analysis
    nop_candidates = _find_nop_candidates(auto_re_dir, results)
    nop_file = os.path.join(auto_re_dir, "nop_experiments.md")

    if nop_candidates:
        print()
        print(f"=== NOP Test Candidates ({len(nop_candidates)}) ===")
        print()
        print(f"These functions have oracle-confirmed writes_to claims and may")
        print(f"be ready for NOP testing. For each candidate:")
        print(f"  1. Read the observation and claim to understand what the function writes")
        print(f"  2. Read the assembly to find the exact store instruction PC")
        print(f"  3. Predict what will break if the write is NOPed")
        print(f"  4. Document the test in nop_experiments.md")
        print()
        for nc in nop_candidates:
            print(f"  {nc['function']}: writes_to {nc['target']}")
            if nc.get("writer_pc"):
                print(f"    Writer PC: {nc['writer_pc']}")
            print(f"    Claim: {nc['claim_id']}")
            print(f"    Observation: workstreams/auto_re/observations/{nc['function']}_obs.md")
            print()

        print(f"Document NOP tests in: {nop_file}")
        print(f"Format for each test:")
        print(f"  - What to NOP (instruction PC, original bytes -> 00 09)")
        print(f"  - Writer function and oracle confirmation")
        print(f"  - Expected effect (what breaks when this write is removed)")
        print(f"  - Best scenario (which save state reveals the effect)")
        print(f"  - Confidence level (HIGH/MEDIUM/LOW)")
        print()
        print(f"The human (or another agent) executes the NOP test by patching")
        print(f"the instruction with the debugger's poke command and observing the game.")
    else:
        if tier_2_count > 0:
            print()
            print(f"No new NOP test candidates found. Existing Tier 2 functions either")
            print(f"already have NOP tests or lack writes_to claims with identifiable PCs.")

    print()
    print(f"COMMIT if you made any updates:")
    print(f"  git add -A workstreams/")
    print(f"  git commit -m \"Integrate results: update knowledge base\"")

    print()
    print(f"--- NEXT ACTION ---")
    print()
    print(f"Run: auto_re.py review")
    print(f"to get a quality check before continuing.")


def cmd_review(config):
    """Output the review subagent prompt for quality and momentum check."""
    auto_re_dir = config["_auto_re_dir"]
    mission_path = config["_mission_path"]
    results_path = config["_results_path"]
    kb_path = config.get("_knowledge_base_path", "")

    print(f"=== Review checkpoint ===")
    print()
    print(f"Spawn a reviewer subagent to check your work quality and mission focus.")
    print(f"Use the Agent tool with the following prompt:")
    print()

    # Build the review prompt dynamically based on what exists
    files_to_read = [f"workstreams/auto_re/results.tsv"]

    if os.path.exists(mission_path):
        files_to_read.insert(0, "workstreams/auto_re/mission.md")

    if kb_path and os.path.exists(kb_path):
        # Make path relative to project
        try:
            rel = os.path.relpath(kb_path, config["_project_dir"])
            files_to_read.append(rel.replace("\\", "/"))
        except ValueError:
            pass

    priorities_path = config["_priorities_path"]
    if os.path.exists(priorities_path):
        files_to_read.append("workstreams/auto_re/explorer_priorities.md")

    obs_count = len(scan_observations(auto_re_dir))
    claims_count = len(scan_claims(auto_re_dir))
    results = parse_results(results_path)

    print(f'  """')
    print(f"  You are reviewing an autonomous RE session. Read these files:")
    print(f"")
    for f in files_to_read:
        print(f"  - {f}")
    print(f"  - Scan workstreams/auto_re/observations/ (all _obs.md files)")
    print(f"  - Scan workstreams/auto_re/claims/ (all .yaml files)")
    print(f"")
    print(f"  Current state: {obs_count} observations, {claims_count} claims, {len(results)} results.")
    print(f"")
    print(f"  Check for these issues and return a SHORT list of action items:")
    print(f"")
    print(f"  QUALITY:")
    print(f"  - Are observations missing Per-Frame Field Analysis? (must be populated)")
    print(f"  - Are value_stable claims being used on globally static fields to pad Tier 2?")
    print(f"  - Are there Tier 2 functions with confirmed writers but no NOP test documented?")
    print(f"  - Are there observations with writes_to data that the claims don't cover?")
    print(f"")
    print(f"  MISSION FOCUS:")
    print(f"  - Read mission.md. Is the recent work aligned with the mission objective?")
    print(f"  - Are there mission-critical gaps being ignored in favor of easier targets?")
    print(f"  - Is the knowledge base up to date with recent findings?")
    print(f"")
    print(f"  MOMENTUM:")
    print(f"  - Are there unfinished priorities in explorer_priorities.md?")
    print(f"  - Are there explored-but-unverified functions that should be verified?")
    print(f"  - Is there work available that should be done before waiting for human input?")
    print(f"")
    print(f"  Return your response as:")
    print(f"  ## Action Items")
    print(f"  1. [HIGH/MED/LOW] Specific action to take")
    print(f"  2. ...")
    print(f"  ## Keep Going")
    print(f"  State clearly: should the agent continue working, or is it genuinely blocked")
    print(f"  on human input? If there is ANY available work, say CONTINUE and name it.")
    print(f'  """')

    print()
    print(f"After the reviewer responds:")
    print(f"  - Address any HIGH action items immediately")
    print(f"  - If the reviewer says CONTINUE, run: auto_re.py status")
    print(f"  - If the reviewer says BLOCKED, report to the human what's needed")
    print()
    print(f"Do NOT skip this review. Do NOT summarize and stop.")


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
    sub.add_parser("review", help="Quality and momentum check via reviewer subagent")

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
    elif args.command == "review":
        cmd_review(config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
