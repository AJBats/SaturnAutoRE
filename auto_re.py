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
from collections import Counter
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
from lib.callgraph import (
    parse_call_trace, FunctionTable, analyze_calls,
    format_tree, format_edge_list, diff_analyses, cross_reference, find_gaps,
)
from lib.memdiff import (
    load_dump, diff_dumps, block_heatmap, classify_regions,
    format_diff_report, format_value_changes,
)


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

    A candidate has EITHER:
    - Tier 2 with a passing writes_to claim (standard path), OR
    - Tier 1 with a rich observation (NOP bypass path — for cases where
      writes_to claims can't pass due to shared addresses like VDP1 VRAM)

    NOP tests are stronger evidence than Tier 2. A function doesn't need
    Tier 2 to be NOP-tested — it needs enough understanding to predict
    the effect. Tier 1 with a detailed observation qualifies.
    """
    candidates = []
    claims_dir = os.path.join(auto_re_dir, "claims")
    obs_dir = os.path.join(auto_re_dir, "observations")

    # Check for existing NOP experiments (YAML or legacy MD)
    existing_nops = set(_parse_nop_experiments(auto_re_dir).keys())

    for r in results:
        func = r.get("function", "")
        try:
            tier = int(r.get("tier", 0))
        except ValueError:
            continue

        if tier < 1:
            continue
        if func in existing_nops:
            continue

        # Check claim file for writes_to claims
        claim_path = os.path.join(claims_dir, f"{func}.yaml")
        has_writes_to = False

        if os.path.exists(claim_path):
            try:
                with open(claim_path) as f:
                    claim_data = yaml.safe_load(f)
            except (yaml.YAMLError, IOError):
                claim_data = {"claims": []}

            for claim in claim_data.get("claims", []):
                if claim.get("type") != "writes_to":
                    continue

                raw_target = claim.get("address", "unknown")
                if isinstance(raw_target, int):
                    target = f"0x{raw_target:08X}"
                else:
                    target = str(raw_target)
                writer_pc = None
                desc = claim.get("description", "")
                pc_match = re.search(r"PC\s+0x([0-9A-Fa-f]+)", desc)
                if pc_match:
                    writer_pc = f"0x{pc_match.group(1)}"

                has_writes_to = True
                candidates.append({
                    "function": func,
                    "target": target,
                    "writer_pc": writer_pc,
                    "claim_id": claim.get("id", ""),
                    "tier": tier,
                    "path": "standard",
                })

        # Tier 1 NOP bypass: if no writes_to claims produced valid candidates
        # (shared addresses, VDP1 VRAM, watchpoint limitations, cross-writers),
        # the function can still be NOP-tested if it has a rich observation.
        # NOP tests are stronger evidence than writes_to claims — the agent
        # just needs to predict what breaks.
        #
        # Check the results notes for FAIL indicators on writes_to claims.
        notes = r.get("notes", "").lower()
        writes_to_all_failed = ("writes_to" in notes or "writes_" in notes) and "fail" in notes
        if tier >= 1 and (not has_writes_to or writes_to_all_failed):
            obs_path = os.path.join(obs_dir, f"{func}_obs.md")
            if os.path.exists(obs_path):
                candidates.append({
                    "function": func,
                    "target": "observation-based (no writes_to claim)",
                    "writer_pc": None,
                    "claim_id": "NOP-bypass",
                    "tier": tier,
                    "path": "bypass",
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
        standard = [c for c in nop_candidates if c.get("path") == "standard"]
        bypass = [c for c in nop_candidates if c.get("path") == "bypass"]

        print()
        print(f"=== NOP Test Candidates ({len(nop_candidates)}) ===")
        print()

        # Cross-reference against existing experiments
        experiments = _parse_nop_experiments(auto_re_dir)
        has_experiment = [c for c in nop_candidates if c["function"] in experiments]
        needs_experiment = [c for c in nop_candidates if c["function"] not in experiments]

        if has_experiment:
            print(f"-- Already in nop_experiments ({len(has_experiment)}) --")
            print()
            for nc in has_experiment:
                exp = experiments[nc["function"]]
                print(f"  {nc['function']}: {exp['status']}"
                      f"{' - ' + exp['conclusion'][:50] if exp.get('conclusion') else ''}")
            print()

        if needs_experiment:
            needs_standard = [c for c in needs_experiment if c.get("path") == "standard"]
            needs_bypass = [c for c in needs_experiment if c.get("path") == "bypass"]

            print(f"-- NEEDS EXPERIMENT ({len(needs_experiment)} functions) --")
            print()
            print(f"  These functions are NOP-test-ready but have no entry in")
            print(f"  nop_experiments.yaml. Write experiments for them NOW.")
            print()
            print(f"  NOP tests are runtime memory pokes — NOT build modifications.")
            print(f"  Poke 0x0009 over a store instruction after loading a save state,")
            print(f"  then observe the behavioral difference. See nop-candidates for")
            print(f"  the full execution procedure.")
            print()
            for nc in needs_standard:
                pc_info = f" patch:{nc['writer_pc']}" if nc.get("writer_pc") else ""
                print(f"  {nc['function']}: writes_to {nc['target']}{pc_info} (Tier {nc['tier']})")
            for nc in needs_bypass:
                print(f"  {nc['function']}: Tier {nc['tier']} (observation-based)")
            print()

            nop_yaml = os.path.join(auto_re_dir, "nop_experiments.yaml")
            template = os.path.join(SCRIPT_DIR, "templates", "nop_experiments.yaml")
            print(f"  Add to: {nop_yaml}")
            print(f"  Schema: {template}")
            if not os.path.exists(nop_yaml):
                print(f"  Create: cp {template} {nop_yaml}")
            print()
        elif has_experiment:
            print(f"All NOP candidates already have experiments. Good.")
            print()
    else:
        if tier_2_count > 0:
            print()
            print(f"No new NOP test candidates found.")

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
    # Check what bulk analysis exists
    cg_dir = os.path.join(auto_re_dir, "call_graphs")
    has_callgraph = False
    if os.path.exists(cg_dir):
        has_callgraph = any(f.endswith("_graph.txt") for f in os.listdir(cg_dir))

    print(f"  Current state: {obs_count} observations, {claims_count} claims, {len(results)} results.")
    print(f"  Call graph analysis: {'done' if has_callgraph else 'NOT done'}")
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
    print(f"  STRATEGY:")
    print(f"  - Has the agent used the analysis tools available? Run auto_re.py tools")
    print(f"    to see the full list. Key tools: callgraph (system architecture),")
    print(f"    memdiff (memory comparison), mem_profile (write tracing),")
    print(f"    CDL (code coverage), DMA trace (data movement).")
    print(f"  - If the agent is picking functions by guesswork or blind call-chain")
    print(f"    following, suggest running callgraph or memdiff to get data first.")
    print(f"  - Is the agent exploring functions that matter for the mission, or")
    print(f"    drifting into utility code and irrelevant subsystems?")
    print(f"  - Are the exploration priorities informed by data or by habit?")
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
    print(f"  - If the reviewer says CONTINUE: run auto_re.py status NOW and")
    print(f"    keep working. Do NOT summarize. Do NOT report to the human.")
    print(f"    Do NOT pause. CONTINUE means CONTINUE.")
    print(f"  - If the reviewer says BLOCKED: report to the human what's needed.")
    print(f"    This is the ONLY case where you stop.")
    print()
    print(f"The review is a checkpoint, not a stopping point. When the reviewer")
    print(f"says CONTINUE, your next action is auto_re.py status — immediately,")
    print(f"without summarizing what you just did.")


def cmd_callgraph(config, scenario=None, diff=False, all_scenarios=False):
    """Capture and analyze call graphs from save state scenarios."""
    auto_re_dir = config["_auto_re_dir"]
    project_dir = config["_project_dir"]
    asm_dir = get_assembly_dir(config)
    save_states = config.get("save_states", {})
    observations_dir = config["_observations_dir"]

    cg_dir = os.path.join(auto_re_dir, "call_graphs")
    traces_dir = os.path.join(auto_re_dir, "traces")
    os.makedirs(cg_dir, exist_ok=True)
    os.makedirs(traces_dir, exist_ok=True)
    # Ensure traces dir is gitignored (raw traces are build artifacts)
    traces_gi = os.path.join(traces_dir, ".gitignore")
    if not os.path.exists(traces_gi):
        with open(traces_gi, "w") as f:
            f.write("# Raw traces are build artifacts -- too large to commit.\n")
            f.write("# Analyzed graphs in call_graphs/ are the committed output.\n")
            f.write("*\n!.gitignore\n")

    print(f"=== Call Graph Analysis ===")
    print()

    # Build function table for symbol resolution
    ftable = None
    if asm_dir and os.path.exists(asm_dir):
        ftable = FunctionTable.from_assembly_dir(asm_dir)
        print(f"Symbol table: {len(ftable.addrs)} functions from {asm_dir}")
    else:
        # Check for linker map — search common locations
        import glob
        map_patterns = [
            os.path.join(project_dir, "build", "*.map"),
            os.path.join(project_dir, "reimpl", "build", "*.map"),
        ]
        for pattern in map_patterns:
            for mp in glob.glob(pattern):
                ftable = FunctionTable.from_map_file(mp)
                if len(ftable.addrs) > 0:
                    print(f"Symbol table: {len(ftable.addrs)} functions from {mp}")
                    break
            if ftable and len(ftable.addrs) > 0:
                break

    if not ftable or len(ftable.addrs) == 0:
        print(f"No symbol table found. Call graph will use raw addresses.")
        print(f"  (Add assembly files to {asm_dir or 'assembly_dir'} for function names)")
        ftable = FunctionTable()
    print()

    # Determine which scenarios to capture
    if scenario:
        targets = {scenario: save_states.get(scenario, {})}
        if not targets[scenario]:
            print(f"ERROR: Unknown scenario '{scenario}'")
            print(f"Available: {', '.join(save_states.keys())}")
            return
    elif all_scenarios:
        targets = save_states
    else:
        # Default: first scenario only
        if not save_states:
            print(f"No save states defined in config.yaml.")
            print(f"Define scenarios under save_states: to use callgraph.")
            return
        first = next(iter(save_states))
        targets = {first: save_states[first]}
        print(f"Capturing scenario '{first}' (use --all for all scenarios)")

    print(f"Scenarios to capture: {', '.join(targets.keys())}")
    print()

    # Tell the agent what to do
    print(f"For each scenario, use the Mednafen debugger to capture a call trace:")
    print()

    for name, state in targets.items():
        state_file = state.get("file", "")
        inputs = state.get("inputs", [])
        frames = state.get("frames", 0)
        notes = state.get("notes", "")

        # Check for callgraph hints in config
        cg_hints = state.get("callgraph", {})
        skip_frames = cg_hints.get("skip", 0)
        capture_frames = cg_hints.get("capture", 0)

        if not capture_frames:
            # Default: capture the entire scenario. Events are fuzzy —
            # the buildup matters as much as the event itself. The trace
            # file is just text; bigger is fine for analysis.
            if frames <= 0:
                capture_frames = 5  # unspecified — just grab a few frames
            else:
                capture_frames = frames - skip_frames

        trace_path = os.path.join(traces_dir, f"{name}_trace.txt")

        print(f"--- Scenario: {name} ---")
        if notes:
            print(f"  {notes}")
        if frames > 0:
            print(f"  Total runway: {frames} frames")
        print()
        print(f"  1. Load save state: {state_file}")
        if inputs:
            if isinstance(inputs[0], list):
                print(f"  2. Apply timed inputs (see save_states.md)")
            else:
                print(f"  2. Hold buttons: {', '.join(inputs)}")
        else:
            print(f"  2. No input (idle)")
        if skip_frames > 0:
            print(f"  3. Advance to the interesting part:")
            print(f"     frame_advance {skip_frames}")
            print(f"  4. Start call trace:")
            print(f"     call_trace_start")
            print(f"  5. Capture through the event ({capture_frames} frames):")
            print(f"     frame_advance {capture_frames}")
            print(f"  6. Stop call trace:")
            print(f"     call_trace_stop")
        else:
            print(f"  3. Start call trace:")
            print(f"     call_trace_start")
            print(f"  4. Advance {capture_frames} frames:")
            print(f"     frame_advance {capture_frames}")
            print(f"  5. Stop call trace:")
            print(f"     call_trace_stop")
        print(f"  Then run auto_re.py callgraph again to auto-detect and analyze.")
        print()

    # Check for existing traces — also auto-detect from IPC dir
    med_config = config.get("mednafen", {})
    ipc_dir = med_config.get("ipc_dir", "build/mcp_ipc")
    if not os.path.isabs(ipc_dir):
        ipc_dir = os.path.join(project_dir, ipc_dir)
    ipc_trace = os.path.join(ipc_dir, "call_trace.txt")

    existing_traces = {}
    for name in targets:
        trace_path = os.path.join(traces_dir, f"{name}_trace.txt")
        if os.path.exists(trace_path):
            existing_traces[name] = trace_path

    # Auto-detect: if IPC has a fresh trace and we have exactly one
    # scenario without a trace, auto-copy it
    if os.path.exists(ipc_trace):
        missing = [n for n in targets if n not in existing_traces]
        if len(missing) == 1:
            dest = os.path.join(traces_dir, f"{missing[0]}_trace.txt")
            import shutil
            shutil.copy2(ipc_trace, dest)
            existing_traces[missing[0]] = dest
            print(f"Auto-detected trace in {ipc_trace}")
            print(f"  Copied to: {dest}")
            print()
        elif len(missing) > 1:
            print(f"Trace file found at {ipc_trace} but {len(missing)} scenarios")
            print(f"still need traces. Copy it manually to the right scenario:")
            for n in missing:
                print(f"  cp {ipc_trace} {os.path.join(traces_dir, f'{n}_trace.txt')}")
            print()

    if existing_traces:
        print(f"=== Analyzing {len(existing_traces)} existing trace(s) ===")
        print()

        all_analyses = {}
        for name, path in existing_traces.items():
            raw = parse_call_trace(path)
            if not raw:
                print(f"  {name}: empty trace (0 calls)")
                continue

            analysis = analyze_calls(raw, ftable)
            all_analyses[name] = analysis

            # Write formatted output
            out_path = os.path.join(cg_dir, f"{name}_graph.txt")
            with open(out_path, "w") as f:
                f.write(f"CALL GRAPH: {name}\n")
                f.write(f"{len(analysis['edges'])} edges, {len(analysis['functions'])} functions\n\n")
                f.write(f"TREE:\n\n")
                f.write(format_tree(analysis))
                f.write(f"\n\n{'=' * 60}\n")
                f.write(f"EDGES ({len(analysis['edges'])}):\n\n")
                f.write(format_edge_list(analysis))
                f.write("\n")

            print(f"  {name}: {len(analysis['edges'])} edges, {len(analysis['functions'])} functions")
            print(f"    Written to: {out_path}")

        # Differential analysis
        if not diff and len(all_analyses) >= 2:
            print()
            print(f"  TIP: Re-run with --diff to see idle-vs-input differences.")
        if diff and len(all_analyses) < 2:
            print()
            print(f"  --diff requires at least 2 scenarios. Capture more traces first.")
        if diff and len(all_analyses) >= 2:
            print()
            print(f"=== Differential Analysis ===")
            print()

            # Find idle scenario (no inputs)
            idle_name = None
            for name in all_analyses:
                state = targets.get(name, {})
                if not state.get("inputs"):
                    idle_name = name
                    break

            if not idle_name:
                print(f"  WARNING: No idle scenario found (no scenario without inputs).")
                print(f"  Diff requires an idle baseline. Add a scenario with inputs: []")
                print(f"  to config.yaml, capture its trace, and re-run with --diff.")
            else:
                baseline = all_analyses[idle_name]
                for name, analysis in all_analyses.items():
                    if name == idle_name:
                        continue
                    d = diff_analyses(baseline, analysis)
                    print(f"  {idle_name} vs {name}:")
                    if d["new"]:
                        print(f"    NEW edges ({len(d['new'])}):")
                        for (caller, callee), count in sorted(d["new"].items(), key=lambda x: -x[1])[:10]:
                            print(f"      {caller} -> {callee} (x{count})")
                    if d["increased"]:
                        print(f"    INCREASED ({len(d['increased'])}):")
                        for (caller, callee), (new_c, old_c) in sorted(d["increased"].items(), key=lambda x: -x[1][0])[:10]:
                            print(f"      {caller} -> {callee}: {old_c} -> {new_c}")
                    print()

        # Cross-reference
        if len(all_analyses) >= 2:
            xref = cross_reference(all_analyses)
            xref_path = os.path.join(cg_dir, "cross_reference.txt")
            with open(xref_path, "w") as f:
                f.write(f"CROSS-REFERENCE: {len(all_analyses)} scenarios, {len(xref['all_edges'])} unique edges\n\n")
                f.write(f"COMMON CORE ({len(xref['common'])} edges -- in all scenarios):\n")
                for caller, callee in sorted(xref["common"]):
                    f.write(f"  {caller} -> {callee}\n")
                f.write(f"\nPER-SCENARIO UNIQUE EDGES:\n")
                for label, edges in sorted(xref["unique"].items()):
                    if edges:
                        f.write(f"\n  {label} only ({len(edges)}):\n")
                        for caller, callee in sorted(edges):
                            f.write(f"    {caller} -> {callee}\n")
            print(f"  Cross-reference: {xref_path}")

        # Gap analysis
        if all_analyses:
            # Merge all analyses for gap finding
            merged_edges = Counter()
            for a in all_analyses.values():
                for edge, count in a["edges"].items():
                    merged_edges[edge] += count
            merged = {"edges": dict(merged_edges), "functions": set()}
            for a in all_analyses.values():
                merged["functions"] |= a["functions"]

            gaps = find_gaps(merged, observations_dir)
            if gaps:
                print()
                print(f"=== Gap Analysis: {len(gaps)} unobserved functions in call graph ===")
                print()
                for func, count in gaps[:20]:
                    print(f"  {func}: {count} calls (no observation)")
                if len(gaps) > 20:
                    print(f"  ... and {len(gaps) - 20} more")
                print()
                print(f"These functions fire per frame but have no observation.")
                print(f"Write the top targets to explorer_priorities.md so")
                print(f"auto_re.py pick can find them:")
                print()
                priorities_path = config["_priorities_path"]
                print(f"  File: {priorities_path}")
                print(f"  For each target, document WHY (call count, callers),")
                print(f"  WHAT to do (breakpoint, watchpoint, scenario), and")
                print(f"  WHAT it unblocks.")
                print()
                print(f"COMMIT your priorities:")
                print(f"  git add workstreams/auto_re/explorer_priorities.md")
                print(f'  git commit -m "Set priorities from call graph gap analysis"')

    else:
        print(f"No existing traces found. Capture traces using the steps above,")
        print(f"then run auto_re.py callgraph again to analyze them.")

    print()
    print(f"--- NEXT ACTION ---")
    print()
    if not existing_traces:
        print(f"Capture call traces for each scenario listed above.")
        print(f"Then run: auto_re.py callgraph")
        if len(targets) == 1 and len(save_states) > 1:
            print()
            print(f"TIP: You only captured 1 of {len(save_states)} scenarios.")
            print(f"Run with --all to capture all scenarios for cross-reference:")
            print(f"  auto_re.py callgraph --all")
    elif len(existing_traces) == 1 and len(save_states) > 1:
        print(f"You have 1 trace but {len(save_states)} scenarios defined.")
        print(f"Capture more scenarios for differential and cross-reference analysis:")
        print(f"  auto_re.py callgraph --all --diff")
    else:
        print(f"Run: auto_re.py status")


def _parse_mcp_tools(mcp_path):
    """Extract tool names and docstrings from mcp_server.py.

    Finds all @mcp.tool() decorated async functions and returns a list
    of (name, first_line_of_docstring) tuples.
    """
    tools = []
    try:
        with open(mcp_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return tools

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("@mcp.tool"):
            # Find the function def (may be next line or a few lines later)
            for j in range(i + 1, min(i + 5, len(lines))):
                defline = lines[j].strip()
                m = re.match(r"async def (\w+)\(", defline)
                if m:
                    name = m.group(1)
                    # Skip past the full signature (may span multiple lines)
                    # Find the line ending with ":"
                    sig_end = j
                    for s in range(j, min(j + 20, len(lines))):
                        if lines[s].rstrip().endswith(":"):
                            sig_end = s
                            break
                    # Look for docstring after signature
                    doc = ""
                    for k in range(sig_end + 1, min(sig_end + 5, len(lines))):
                        docline = lines[k].strip()
                        if docline.startswith('"""') or docline.startswith("'''"):
                            doc = docline.strip("\"'").strip()
                            if not doc:
                                # Multi-line — grab next line
                                if k + 1 < len(lines):
                                    doc = lines[k + 1].strip().strip("\"'").strip()
                            break
                        if docline and not docline.startswith("#"):
                            break  # non-docstring code — no docstring exists
                    tools.append((name, doc))
                    break
        i += 1
    return tools


def cmd_tools(config):
    """List available analysis tools and MCP capabilities."""
    from lib.config import MEDNAFEN_DIR

    print(f"=== Available Analysis Tools ===")
    print()

    # --- CLI Tools ---
    print(f"--- CLI Tools (auto_re.py) ---")
    print()
    print(f"  status            Show pipeline status and next action")
    print(f"  pick              Pick the next function to investigate")
    print(f"  explore-check     Validate an observation file")
    print(f"  verify            Generate claims and run oracle")
    print(f"  integrate         Check results, NOP candidates, suggest next steps")
    print(f"  review            Quality and momentum check via reviewer subagent")
    print(f"  callgraph         Capture and analyze per-frame call trees")
    print(f"  memdiff           Compare two memory dumps byte-by-byte")
    print(f"  nop-candidates    List functions ready for NOP testing")
    print(f"  graduate          List or review function graduation candidates")
    print(f"  tools             This listing")
    print()

    # --- MCP Tools (parsed from mcp_server.py) ---
    mcp_path = os.path.join(MEDNAFEN_DIR, "mcp_server.py")
    tools = _parse_mcp_tools(mcp_path)

    if tools:
        print(f"--- MCP Debugger Tools ({len(tools)} tools, from mcp_server.py) ---")
        print()
        for name, doc in tools:
            if doc:
                print(f"  {name:30s} {doc[:70]}")
            else:
                print(f"  {name}")
        print()
    else:
        print(f"--- MCP Debugger Tools ---")
        print()
        print(f"  Could not parse tools from {mcp_path}")
        print(f"  Run the MCP server interactively to see available tools.")
        print()

    # --- Static Analysis ---
    asm_dir = get_assembly_dir(config)
    project_dir = config["_project_dir"]
    ghidra_dir = os.path.join(project_dir, "ghidra_reference")

    print(f"--- Static Analysis ---")
    print()
    if asm_dir and os.path.exists(asm_dir):
        count = sum(1 for f in os.listdir(asm_dir) if f.endswith(".s"))
        print(f"  Assembly: {asm_dir} ({count} .s files)")
    if os.path.exists(ghidra_dir):
        count = sum(1 for f in os.listdir(ghidra_dir) if f.endswith(".c"))
        print(f"  Ghidra C: {ghidra_dir} ({count} .c files)")
        print(f"    Read decompiled C to aid static analysis — understand control")
        print(f"    flow, identify struct fields, trace data dependencies.")
    print()


def cmd_memdiff(config, dump_a=None, dump_b=None, label_a="A", label_b="B",
                region_lo=None, region_hi=None):
    """Compare two memory dumps and report differences."""
    auto_re_dir = config["_auto_re_dir"]
    diff_dir = os.path.join(auto_re_dir, "memdiffs")
    os.makedirs(diff_dir, exist_ok=True)

    known_structs = config.get("targets", {})
    save_states = config.get("save_states", {})

    # Default memory region: Work RAM High (1MB)
    base_addr = int(region_lo, 16) if region_lo else 0x06000000
    end_addr = int(region_hi, 16) if region_hi else 0x06100000
    region_size = end_addr - base_addr

    print(f"=== Memory Diff ===")
    print()

    if dump_a and dump_b:
        # Both dumps provided — analyze them
        if not os.path.exists(dump_a):
            print(f"ERROR: Dump A not found: {dump_a}")
            return
        if not os.path.exists(dump_b):
            print(f"ERROR: Dump B not found: {dump_b}")
            return

        data_a = load_dump(dump_a)
        data_b = load_dump(dump_b)

        if len(data_a) != len(data_b):
            print(f"WARNING: Dump sizes differ ({len(data_a)} vs {len(data_b)})")
            print(f"Comparing first {min(len(data_a), len(data_b))} bytes.")

        diffs = diff_dumps(data_a, data_b, base_addr)
        heatmap = block_heatmap(diffs, base_addr)
        classified = classify_regions(heatmap, known_structs)

        # Print report
        report = format_diff_report(
            diffs, heatmap, classified, min(len(data_a), len(data_b)),
            label_a, label_b)
        print(report)
        print()

        # Write report to file
        out_name = f"diff_{label_a}_vs_{label_b}.txt"
        out_path = os.path.join(diff_dir, out_name)
        with open(out_path, "w") as f:
            f.write(report)
            f.write("\n\n")
            f.write(format_value_changes(diffs, base_addr))
        print(f"Full report written to: {out_path}")

        print()
        print(f"--- NEXT ACTION ---")
        print()
        if diffs:
            print(f"Review the active regions. Unknown regions with many changed bytes")
            print(f"are discovery targets — they may contain data structures you haven't")
            print(f"mapped yet. Consider adding them to config.yaml targets.")
        else:
            print(f"No differences found. Try a different comparison (different input,")
            print(f"more frames, different memory region).")
        print()
        print(f"Run: auto_re.py status")
    else:
        # No dumps — show instructions
        print(f"Compare two memory dumps to find active/responsive regions.")
        print(f"Use this to compare any two game states:")
        print(f"  - Idle vs input (find input-responsive memory)")
        print(f"  - Frame N vs frame N+1 (find per-frame updates)")
        print(f"  - Normal vs NOPed function (find what a function affects)")
        print(f"  - Different save states (find state-dependent regions)")
        print()
        print(f"CAPTURE INSTRUCTIONS:")
        print()
        print(f"  For each state you want to compare, dump memory to a file:")
        print()
        print(f"  1. Load save state:")
        print(f"     load_state <path>")
        print(f"  2. (Optional) apply input or advance frames")
        print(f"  3. Dump memory region:")
        print(f"     dump_region 0x{base_addr:08X} 0x{region_size:X} <output_path>")
        print()
        print(f"  Example -- comparing idle vs throttle after 60 frames:")
        print()
        print(f"     # Capture A: idle")
        print(f"     load_state <save_state>")
        print(f"     frame_advance 60")
        print(f"     dump_region 0x{base_addr:08X} 0x{region_size:X} {diff_dir}/dump_idle.bin")
        print()
        print(f"     # Capture B: throttle")
        print(f"     load_state <save_state>")

        # Show first input button if available
        controls = config.get("controls", {})
        first_btn = next(iter(controls.values()), "BUTTON") if controls else "BUTTON"
        print(f"     input_press {first_btn}")
        print(f"     frame_advance 60")
        print(f"     dump_region 0x{base_addr:08X} 0x{region_size:X} {diff_dir}/dump_{first_btn.lower()}.bin")
        print()
        print(f"  Then analyze:")
        print(f"     auto_re.py memdiff {diff_dir}/dump_idle.bin {diff_dir}/dump_{first_btn.lower()}.bin")
        print(f"       --label-a idle --label-b {first_btn.lower()}")
        print()
        print(f"  Memory region: 0x{base_addr:08X} - 0x{end_addr:08X} ({region_size // 1024}KB)")
        print(f"  Override with: --region-lo 0xADDR --region-hi 0xADDR")


def _parse_nop_experiments(auto_re_dir):
    """Parse nop_experiments.yaml for experiment status.

    Searches for nop_experiments.yaml in auto_re/ and sibling directories.
    Falls back to legacy nop_experiments.md parsing if no YAML found.
    Returns dict of function -> {status, field, conclusion, name, patch_addr}.
    """
    experiments = {}
    search_paths = [
        os.path.join(auto_re_dir, "nop_experiments.yaml"),
        os.path.join(auto_re_dir, "..", "driving_model", "nop_experiments.yaml"),
    ]

    for nop_path in search_paths:
        if not os.path.exists(nop_path):
            continue
        try:
            with open(nop_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, IOError, OSError):
            continue

        if not data or "experiments" not in data:
            continue

        for exp in data.get("experiments", []) or []:
            func = exp.get("function", "")
            if not func:
                continue
            experiments[func] = {
                "status": exp.get("status", "proposed").upper(),
                "field": exp.get("field", ""),
                "conclusion": exp.get("conclusion", ""),
                "name": exp.get("name", ""),
                "patch_addr": exp.get("patch_addr", ""),
                "prediction": exp.get("prediction", ""),
                "result": exp.get("result", ""),
                "scenario": exp.get("scenario", ""),
                "source": nop_path,
            }

    # Fallback: try legacy .md format if no YAML found
    if not experiments:
        md_paths = [
            os.path.join(auto_re_dir, "nop_experiments.md"),
            os.path.join(auto_re_dir, "..", "driving_model", "nop_experiments.md"),
        ]
        for md_path in md_paths:
            if not os.path.exists(md_path):
                continue
            try:
                with open(md_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except (IOError, OSError):
                continue
            # Simple scan: find CONFIRMED results with function names
            for m in re.finditer(
                r"(FUN_[0-9A-Fa-f]{6,8}|sym_[0-9A-Fa-f]{6,8}).*?CONFIRMED[:\s]+(.+?)(?:\n|$)",
                content, re.IGNORECASE
            ):
                func = m.group(1)
                if func not in experiments:
                    experiments[func] = {
                        "status": "CONFIRMED",
                        "field": "",
                        "conclusion": m.group(2).strip(),
                        "name": "",
                        "patch_addr": "",
                        "prediction": "",
                        "result": "",
                        "scenario": "",
                        "source": md_path,
                    }

    return experiments


def cmd_nop_candidates(config):
    """List NOP tests — curated experiments first, then raw candidates."""
    auto_re_dir = config["_auto_re_dir"]
    results_path = config["_results_path"]

    print(f"=== NOP Tests ===")
    print()

    # First: show curated experiments from nop_experiments.md
    experiments = _parse_nop_experiments(auto_re_dir)

    if experiments:
        confirmed = {f: e for f, e in experiments.items() if e["status"] == "CONFIRMED"}
        proposed = {f: e for f, e in experiments.items() if e["status"] == "PROPOSED"}
        disproved = {f: e for f, e in experiments.items() if e["status"] == "DISPROVED"}
        inconclusive = {f: e for f, e in experiments.items() if e["status"] == "INCONCLUSIVE"}

        if confirmed:
            print(f"-- CONFIRMED ({len(confirmed)}) --")
            print()
            for func, e in confirmed.items():
                name = f" -> {e['name']}" if e.get("name") else ""
                field = f" ({e['field']})" if e.get("field") else ""
                print(f"  {func}{name}{field}: {e['conclusion'][:70]}")
            print()

        if inconclusive:
            print(f"-- INCONCLUSIVE ({len(inconclusive)}) --")
            print()
            for func, e in inconclusive.items():
                field = f" ({e['field']})" if e.get("field") else ""
                print(f"  {func}{field}: {e.get('result', e.get('prediction', ''))[:70]}")
            print()

        if disproved:
            print(f"-- DISPROVED ({len(disproved)}) --")
            print()
            for func, e in disproved.items():
                print(f"  {func}: {e.get('result', '')[:70]}")
            print()

        if proposed:
            print(f"-- PROPOSED (not yet tested) ({len(proposed)}) --")
            print()
            for func, e in proposed.items():
                field = f" ({e['field']})" if e.get("field") else ""
                addr = f" patch:{e['patch_addr']}" if e.get("patch_addr") else ""
                print(f"  {func}{field}{addr}: {e.get('prediction', '')[:60]}")
            print()
    else:
        print(f"No nop_experiments.yaml found. Create one from the template:")
        print(f"  cp {os.path.join(SCRIPT_DIR, 'templates', 'nop_experiments.yaml')} \\")
        print(f"     workstreams/auto_re/nop_experiments.yaml")
        print()

    # Second: find raw candidates not already in experiments
    results = parse_results(results_path)
    if not results:
        if not experiments:
            print(f"No results in results.tsv yet. Run the explore->verify cycle first.")
        return

    candidates = _find_nop_candidates(auto_re_dir, results)
    # Filter out anything already in curated experiments
    new_candidates = [c for c in candidates if c["function"] not in experiments]

    if new_candidates:
        standard = [c for c in new_candidates if c.get("path") == "standard"]
        bypass = [c for c in new_candidates if c.get("path") == "bypass"]

        print(f"-- Additional candidates (not in nop_experiments.yaml) ({len(new_candidates)}) --")
        print()
        if standard:
            for c in standard:
                pc_info = f" at PC {c['writer_pc']}" if c.get("writer_pc") else ""
                print(f"  {c['function']}: writes_to {c['target']}{pc_info} (Tier {c['tier']})")
        if bypass:
            for c in bypass:
                print(f"  {c['function']}: Tier {c['tier']} (observation-based, writes_to blocked)")
        print()

    # Guidance
    nop_yaml = os.path.join(auto_re_dir, "nop_experiments.yaml")
    print(f"--- Adding NOP experiments ---")
    print()
    print(f"WARNING: Claim PCs are NOT patch addresses. SH-2 watchpoints report")
    print(f"the PC 2-4 bytes AFTER the store instruction. Always verify the opcode")
    print(f"at the candidate address is a store (mov.l/mov.w/mov.b) before writing")
    print(f"patch_addr. See the template for the verification procedure.")
    print()
    print(f"Add experiments to: {nop_yaml}")
    if not os.path.exists(nop_yaml):
        print(f"  (copy template: cp {os.path.join(SCRIPT_DIR, 'templates', 'nop_experiments.yaml')} {nop_yaml})")
    print()

    # Point to schema template
    template_path = os.path.join(SCRIPT_DIR, "templates", "nop_experiments.yaml")
    print(f"Schema and examples: {template_path}")
    print()

    print(f"--- Executing a NOP test ---")
    print()
    print(f"NOP tests are runtime memory pokes on the RETAIL build, NOT build")
    print(f"modifications. This gives pinpoint before/after comparison.")
    print()
    print(f"  1. Load a save state:  load_state <scenario_path>")
    print(f"  2. Poke NOP (0x0009) over the store instruction:")
    print(f"     raw_command \"poke <patch_addr> 0009\"")
    print(f"  3. Free-run and observe behavior (screenshot, memory read, etc.)")
    print(f"  4. Reload the SAME save state (clean slate) to compare with/without")
    print()
    print(f"After running NOP tests, update status to 'confirmed' and add result/conclusion.")
    print(f"Then run: auto_re.py graduate")


def _parse_graduated(auto_re_dir):
    """Read graduated.tsv and return dict of function -> graduation info."""
    grad_path = os.path.join(auto_re_dir, "graduated.tsv")
    graduated = {}
    if not os.path.exists(grad_path):
        return graduated
    with open(grad_path, encoding="utf-8", errors="replace") as f:
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
            graduated[row.get("function", "")] = row
    return graduated


def _find_graduation_candidates(auto_re_dir, results):
    """Find functions ready for graduation (rename + annotation).

    A graduation candidate has:
    - NOP test results (mentioned in nop_experiments.md with CONFIRMED), OR
    - Tier 2 with writes_to + behavioral understanding
    AND:
    - Not already graduated (not in graduated.tsv)
    """
    candidates = []
    graduated = _parse_graduated(auto_re_dir)

    # Check NOP experiments file for confirmed functions
    nop_file = os.path.join(auto_re_dir, "nop_experiments.md")
    nop_confirmed = {}
    if os.path.exists(nop_file):
        try:
            with open(nop_file, encoding="utf-8", errors="replace") as f:
                content = f.read()
            # Find CONFIRMED results with function names
            for m in re.finditer(
                r"(FUN_[0-9A-Fa-f]+|sym_[0-9A-Fa-f]+).*?CONFIRMED[:\s]+(.+?)(?:\n|$)",
                content, re.IGNORECASE
            ):
                nop_confirmed[m.group(1)] = m.group(2).strip()
        except (IOError, OSError):
            pass

    # Also check for nop_experiments.md in sibling dirs (driving_model/)
    dm_nop = os.path.join(auto_re_dir, "..", "driving_model", "nop_experiments.md")
    if os.path.exists(dm_nop):
        try:
            with open(dm_nop, encoding="utf-8", errors="replace") as f:
                content = f.read()
            for m in re.finditer(
                r"(FUN_[0-9A-Fa-f]+|sym_[0-9A-Fa-f]+).*?CONFIRMED[:\s]+(.+?)(?:\n|$)",
                content, re.IGNORECASE
            ):
                if m.group(1) not in nop_confirmed:
                    nop_confirmed[m.group(1)] = m.group(2).strip()
        except (IOError, OSError):
            pass

    # Build candidate list
    result_map = {r.get("function", ""): r for r in results}

    for func, conclusion in nop_confirmed.items():
        if func in graduated:
            continue
        tier = 0
        if func in result_map:
            try:
                tier = int(result_map[func].get("tier", 0))
            except ValueError:
                pass
        candidates.append({
            "function": func,
            "evidence": f"NOP-confirmed: {conclusion}",
            "tier": tier,
            "source": "nop",
        })

    # Also include Tier 2 functions with writes_to that haven't been NOP'd
    # These are candidates for graduation IF the human is satisfied with
    # the oracle evidence alone (without a NOP test)
    for r in results:
        func = r.get("function", "")
        if func in graduated or func in nop_confirmed:
            continue
        try:
            tier = int(r.get("tier", 0))
        except ValueError:
            continue
        if tier < 2:
            continue
        # Check for writes_to PASS in notes (adjacent, not just anywhere)
        notes = r.get("notes", "")
        if re.search(r"writes_\w+\s+PASS", notes, re.IGNORECASE):
            candidates.append({
                "function": func,
                "evidence": f"Tier 2 with writes_to PASS",
                "tier": tier,
                "source": "tier2",
            })

    return candidates


def cmd_graduate(config, func_name=None, proposed_name=None):
    """List graduation candidates or start graduation review for a function."""
    auto_re_dir = config["_auto_re_dir"]
    results_path = config["_results_path"]
    results = parse_results(results_path)
    graduated = _parse_graduated(auto_re_dir)

    if func_name is None:
        # List mode — show candidates
        print(f"=== Graduation Candidates ===")
        print()

        if graduated:
            print(f"Already graduated ({len(graduated)}):")
            for func, info in graduated.items():
                print(f"  {func} -> {info.get('name', '?')} ({info.get('date', '?')})")
            print()

        candidates = _find_graduation_candidates(auto_re_dir, results)

        if not candidates:
            print(f"No candidates ready for graduation.")
            print()
            print(f"Functions graduate when they have:")
            print(f"  - NOP test confirmation (strongest), OR")
            print(f"  - Tier 2 with a passing writes_to claim")
            print()
            print(f"Run: auto_re.py nop-candidates")
            return

        nop_cands = [c for c in candidates if c["source"] == "nop"]
        tier2_cands = [c for c in candidates if c["source"] == "tier2"]
        obs_dir = config["_observations_dir"]

        if nop_cands:
            print(f"-- NOP-confirmed (ready for graduation) --")
            print()
            for c in nop_cands:
                func = c["function"]
                obs = os.path.join(obs_dir, f"{func}_obs.md")
                obs_ref = f"  obs: {obs}" if os.path.exists(obs) else ""
                print(f"  {func}: {c['evidence']}")
                if obs_ref:
                    print(obs_ref)
            print()

        if tier2_cands:
            print(f"-- Tier 2 with writes_to (consider for graduation) --")
            print()
            for c in tier2_cands:
                func = c["function"]
                obs = os.path.join(obs_dir, f"{func}_obs.md")
                obs_ref = f"  obs: {obs}" if os.path.exists(obs) else ""
                print(f"  {func}: {c['evidence']}")
                if obs_ref:
                    print(obs_ref)
            print()

        # Skill-like instruction for the agent
        nop_file = os.path.join(auto_re_dir, "nop_experiments.yaml")
        if not os.path.exists(nop_file):
            nop_file = os.path.join(auto_re_dir, "nop_experiments.md")
        if not os.path.exists(nop_file):
            nop_file = os.path.join(auto_re_dir, "..", "driving_model", "nop_experiments.md")

        print(f"--- How to graduate a function ---")
        print()
        print(f"1. Pick a candidate from the list above.")
        print(f"2. Read its observation file and NOP test results:")
        if os.path.exists(nop_file):
            print(f"     NOP evidence: {nop_file}")
        print(f"     Observations: {obs_dir}/")
        print(f"     Results: {config['_results_path']}")
        print(f"3. Based on the evidence, propose a human-readable name for the")
        print(f"   function. The name should describe WHAT the function does,")
        print(f"   not HOW (e.g. 'velocity_integrator' not 'add_F0_to_24').")
        print(f"4. Discuss the proposed name with the human. They approve or revise.")
        print(f"5. Once agreed, run:")
        print(f"     auto_re.py graduate <FUNCTION> <approved_name>")
        print(f"6. Follow the line-by-line review instructions in the output.")
        print(f"   Read EVERY instruction in the assembly and check it against")
        print(f"   the proposed name. If anything contradicts the interpretation,")
        print(f"   DO NOT graduate — document the contradiction instead.")
        return

    # Review mode — start graduation for a specific function
    print(f"=== Graduate: {func_name} ===")
    print()

    if func_name in graduated:
        info = graduated[func_name]
        print(f"Already graduated as '{info.get('name', '?')}' on {info.get('date', '?')}")
        return

    # Gather all evidence
    obs_path = os.path.join(auto_re_dir, "observations", f"{func_name}_obs.md")
    claim_path = os.path.join(auto_re_dir, "claims", f"{func_name}.yaml")
    result_map = {r.get("function", ""): r for r in results}

    print(f"--- Evidence summary ---")
    print()

    # Results
    if func_name in result_map:
        r = result_map[func_name]
        print(f"Oracle: {r.get('passed', '?')}/{r.get('total', '?')} passed, Tier {r.get('tier', '?')}")
        if r.get("notes"):
            print(f"  {r['notes'][:200]}")
    else:
        print(f"Oracle: no results")
    print()

    # NOP evidence
    nop_files = [
        os.path.join(auto_re_dir, "nop_experiments.md"),
        os.path.join(auto_re_dir, "..", "driving_model", "nop_experiments.md"),
    ]
    nop_evidence = []
    for nf in nop_files:
        if os.path.exists(nf):
            try:
                with open(nf, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                if func_name in content:
                    # Extract the relevant section
                    idx = content.index(func_name)
                    start = content.rfind("\n### ", 0, idx)
                    if start == -1:
                        start = max(0, idx - 200)
                    end = content.find("\n### ", idx + 1)
                    if end == -1:
                        end = min(len(content), idx + 1000)
                    snippet = content[start:end].strip()
                    nop_evidence.append(snippet)
            except (IOError, OSError):
                pass

    if nop_evidence:
        print(f"NOP test evidence:")
        for snippet in nop_evidence:
            for line in snippet.split("\n")[:10]:
                print(f"  {line}")
            if len(snippet.split("\n")) > 10:
                print(f"  ... ({len(snippet.split(chr(10)))} lines total)")
        print()
    else:
        print(f"NOP test: none")
        print()

    # Observation
    if os.path.exists(obs_path):
        print(f"Observation: {obs_path}")
    else:
        print(f"Observation: none")
    print()

    # Assembly source
    asm_dir = get_assembly_dir(config)
    asm_file = None
    if asm_dir:
        # Search for the function's assembly file
        for root, dirs, files in os.walk(asm_dir):
            for f in files:
                if f == f"{func_name}.s" or f.startswith(f"{func_name}."):
                    asm_file = os.path.join(root, f)
                    break
            if asm_file:
                break
    if asm_file:
        print(f"Assembly: {asm_file}")
    else:
        print(f"Assembly: not found in {asm_dir}")
    print()

    # The graduation instruction
    print(f"--- Graduation review ---")
    print()
    if proposed_name:
        print(f"Proposed name: {proposed_name}")
    else:
        print(f"No name proposed. Usage: auto_re.py graduate {func_name} <proposed_name>")
        return
    print()
    print(f"TASK: Read {func_name} line by line with the interpretation '{proposed_name}'.")
    print(f"For EVERY instruction, ask:")
    print(f"  1. Does this make sense if this function is '{proposed_name}'?")
    print(f"  2. Can I connect this line to one of the evidence data points above?")
    print(f"  3. Does anything here CONTRADICT the interpretation?")
    print()
    print(f"If the function reads a field, ask: why would '{proposed_name}' need this input?")
    print(f"If it writes a field, ask: is this output consistent with '{proposed_name}'?")
    print(f"If it branches, ask: what condition would '{proposed_name}' check for?")
    print()
    print(f"If EVERYTHING checks out, record the graduation:")
    print()

    grad_path = os.path.join(auto_re_dir, "graduated.tsv")
    if not os.path.exists(grad_path):
        print(f"  Create {grad_path} with header:")
        print(f"  function\tname\tdate\tevidence")
        print()
    print(f"  Add line:")
    print(f"  {func_name}\t{proposed_name}\t<today's date>\t<one-line evidence summary>")
    print()
    print(f"Then annotate the assembly with Level 1 comments (evidence + pipeline context)")
    print(f"and update the struct_defs.inc with any named offsets.")
    print()
    print(f"If something is FISHY, document the contradiction and DO NOT graduate.")
    print(f"A failed graduation attempt is valuable — it means the interpretation is wrong")
    print(f"or incomplete, and the function needs more investigation.")


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

    cg = sub.add_parser("callgraph", help="Capture and analyze call graphs")
    cg.add_argument("--scenario", "-s", default=None,
                     help="Capture/analyze one scenario (default: first)")
    cg.add_argument("--all", action="store_true", dest="all_scenarios",
                     help="Capture/analyze all scenarios")
    cg.add_argument("--diff", action="store_true",
                     help="Compute idle-vs-input differentials")

    md = sub.add_parser("memdiff", help="Compare two memory dumps")
    md.add_argument("dump_a", nargs="?", default=None,
                     help="First dump file (or omit for instructions)")
    md.add_argument("dump_b", nargs="?", default=None,
                     help="Second dump file")
    md.add_argument("--label-a", default="A", help="Label for first dump")
    md.add_argument("--label-b", default="B", help="Label for second dump")
    md.add_argument("--region-lo", default=None,
                     help="Base address of dumped region (hex, default: 0x06000000)")
    md.add_argument("--region-hi", default=None,
                     help="End address of dumped region (hex, default: 0x06100000)")

    sub.add_parser("tools", help="List available analysis tools and MCP capabilities")

    sub.add_parser("nop-candidates", help="List functions ready for NOP testing")

    grad = sub.add_parser("graduate", help="List or review graduation candidates")
    grad.add_argument("function", nargs="?", default=None,
                       help="Function to graduate (e.g. FUN_060366EC)")
    grad.add_argument("name", nargs="?", default=None,
                       help="Proposed name (e.g. velocity_integrator)")

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
    elif args.command == "callgraph":
        cmd_callgraph(config, args.scenario, args.diff, args.all_scenarios)
    elif args.command == "memdiff":
        cmd_memdiff(config, args.dump_a, args.dump_b, args.label_a, args.label_b,
                    args.region_lo, args.region_hi)
    elif args.command == "tools":
        cmd_tools(config)
    elif args.command == "nop-candidates":
        cmd_nop_candidates(config)
    elif args.command == "graduate":
        cmd_graduate(config, args.function, args.name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
