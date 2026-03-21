#!/usr/bin/env python3
"""Generic test runner for auto_re claims.

Reads a YAML claim file and the project's config.yaml, boots Mednafen,
runs each claim's test against the emulator, reports pass/fail.

This is the oracle — game-agnostic. All game-specific configuration
comes from workstreams/auto_re/config.yaml.

Usage (from a project directory):
    python /path/to/SaturnAutoRE/test_claim.py workstreams/auto_re/claims/FUN_XXXXXXXX.yaml
    python /path/to/SaturnAutoRE/test_claim.py workstreams/auto_re/claims/FUN_XXXXXXXX.yaml -v
    python /path/to/SaturnAutoRE/test_claim.py workstreams/auto_re/claims/FUN_XXXXXXXX.yaml --claim writes_field
"""

import os
import sys
import time
import yaml
import argparse
import struct

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MEDNAFEN_DIR = os.path.join(SCRIPT_DIR, "mednafen")
sys.path.insert(0, MEDNAFEN_DIR)

from mednafen_bot import MednafenBot, _win_path

# --- Configuration from project ---

def _load_project_config(project_dir):
    """Load config.yaml from the project directory."""
    config_path = os.path.join(project_dir, "workstreams", "auto_re", "config.yaml")
    if not os.path.exists(config_path):
        print(f"ERROR: No config.yaml at {config_path}")
        sys.exit(1)
    with open(config_path) as f:
        return yaml.safe_load(f)


def _resolve_save_states(config, project_dir):
    """Build SAVE_STATES dict from config, resolving paths."""
    states = {}
    for name, state in config.get("save_states", {}).items():
        path = state.get("file", "")
        if path and not os.path.isabs(path):
            path = os.path.join(project_dir, path)
        states[name] = path
    return states


def _resolve_scenario_inputs(config):
    """Build scenario input specs from config.

    Returns dict of scenario -> input spec, where input spec is one of:
    - list of button strings (simple: hold all buttons)
    - list of [frame, action, button] tuples (timed events)
    - None (playback scenario — inputs come from a file)
    """
    inputs = {}
    for name, state in config.get("save_states", {}).items():
        raw = state.get("inputs", [])
        playback = state.get("playback")
        if playback:
            inputs[name] = None  # playback scenario
        elif raw and isinstance(raw[0], list):
            # Timed events: [[frame, action, button], ...]
            inputs[name] = [(e[0], e[1], e[2]) for e in raw]
        else:
            # Simple: [button, button, ...]
            inputs[name] = raw
    return inputs


def _resolve_playback_files(config, project_dir):
    """Build playback file dict from config."""
    playbacks = {}
    for name, state in config.get("save_states", {}).items():
        playback = state.get("playback")
        if playback:
            if not os.path.isabs(playback):
                playback = os.path.join(project_dir, playback)
            playbacks[name] = playback
    return playbacks


# --- Input handling ---

def _is_timed(scenario_inputs, scenario):
    """Check if a scenario uses timed input events."""
    inputs = scenario_inputs.get(scenario, [])
    return inputs and isinstance(inputs[0], tuple)


def _is_playback(scenario_inputs, scenario):
    """Check if a scenario uses input playback."""
    return scenario_inputs.get(scenario) is None


def _apply_simple_inputs(bot, scenario_inputs, scenario):
    """Press and hold all buttons for a simple scenario."""
    for btn in scenario_inputs.get(scenario, []):
        bot.send_and_wait(f"input {btn}", "ok input", timeout=5)


def _release_simple_inputs(bot, scenario_inputs, scenario):
    """Release all buttons for a simple scenario."""
    for btn in scenario_inputs.get(scenario, []):
        bot.send_and_wait(f"input_release {btn}", "ok input_release", timeout=5)


def _advance_with_timed_inputs(bot, scenario_inputs, scenario, total_frames, verbose=False):
    """Advance frames while replaying timed input events."""
    events = scenario_inputs[scenario]
    events = [(f, act, btn) for f, act, btn in events if f <= total_frames]
    current_frame = 0

    for frame, action, button in events:
        if frame > current_frame:
            delta = frame - current_frame
            bot.send_and_wait(f"frame_advance {delta}",
                              "done frame_advance", timeout=max(delta, 30))
            current_frame = frame
        if action == "press":
            bot.send_and_wait(f"input {button}", "ok input", timeout=5)
        elif action == "release":
            bot.send_and_wait(f"input_release {button}", "ok input_release", timeout=5)
        if verbose:
            print(f"    frame {frame}: {action} {button}")

    remaining = total_frames - current_frame
    if remaining > 0:
        bot.send_and_wait(f"frame_advance {remaining}",
                          "done frame_advance", timeout=max(remaining, 30))

    # Release any buttons still held
    for frame, action, button in events:
        if action == "press":
            released = any(f2 > frame and act2 == "release" and btn2 == button
                           for f2, act2, btn2 in events if f2 <= total_frames)
            if not released:
                bot.send_and_wait(f"input_release {button}",
                                  "ok input_release", timeout=5)


def _advance_with_watchpoint(bot, frames, verbose=False):
    """Advance frames, handling watchpoint interrupts."""
    remaining = frames
    for _ in range(frames + 10):
        if remaining <= 0:
            break
        bot.send(f"frame_advance {remaining}")
        ack = bot.wait_ack(["done frame_advance", "hit watchpoint"],
                           timeout=max(remaining, 30))
        if not ack:
            break
        if "hit watchpoint" in ack:
            if verbose:
                print(f"  Watchpoint hit, resuming...")
            remaining -= 1
            continue
        if "done frame_advance" in ack:
            break


# --- Address Resolution ---

def _fmt_addr(addr):
    """Format an integer address as hex without 0x prefix."""
    return f"{addr:08X}"


def resolve_address(addr_spec, bot, function_addr, verbose=False):
    """Resolve an address specification to an absolute address.

    Supports:
    - Plain int or "0x..." hex string
    - "GBR+N" — break at function_addr, read GBR register, add N
    """
    if isinstance(addr_spec, int):
        return addr_spec

    if isinstance(addr_spec, str) and addr_spec.startswith("0x"):
        return int(addr_spec, 16)

    if isinstance(addr_spec, str) and addr_spec.startswith("GBR+"):
        offset = int(addr_spec[4:])
        if verbose:
            print(f"  Resolving {addr_spec}: breaking at {_fmt_addr(function_addr)} to read GBR...")

        bot.send_and_wait(f"breakpoint {_fmt_addr(function_addr)}", "ok breakpoint", timeout=10)
        bot.send("run")
        ack = bot.wait_ack("break ", timeout=30)
        if not ack or "break " not in ack:
            print(f"  WARN: breakpoint at {_fmt_addr(function_addr)} not hit within timeout")
            bot.send_and_wait("breakpoint_clear", "breakpoint_clear", timeout=5)
            return None

        reg_ack = bot.send_and_wait("dump_regs", "GBR=", timeout=10)
        bot.send_and_wait("breakpoint_clear", "breakpoint_clear", timeout=5)

        if not reg_ack:
            print(f"  WARN: could not read registers")
            return None

        gbr_val = None
        for part in reg_ack.split():
            if part.startswith("GBR="):
                raw = part[4:].replace("0x", "").replace("0X", "")
                gbr_val = int(raw, 16)
                break

        if gbr_val is None:
            print(f"  WARN: GBR not found in register dump")
            return None

        resolved = gbr_val + offset
        if verbose:
            print(f"  Resolved: GBR=0x{gbr_val:08X} + {offset} = 0x{resolved:08X}")

        bot.send_and_wait("frame_advance 1", "done frame_advance", timeout=10)
        return resolved

    raise ValueError(f"Unknown address format: {addr_spec!r}")


# --- Test Implementations ---

def test_writes_to(claim, bot, ctx, verbose=False):
    """Test: does function F write to address A?"""
    scenario = claim.get("scenario", "")
    frames = claim.get("frames", 60)

    func_start = int(claim["function"][4:], 16)
    func_end = claim.get("function_end")
    if isinstance(func_end, str):
        func_end = int(func_end, 16)

    _load_scenario(bot, ctx, scenario, verbose)

    target_addr = resolve_address(claim["address"], bot, func_start, verbose)
    if target_addr is None:
        return False, "Could not resolve target address"

    if _is_playback(ctx["inputs"], scenario):
        pass  # playback handles inputs
    elif not _is_timed(ctx["inputs"], scenario):
        _apply_simple_inputs(bot, ctx["inputs"], scenario)

    bot.send_and_wait(f"watchpoint {_fmt_addr(target_addr)}", "ok watchpoint", timeout=5)

    if verbose:
        print(f"  Watchpoint set at {_fmt_addr(target_addr)}, advancing {frames} frames...")

    if _is_timed(ctx["inputs"], scenario) and not _is_playback(ctx["inputs"], scenario):
        # Timed inputs with watchpoint — need to interleave
        events = [(f, a, b) for f, a, b in ctx["inputs"][scenario] if f <= frames]
        current_frame = 0
        for frame, action, button in events:
            if frame > current_frame:
                delta = frame - current_frame
                remaining = delta
                while remaining > 0:
                    bot.send(f"frame_advance {remaining}")
                    ack = bot.wait_ack(["done frame_advance", "hit watchpoint"],
                                       timeout=max(remaining, 30))
                    if not ack:
                        break
                    if "hit watchpoint" in ack:
                        remaining -= 1
                        continue
                    break
                current_frame = frame
            if action == "press":
                bot.send_and_wait(f"input {button}", "ok input", timeout=5)
            elif action == "release":
                bot.send_and_wait(f"input_release {button}", "ok input_release", timeout=5)
        remaining = frames - current_frame
        while remaining > 0:
            bot.send(f"frame_advance {remaining}")
            ack = bot.wait_ack(["done frame_advance", "hit watchpoint"],
                               timeout=max(remaining, 30))
            if not ack:
                break
            if "hit watchpoint" in ack:
                remaining -= 1
                continue
            break
    else:
        _advance_with_watchpoint(bot, frames, verbose)

    hits_path = os.path.join(ctx["ipc_dir"], "watchpoint_hits.txt")
    hits = _parse_watchpoint_hits(hits_path)

    bot.send_and_wait("watchpoint_clear", "ok watchpoint_clear", timeout=5)

    if not _is_playback(ctx["inputs"], scenario) and not _is_timed(ctx["inputs"], scenario):
        _release_simple_inputs(bot, ctx["inputs"], scenario)

    if func_end:
        my_hits = [h for h in hits if func_start <= h["pc"] < func_end]
    else:
        my_hits = [h for h in hits if h["pc"] == func_start]

    passed = len(my_hits) > 0
    detail = f"{len(my_hits)} hits from function, {len(hits)} total watchpoint hits"
    return passed, detail


def test_call_count_per_frame(claim, bot, ctx, verbose=False):
    """Test: how many times is function F called per frame?"""
    scenario = claim.get("scenario", "")
    func_addr = claim["address"]
    if isinstance(func_addr, str):
        func_addr = int(func_addr, 16)
    expected = claim["expected_count"]
    tolerance = claim.get("tolerance", 5)

    _load_scenario(bot, ctx, scenario, verbose)

    if _is_playback(ctx["inputs"], scenario):
        pass
    elif not _is_timed(ctx["inputs"], scenario):
        _apply_simple_inputs(bot, ctx["inputs"], scenario)
    else:
        for frame, action, button in ctx["inputs"][scenario]:
            if frame == 0 and action == "press":
                bot.send_and_wait(f"input {button}", "ok input", timeout=5)

    bot.send_and_wait(f"breakpoint {_fmt_addr(func_addr)}", "ok breakpoint", timeout=5)

    if verbose:
        print(f"  Breakpoint at {_fmt_addr(func_addr)}, counting hits in 1 frame...")

    hit_count = 0
    ref_frame = None

    for _ in range(200):
        bot.send("run")
        ack = bot.wait_ack("break ", timeout=10)
        if not ack or "break " not in ack:
            break
        current_frame = _parse_frame_from_ack(ack)
        if ref_frame is None:
            ref_frame = current_frame
        if current_frame is not None and current_frame > ref_frame:
            break
        hit_count += 1

    bot.send_and_wait("breakpoint_clear", "breakpoint_clear", timeout=5)

    if _is_playback(ctx["inputs"], scenario):
        pass
    elif not _is_timed(ctx["inputs"], scenario):
        _release_simple_inputs(bot, ctx["inputs"], scenario)
    else:
        for frame, action, button in ctx["inputs"][scenario]:
            if frame == 0 and action == "press":
                bot.send_and_wait(f"input_release {button}", "ok input_release", timeout=5)

    passed = abs(hit_count - expected) <= tolerance
    detail = f"{hit_count} calls (expected {expected} +/- {tolerance})"
    return passed, detail


def test_value_changes_with_input(claim, bot, ctx, verbose=False):
    """Test: does value at A change in expected direction with input?"""
    frames = claim.get("frames", 60)
    input_btn = claim.get("input", "none")
    direction = claim["direction"]
    scenario = claim.get("scenario", "")

    func_addr = claim.get("_parent_address", 0)

    _load_scenario(bot, ctx, scenario, verbose)

    target_addr = resolve_address(claim["address"], bot, func_addr, verbose)
    if target_addr is None:
        return False, "Could not resolve target address"

    before = _read_u32(bot, target_addr, ctx["ipc_dir"])
    if before is None:
        return False, "Could not read before value"

    if verbose:
        print(f"  Before: {target_addr:#010x} = 0x{before:08X} ({before})")

    if _is_playback(ctx["inputs"], scenario):
        bot.send_and_wait(f"frame_advance {frames}", "done frame_advance",
                          timeout=max(frames, 30))
    elif _is_timed(ctx["inputs"], scenario):
        _advance_with_timed_inputs(bot, ctx["inputs"], scenario, frames, verbose)
    else:
        if input_btn and input_btn != "none":
            bot.send_and_wait(f"input {input_btn}", "ok input", timeout=5)
        bot.send_and_wait(f"frame_advance {frames}", "done frame_advance",
                          timeout=max(frames, 30))
        if input_btn and input_btn != "none":
            bot.send_and_wait(f"input_release {input_btn}", "ok input_release", timeout=5)

    after = _read_u32(bot, target_addr, ctx["ipc_dir"])
    if after is None:
        return False, "Could not read after value"

    if verbose:
        print(f"  After:  {target_addr:#010x} = 0x{after:08X} ({after})")

    before_s = struct.unpack('>i', struct.pack('>I', before))[0]
    after_s = struct.unpack('>i', struct.pack('>I', after))[0]

    if direction == "increases":
        passed = after_s > before_s
    elif direction == "decreases":
        passed = after_s < before_s
    else:
        return False, f"Unknown direction: {direction}"

    detail = f"before={before_s}, after={after_s}, direction={direction}"
    return passed, detail


def test_value_stable(claim, bot, ctx, verbose=False):
    """Test: does value at A stay constant when idle?"""
    frames = claim.get("frames", 60)
    scenario = claim.get("scenario", "")

    func_addr = claim.get("_parent_address", 0)

    _load_scenario(bot, ctx, scenario, verbose)

    target_addr = resolve_address(claim["address"], bot, func_addr, verbose)
    if target_addr is None:
        return False, "Could not resolve target address"

    before = _read_u32(bot, target_addr, ctx["ipc_dir"])
    if before is None:
        return False, "Could not read before value"

    bot.send_and_wait(f"frame_advance {frames}", "done frame_advance",
                      timeout=max(frames, 30))

    after = _read_u32(bot, target_addr, ctx["ipc_dir"])
    if after is None:
        return False, "Could not read after value"

    passed = before == after
    detail = f"before=0x{before:08X}, after=0x{after:08X}"
    return passed, detail


# --- Helpers ---

def _load_scenario(bot, ctx, scenario, verbose=False):
    """Load save state and start input playback if applicable."""
    state_path = ctx["save_states"].get(scenario)
    if not state_path:
        raise ValueError(f"Unknown scenario: {scenario}")

    if not _is_playback(ctx["inputs"], scenario):
        bot.send_and_wait("frame_advance 1", "done frame_advance", timeout=10)

    ack = bot.send_and_wait(f"load_state {_win_path(state_path)}", "load_state", timeout=15)
    if not ack or "error" in ack.lower():
        raise RuntimeError(f"Failed to load save state: {ack}")

    if _is_playback(ctx["inputs"], scenario):
        playback_path = ctx["playbacks"].get(scenario, "")
        if playback_path:
            bot.send_and_wait(
                f"input_playback {_win_path(playback_path)}",
                "ok input_playback", timeout=5)
            if verbose:
                print(f"  Input playback started: {os.path.basename(playback_path)}")
    else:
        bot.send_and_wait("frame_advance 2", "done frame_advance", timeout=10)

    if verbose:
        print(f"  Loaded scenario '{scenario}'")


def _parse_watchpoint_hits(hits_path):
    """Parse watchpoint_hits.txt into list of dicts."""
    hits = []
    if not os.path.exists(hits_path):
        return hits
    with open(hits_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            hit = {}
            for part in line.split():
                if "=" in part:
                    key, val = part.split("=", 1)
                    if key in ("pc", "pr", "addr", "old", "new"):
                        hit[key] = int(val, 16)
                    elif key == "frame":
                        hit[key] = int(val)
                    else:
                        hit[key] = val
            if "pc" in hit:
                hits.append(hit)
    return hits


def _read_u32(bot, addr, ipc_dir):
    """Read a 32-bit big-endian value from memory."""
    out_path = os.path.join(ipc_dir, "u32_tmp.bin")
    if os.path.exists(out_path):
        os.remove(out_path)
    ack = bot.send_and_wait(
        f"dump_mem_bin {_fmt_addr(addr)} 4 {_win_path(out_path)}",
        "dump_mem_bin", timeout=10,
    )
    if not ack:
        return None
    time.sleep(0.1)
    if not os.path.exists(out_path):
        return None
    with open(out_path, "rb") as f:
        data = f.read(4)
    if len(data) < 4:
        return None
    return struct.unpack(">I", data)[0]


def _parse_frame_from_ack(ack):
    """Extract frame=N from an ack string."""
    for part in ack.split():
        if part.startswith("frame="):
            try:
                return int(part[6:])
            except ValueError:
                pass
    return None


# --- Test Dispatch ---

TEST_TYPES = {
    "writes_to": test_writes_to,
    "call_count_per_frame": test_call_count_per_frame,
    "value_changes_with_input": test_value_changes_with_input,
    "value_stable": test_value_stable,
}


# --- Main ---

def run_claims(claim_file, project_dir, only_claim=None, verbose=False):
    """Load claim file, boot emulator, run all claims, report results."""
    config = _load_project_config(project_dir)

    with open(claim_file) as f:
        data = yaml.safe_load(f)

    function = data.get("function", "unknown")
    claims = data.get("claims", [])
    parent_addr = data.get("address", 0)
    if isinstance(parent_addr, str):
        parent_addr = int(parent_addr, 16)

    if only_claim:
        claims = [c for c in claims if c.get("id") == only_claim]
        if not claims:
            print(f"No claim with id '{only_claim}' found")
            return []

    print(f"Testing {function} -- {len(claims)} claim(s)")
    print(f"Source: {data.get('source_file', 'unknown')}")
    print()

    # Build context from config
    cue_path = config.get("cue_path", "")
    if cue_path and not os.path.isabs(cue_path):
        cue_path = os.path.join(project_dir, cue_path)

    med_config = config.get("mednafen", {})

    # Oracle uses its own IPC directory — separate from the MCP server's
    # to avoid stale artifacts (traces, snapshots) causing crashes
    ipc_dir = os.path.join(project_dir, "build", "oracle_ipc")

    # Use project's home dir for config/firmware
    home_dir = med_config.get("home_dir", "build/mednafen_home")
    if not os.path.isabs(home_dir):
        home_dir = os.path.join(project_dir, home_dir)

    ctx = {
        "save_states": _resolve_save_states(config, project_dir),
        "inputs": _resolve_scenario_inputs(config),
        "playbacks": _resolve_playback_files(config, project_dir),
        "ipc_dir": ipc_dir,
    }

    os.makedirs(ipc_dir, exist_ok=True)

    bot = MednafenBot(ipc_dir, cue_path, home_dir=home_dir, verbose=verbose)
    print("Starting Mednafen...")
    if not bot.start(timeout=30):
        print("FAIL: Mednafen did not start")
        return []

    print("Mednafen ready.\n")

    hits_path = os.path.join(ipc_dir, "watchpoint_hits.txt")

    results = []
    for claim in claims:
        claim_id = claim.get("id", "unnamed")
        claim_type = claim["type"]
        description = claim.get("description", "")

        print(f"  [{claim_id}] {description}")

        if claim_type not in TEST_TYPES:
            print(f"    SKIP -- unknown test type: {claim_type}")
            results.append({"id": claim_id, "passed": None, "detail": "unknown type"})
            continue

        claim["_parent_address"] = parent_addr

        try:
            if os.path.exists(hits_path):
                os.remove(hits_path)
        except PermissionError:
            pass

        try:
            passed, detail = TEST_TYPES[claim_type](claim, bot, ctx, verbose)
        except Exception as e:
            passed, detail = False, f"ERROR: {e}"

        status = "PASS" if passed else "FAIL"
        print(f"    {status} -- {detail}")
        results.append({"id": claim_id, "passed": passed, "detail": detail})

    bot.quit()

    print()
    total = len(results)
    passed_count = sum(1 for r in results if r["passed"])
    types_passed = set()
    for r, c in zip(results, claims):
        if r["passed"]:
            types_passed.add(c["type"])

    if passed_count == 0:
        tier = 0
    elif passed_count >= 3 and len(types_passed) >= 2:
        tier = 2
    else:
        tier = 1

    print(f"Results: {passed_count}/{total} passed -- Tier {tier}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Run auto_re claim tests")
    parser.add_argument("claim_file", help="Path to YAML claim file")
    parser.add_argument("--project", "-p", default=None,
                        help="Project directory (default: current directory)")
    parser.add_argument("--claim", help="Run only this claim ID")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    project_dir = args.project or os.getcwd()
    results = run_claims(args.claim_file, project_dir, args.claim, args.verbose)

    if any(r["passed"] for r in results):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
