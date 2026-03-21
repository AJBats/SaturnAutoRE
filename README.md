# SaturnAutoRE — Autonomous Reverse Engineering Pipeline

A reusable harness for reverse engineering Sega Saturn games using Claude
and the Mednafen emulator. Provides a CLI that guides a single Claude agent
through a structured explore → verify → integrate cycle.

## What This Is

You give it a Saturn game project. It gives you a pipeline that:
1. Picks functions to investigate (from priorities or call-chain exploration)
2. Validates observation reports for completeness
3. Generates testable claims from observation data
4. Runs claims against the emulator (oracle testing)
5. Tracks progress and tells the agent what to do next

Every command output ends with the next command to run. The agent never
has to decide what to do — the tool decides.

## Quick Start — Setting Up a New Project

### Prerequisites

- A Saturn game project directory with:
  - A disc image (.cue/.bin) of the game
  - Mednafen save states for in-game scenarios (human creates these)
  - Optionally: disassembled code (not required for early-stage RE)
- Python 3 with `pyyaml` installed
- The Mednafen emulator built (see "Building Mednafen" below)

### Step 1: Create the auto_re directory structure

In your game project directory:

```bash
mkdir -p workstreams/auto_re/observations
mkdir -p workstreams/auto_re/claims
mkdir -p workstreams/auto_re/reviews
mkdir -p build/save_states
mkdir -p build/samples
mkdir -p build/mcp_ipc
mkdir -p build/mednafen_home
```

### Step 2: Create config.yaml

Copy `templates/config.yaml` from this repo to your project at
`workstreams/auto_re/config.yaml`. Fill in:

```yaml
game_name: "Your Game Name"

# Where disassembled code lives (relative to project root)
# Leave empty if no disassembly exists yet
assembly_dir: ""

# Memory regions to investigate. Name them whatever makes sense.
# You may not know these yet — add them as you discover them.
targets:
  # Example for a 3D game:
  # vdp1_vram:
  #   base: 0x25C00000
  #   stride: 0
  #   count: 1
  #   addressing: direct
  #   notes: "VDP1 command table"

# Game controls — map roles to Saturn buttons
# Use whatever roles make sense for your game
controls:
  # Examples:
  # throttle: C
  # shoot: A
  # jump: B

# Save states — each is a scenario for deterministic testing
# Human creates these by playing the game and saving at key moments
save_states: {}
  # Example:
  # level1_start:
  #   file: build/save_states/level1.mc0
  #   inputs: []
  #   frames: 300
  #   notes: "Level 1, player standing still, enemies approaching"

# Where to store accumulated RE knowledge (relative to project root)
knowledge_base: workstreams/auto_re/struct_map.md

# Disc image path (relative to project root)
cue_path: "external_resources/Your Game/Your Game.cue"

# Mednafen IPC and home directories (for parallel operation)
mednafen:
  ipc_dir: build/mcp_ipc
  home_dir: build/mednafen_home
```

### Step 3: Write mission.md

Copy `templates/mission.md` to `workstreams/auto_re/mission.md`. This is
the most important file — it tells the agent what to investigate and why.

```markdown
# Mission — Your Game

## Objective

What are you trying to understand? Be specific about what "done" looks like.

## What We Know

Starting knowledge — known addresses, confirmed fields, prior discoveries.

## What We Need to Find

Specific unknowns. Each should be concrete enough to investigate.

## Phases

### Phase 1: [First thing to investigate]
What to look for, how to look for it.

## Game-Specific Context

Controls, game modes, hardware usage, frame timing, anything relevant.
```

### Step 4: Set up the Mednafen MCP server

Create `.mcp.json` in your project root. This connects Claude Code to the
Mednafen debugger:

```json
{
  "mcpServers": {
    "mednafen": {
      "type": "stdio",
      "command": "python",
      "args": [
        "REPLACE_WITH_PATH/SaturnAutoRE/mednafen/mcp_server.py",
        "--ipc-dir",
        "build/mcp_ipc",
        "--home-dir",
        "build/mednafen_home"
      ],
      "env": {}
    }
  }
}
```

Replace `REPLACE_WITH_PATH` with the actual path to this SaturnAutoRE repo.

### Step 5: Create save states

This requires a human. Boot the game in Mednafen, navigate to the gameplay
situation you want to investigate, and save state. Document each save state
in `build/save_states/README.md` with:
- What game mode/level/screen
- What's happening (player position, speed, enemies, etc.)
- What inputs to hold for deterministic replay

Add each save state to your `config.yaml` under `save_states:`.

### Step 6: Run the pipeline

From your project directory:

```bash
# See current status and what to do next
python /path/to/SaturnAutoRE/auto_re.py status

# Pick a function to investigate
python /path/to/SaturnAutoRE/auto_re.py pick

# After investigating, validate the observation
python /path/to/SaturnAutoRE/auto_re.py explore-check FUN_XXXXXXXX

# Generate claims and test them
python /path/to/SaturnAutoRE/auto_re.py verify FUN_XXXXXXXX

# Check results and get next action
python /path/to/SaturnAutoRE/auto_re.py integrate
```

Each command tells you what to do next. Follow the chain.

## The Pipeline Cycle

```
pick → investigate with debugger → explore-check → verify → integrate → pick
                                        ↑                        |
                                        └── fix observation ─────┘
```

1. **Pick** — select next function from priorities or call-chain
2. **Explore** — use Mednafen debugger (breakpoints, watchpoints, memory
   sampling) to observe what the function does at runtime
3. **Explore-check** — validate the observation report has all required
   sections (call frequency, register context, memory writes, field analysis)
4. **Verify** — auto-generate claims from observation data and test them
   against the emulator (oracle)
5. **Integrate** — review results, update knowledge base, pick next target

## Observation Reports

Each investigated function gets an observation report at
`workstreams/auto_re/observations/FUN_XXXXXXXX_obs.md`. The report must
include:

- **YAML frontmatter** — function address, scenarios tested, reachability
- **Call Frequency** — how many times per frame in each scenario
- **Register Context** — register values at function entry
- **Memory Writes** — watchpoint data showing what the function writes
- **Per-Frame Field Analysis** — behavioral classification of fields from
  sample CSV data (MANDATORY — the pipeline gates on this)

See `templates/observation_report.md` for the full template.

## Claim Types

The oracle tests 4 types of claims:

| Type | What it tests |
|------|---------------|
| `writes_to` | Function F writes to address A during scenario S |
| `call_count_per_frame` | Function F is called N±T times per frame |
| `value_changes_with_input` | Value at A increases/decreases with input I |
| `value_stable` | Value at A stays constant when idle |

Claims are generated automatically from observation data. The oracle
(`tools/test_claim.py` in your project) runs them mechanically against
Mednafen.

## Tier System

- **Tier 0** — no claims passed (hypothesis only)
- **Tier 1** — 1 claim passed (one empirical data point)
- **Tier 2** — 3+ claims passed, 2+ types, at least 1 function-specific

Function-specific means the claim tests something unique to this function
(e.g., `writes_to` with a PC in the function's range), not a generic
`value_stable` on a globally static field.

## Building Mednafen

The emulator lives in `mednafen/` as a git submodule. Build it once:

```bash
cd mednafen
wsl bash build_with_gcc494.sh
```

This cross-compiles a Windows `.exe` using GCC 4.9.4 in WSL. The build
takes a few minutes. The resulting `src/mednafen.exe` is used by all
projects.

Prerequisites for building:
- WSL with the GCC 4.9.4 MinGW cross-compiler at `/opt/gcc-4.9.4-mingw64/`
- SDL2, FLAC, zlib, iconv dev packages for MinGW

## File Layout

```
SaturnAutoRE/                          ← this repo (the harness)
  auto_re.py                           ← CLI entry point
  lib/
    config.py                          ← project config loader
    pipeline.py                        ← filesystem-based state tracking
    claim_generator.py                 ← observation → claims
  templates/
    config.yaml                        ← template for new projects
    mission.md                         ← template for RE mission
    observation_report.md              ← template for function observations
    mcp.json                           ← template for MCP server config
  mednafen/                            ← emulator submodule (shared)

YourGameProject/                       ← your project (uses the harness)
  workstreams/auto_re/
    config.yaml                        ← game-specific parameters
    mission.md                         ← RE objective and phases
    observations/                      ← function observation reports
    claims/                            ← generated claim YAML files
    reviews/                           ← reviewer feedback (optional)
  build/
    save_states/                       ← emulator save states
    samples/                           ← per-frame memory capture CSVs
    mcp_ipc/                           ← MCP server IPC (auto-created)
    mednafen_home/                     ← Mednafen config dir (auto-created)
  tools/
    test_claim.py                      ← oracle test runner
  .mcp.json                           ← MCP server config (points here)
```

## Projects Using This Pipeline

This pipeline has been used to reverse engineer driving model physics
across two Saturn racing games, producing 40+ Tier 2 verified functions,
10+ NOP-confirmed field identities, and a complete force→velocity→position
pipeline map.
