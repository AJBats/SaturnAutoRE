# SaturnAutoRE — Autonomous Reverse Engineering Pipeline

[![Demo Video](https://img.youtube.com/vi/wgwie6i-ASU/maxresdefault.jpg)](https://www.youtube.com/watch?v=wgwie6i-ASU)

A reusable harness for reverse engineering Sega Saturn games using Claude
and the Mednafen emulator. A CLI guides the agent through a structured
explore → verify → integrate cycle, with NOP testing, graduation, call
graph analysis, memory diffing, and more.

Every command output ends with the next command to run. The agent never
has to decide what to do — the tool decides.

## Setup

### 1. Build Mednafen

The emulator lives in `mednafen/` as a git submodule. Build once in WSL:

```bash
cd mednafen
wsl bash build_with_gcc494.sh         # release build
wsl bash build_with_gcc494.sh --debug # debug build (symbols + crash dumps)
```

Requires GCC 4.9.4 MinGW cross-compiler at `/opt/gcc-4.9.4-mingw64/` in WSL.

### 2. Set up your game project

Create the directory structure and config from the templates in this repo:

```bash
# In your game project directory:
mkdir -p workstreams/auto_re/observations
mkdir -p workstreams/auto_re/claims
mkdir -p build/save_states build/samples build/mcp_ipc build/mednafen_home

# Copy and fill in the essentials:
cp /path/to/SaturnAutoRE/templates/config.yaml  workstreams/auto_re/config.yaml
cp /path/to/SaturnAutoRE/templates/mission.md    workstreams/auto_re/mission.md
cp /path/to/SaturnAutoRE/templates/mcp.json      .mcp.json
```

Edit `config.yaml` with your game's disc image path, save states, memory
regions, and controls. Edit `mission.md` with what you're trying to reverse
engineer. Edit `.mcp.json` to point to this repo's `mednafen/mcp_server.py`.

### 3. Create save states

Boot the game in Mednafen, navigate to the gameplay situations you want to
investigate, and save state. Add each to `config.yaml` under `save_states:`.
This is the one step that requires a human playing the game.

### 4. Point your Claude at the entry point

From your game project directory, tell Claude:

> Read `/path/to/SaturnAutoRE/auto_re.py` and run `python /path/to/SaturnAutoRE/auto_re.py status`

The CLI will take over from there — every command tells the agent exactly
what to do next. The templates in this repo are self-documenting, and
`auto_re.py tools` lists every available debugger capability.

## How It Works

```
status → pick → explore → explore-check → verify → integrate
                                                       ↓
                          review ← graduate ← nop-candidates
                            ↓
                          status → pick → ...
```

The agent uses the Mednafen debugger (via MCP server) to set breakpoints,
watchpoints, capture memory samples, trace calls, and profile reads/writes.
Observations become testable claims, claims get tested mechanically against
the emulator, and confirmed functions graduate to human-readable names.

NOP tests are interactive — the agent pokes instructions at runtime and the
human observes the visual result.

## What's In This Repo

| Path | Purpose |
|------|---------|
| `auto_re.py` | CLI entry point (11 commands) |
| `test_claim.py` | Oracle test runner |
| `lib/` | Config, pipeline state, claim generation, call graphs, memdiff |
| `tools/del_recon.py` | Dependency recon for safe function deletion |
| `watchdog.py` | Agent stall detection and auto-nudge (experimental, untested) |
| `templates/` | Config, mission, observation, NOP experiment, save state templates |
| `mednafen/` | Emulator submodule with automation, MCP server, debug features |
