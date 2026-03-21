# Save States Catalog

Reference for all save states used in the auto_re pipeline.
Each entry documents the game state, temporal boundaries, and known constraints.

Place this file at `workstreams/auto_re/save_states.md` in your project.
Update it whenever a new save state is created.

## example_state.mc0

- **Mode**: Game mode (level, menu, cutscene, etc.)
- **Scene**: What's on screen — describe the gameplay situation
- **Player control**: What input is available (full control, limited, none)
- **Known constraints**:
  - How many frames before the scene changes or becomes invalid
  - Any events that happen at specific frames (enemy spawn, transition, etc.)
  - Frame rate (30fps or 60fps)
- **Best for**: What this save state is good for investigating
- **Avoid for**: What this save state is NOT suitable for

### Scenarios (deterministic replay)

Scenarios come in three types depending on input complexity.

#### Simple scenarios — hold buttons for the entire run

Load state → hold inputs → advance N frames. Use for steady-state testing
(constant throttle, constant steer, idle).

| Scenario | Inputs | Frames | Expected outcome |
|----------|--------|--------|------------------|
| **scenario_name** | button (hold) | N | What happens during this replay |

In config.yaml:
```yaml
scenario_name:
  file: build/save_states/example_state.mc0
  inputs: [C]
  frames: 300
```

#### Timed scenarios — press/release at specific frames

Load state → apply input events at precise frame numbers. Use when you need
button taps, gear shifts, or input changes mid-scenario.

| Frame | Event | Notes |
|-------|-------|-------|
| 0 | PRESS C | Throttle from start |
| 190 | PRESS DOWN | Gear shift |
| 195 | RELEASE DOWN | |

In config.yaml:
```yaml
scenario_name:
  file: build/save_states/example_state.mc0
  inputs:
    - [0, press, C]
    - [190, press, DOWN]
    - [195, release, DOWN]
  frames: 300
```

#### Playback scenarios — recorded input file

For complex input sequences (collision setups, multi-phase maneuvers),
record the inputs once and replay them exactly. The emulator handles
input injection at the correct frames — no manual frame-stepping needed.

**Creating a playback recording:**
1. Boot the game, load the save state
2. Start input recording: `input_record_start <path>`
3. Play the scenario manually (the emulator logs every button event)
4. Stop recording: `input_record_stop`
5. The recording file is a text file with frame-accurate button events

**Using a playback recording:**
```
load_state build/save_states/example_state.mc0
input_playback_start build/save_states/example_playback.input.txt
sample_memory <addr> <size> <frames> <output>
```

The playback injects inputs automatically while other commands (sample_memory,
frame_advance, watchpoints) run normally. This is how you test scenarios that
require precise timing — like grazing another car at exactly the right angle.

Document the key events in the playback:

| Frame | Event | Notes |
|-------|-------|-------|
| 0 | PRESS C | Throttle from rolling start |
| 33 | PRESS LEFT | First steer toward target |
| 38 | RELEASE LEFT | |
| 100-130 | — | Contact event (sparks visible) |
| 131 | PRESS START | Pause after event |

**Input recording**: `build/save_states/example_playback.input.txt`

In config.yaml:
```yaml
scenario_name:
  file: build/save_states/example_state.mc0
  playback: build/save_states/example_playback.input.txt
  frames: 140
```
