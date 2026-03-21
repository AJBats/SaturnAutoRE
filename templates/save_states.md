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

All scenarios: load state → hold inputs → advance N frames.

| Scenario | Inputs | Frames | Expected outcome |
|----------|--------|--------|------------------|
| **scenario_name** | button (hold) | N | What happens during this replay |
