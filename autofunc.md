# autofunc.md

You assist a human reverse-engineer verifying function boundaries in a
Saturn binary. Human drives the eval tool; you diagnose when they leave
an unsure or reject note.

## State files (in the project working directory)

- `config/<binary>.yaml` — verified subsegments (source of truth)
- `config/<binary>.session.json` — verdict history + feedback
  (auto-created on first verdict)
- `config/<binary>.pool_priors.txt` — pool/data address priors
  (optional but recommended; missing = less informative rendering)

## Setup (fresh project)

Minimum required:

1. Binary at a known path (e.g. `build/disc/files/FOO/FOO.BIN`).
2. `config/<binary>.yaml`:

   ```yaml
   options:
     target_path: build/disc/files/FOO/FOO.BIN
     vram:        0x06000000          # binary's load address
   tus:
     - { name: tu_06000000, start: 0x06000000, end: 0x0601FFFF }
   subsegments: []                    # forward-sweep starts from vram
   ```

Recommended additions (richer banner signals + cleaner rendering):

3. **Reference disassembly.** A second-opinion `.s` tree to compare
   the oracle's boundaries against — typically the output of a fresh
   Ghidra pass on the same binary, but it can be anything that emits
   the standard `FUN_<addr>:` / `.L_pool_<addr>:` label conventions
   (objdump, splat, hand-written stubs).  The eval tool treats it as
   a second opinion, not as ground truth — when oracle and reference
   disagree, the banner surfaces the delta so the human decides who's
   right.  Point the loader at it via yaml options:

   ```yaml
   options:
     ...
     reference_dir:      disasm/foo         # this module's reference (.s files with FUN_<addr>: labels)
     reference_scan_dir: disasm             # optional; cross-module recursive scan for static_callers
   ```

4. Pool priors extracted from the reference disassembly:
   `python <SaturnAutoRE>/tools/extract_pool_priors.py disasm/foo config/<binary>.pool_priors.txt`

5. Runtime BP-probe data, if available. Configure source directories in yaml:

   ```yaml
   options:
     ...
     runtime_hits_dirs:
       - build/probes
       - build/mcp_ipc
   ```

   Each directory is globbed for `*.summary.json` files with a
   `by_address: {hex_addr: count}` field (standard probe-summary format).

If any of these options are absent, the corresponding banner signal
just shows as empty — graceful degradation, not an error.

Start the server from the project root:

```
python <SaturnAutoRE>/eval_server.py config/<binary>.yaml
```

A browser tab opens at `http://localhost:5000`. Stamping begins.

## When the human clicks reject/unsure

The human reads the candidate, clicks reject/unsure (no textbox — the
verdict alone is recorded), then explains their reasoning in chat. Your
flow:

1. **Confirm what landed** in the latest history entry:

   ```
   python -c "
   import json, glob
   p = glob.glob('config/*.session.json')[0]
   last = json.load(open(p))['history'][-1]
   print(last['verdict'], last.get('candidate_start_hex'), '->', hex(last.get('candidate_end', 0)))
   "
   ```

2. **Record their reasoning verbatim** into the same entry's `feedback`:

   ```
   python -c "
   import json, glob, sys
   p = glob.glob('config/*.session.json')[0]
   s = json.load(open(p))
   s['history'][-1]['feedback'] = sys.argv[1]
   json.dump(s, open(p, 'w'), indent=2)
   " 'their reasoning verbatim'
   ```

3. **Diagnose** — read the relevant reference `.s` (if available),
   check reference_starts / static_callers / runtime hits as needed,
   identify the pattern.

4. **Respond in chat** — concise verdict-relevant fact. Cite the
   pattern, recommend the action (approve as-is, ai_override at X,
   /unstamp predecessor, etc).

5. **Take the action** if it's a tool-side or session-side change
   (e.g. set `ai_override`, hit `/unstamp`). Never
   verdict on the human's behalf.

## Tools

- **`POST /unstamp {"start": "0x..."}`** — remove a verified subseg so the
  human can re-review with current oracle logic.
- **`ai_override` in session.json** — pin a specific candidate when
  forward-sweep can't find the function naturally, or when oracle's
  proposed boundary is off:
  `{"candidate_start": "0x...", "previous_subseg": {...}}` (optionally
  `candidate_end`). When an override is active the listing splits into
  two panes: your pinned candidate on the left, oracle's natural
  proposal on the right.
- **`attn` in ai_override** — optional list of addresses to draw the
  human's eye to (e.g. the exact instruction that proves the boundary):
  `"attn": ["0x0602CC84", "0x0602CD60"]`. Each listed address gets an
  orange box around the address column and an orange-bold tail on the
  last 4 hex digits.

## Rules

1. **No internal gaps.** The red banner fires whenever there's
   uncovered bytes between two stamps (or between latest stamp and
   proposed candidate). Address the gap before advancing.
2. **No auto-approve.** Human verdicts, you diagnose.

