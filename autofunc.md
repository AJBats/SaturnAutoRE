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

## When you're called in to diagnose

Two cases — same diagnosis steps, different source of truth for "what's
on screen":

### A) Live mid-stream question — "is the current candidate right?"

The human hasn't verdicted yet. The currently displayed candidate is
**not in session.json yet**; it's in `/state`. Read it:

```
curl -s http://localhost:5000/state | python -m json.tool
```

Skip to "Diagnose" below.

### B) Post-verdict — the human clicked reject/unsure

The verdict (without text) is now the last entry in session.json. Your
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

### Diagnose (both cases)

3. **Diagnose** — start with `candidate.yellow_flags` from `/state`
   (often a smoking gun: `"no prologue register pushes detected"`
   means the proposed start is mid-function; `"no clean rts at
   expected position"` means the end is wrong). Then check
   `candidate.reference.verdict`, `candidate.evidence.static_callers`,
   midpoints, and the reference `.s` as needed.

4. **Respond in chat** — concise verdict-relevant fact. Cite the
   pattern, recommend the action (approve as-is, ai_override at X,
   /unstamp predecessor, etc).

5. **Take the action** if it's a tool-side or session-side change
   (e.g. set `ai_override`, hit `/unstamp`). Never verdict on the
   human's behalf.

## Tools

- **`GET /state`** — the currently displayed candidate plus all evidence.
  Source of truth for live mid-stream questions. Key fields:
  - `candidate.start_hex` / `end_hex` — proposed boundaries.
  - `candidate.yellow_flags` — list of strings from oracle's structural
    check. Highest-signal diagnostic. Examples: `"no prologue register
    pushes detected"` (proposed start is mid-function), `"no clean rts
    at expected position"` (end is wrong), `"stack alloc/dealloc
    mismatch: 8 vs 4"`, `"prologue/epilogue register order mismatch:
    pushed [r8,r9], restored [r9,r8]"`.
  - `candidate.reference.verdict` — `"agrees"` / `"disagrees"` /
    `"silent"`. `silent` = reference has no `FUN_<start>` at the
    proposed address. `disagrees` includes an `end_delta` in bytes.
  - `candidate.evidence.static_callers` — same-module callers found
    by scanning reference `.s` files (`bsr`, `jsr`, `.4byte FUN_*`).
    Strong signal that the address is a function entry.
  - `candidate.evidence.cross_module_callers` — same-name references
    in sibling hot-swap modules that share this binary's load address.
    Physically impossible at runtime — shown for context only.
  - `candidate.evidence.midpoints` — list of reference function starts
    that fall *inside* our proposed range. Each midpoint has its own
    `static_callers` / `runtime_hits` so you can tell if reference's
    proposed split is real (caller evidence) or a Ghidra hallucination.
  - `internal_gaps` — list of uncovered byte ranges between verified
    subsegs. Each entry: `{start_hex, end_hex, size, preceding_name,
    preceding_start}`. Non-empty = the red gap banner is firing.
- **`POST /unstamp {"start": "0x..."}`** — remove a verified subseg so the
  human can re-review with current oracle logic. Works with either an
  int or `"0x..."` hex string for `start`.
- **`ai_override` in session.json** — pin a specific candidate when
  forward-sweep can't find the function naturally, or when oracle's
  proposed boundary is off. **Independent of any verdict** — setting it
  auto-refreshes the UI on the next poll; you don't need a reject first.
  Full schema:

  ```json
  "ai_override": {
    "candidate_start": "0x0602CC84",
    "candidate_end":   "0x0602CD61",
    "previous_subseg": {
      "start": "0x0602B22C",
      "end":   "0x0602CC83",
      "type":  "code",
      "file":  "tu_0602B22C"
    },
    "attn": ["0x0602CC84", "0x0602CD60"]
  }
  ```

  `candidate_end` and `attn` are optional. `previous_subseg` mirrors
  the yaml subseg shape (start/end accept int or hex string) and tells
  the eval tool what to render in the "previous" section above the
  candidate. When override is active the listing splits into two panes:
  your pinned candidate on the left, oracle's natural proposal on the
  right.
- **`attn` in ai_override** — optional list of addresses to draw the
  human's eye to (e.g. the exact instruction that proves the boundary).
  Each listed address gets an orange box around the address column and
  an orange-bold tail on the last 4 hex digits.

## Rules

1. **No internal gaps.** The red banner fires whenever there's
   uncovered bytes between two stamps (or between latest stamp and
   proposed candidate). Address the gap before advancing.
2. **No auto-approve.** Human verdicts, you diagnose.
3. **Trailing pool stamps with the function.** When a function ends
   with a pool it references (constants loaded via PC-relative
   `mov.l @(disp,PC),Rn`), extend the stamp's `end` to include the
   pool. The data belongs with the code that owns it.

