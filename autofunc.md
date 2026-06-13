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
   subsegments: []                    # forward-sweep starts from vram
   ```

   For **windowed verification** (a few regions of interest in a large
   binary, everything else legally unswept), see "Islands" below — the
   yaml gains a top-level `islands:` list and the sweep starts from
   seeds instead of vram.

Recommended additions (richer banner signals + cleaner rendering):

3. **Reference disassembly.** A second-opinion `.s` tree to compare
   the analyzer's boundaries against — typically the output of a fresh
   Ghidra pass on the same binary, but it can be anything that emits
   the standard `FUN_<addr>:` / `.L_pool_<addr>:` label conventions
   (objdump, splat, hand-written stubs).  The eval tool treats it as
   a second opinion, not as ground truth — when analyzer and reference
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

A browser tab opens at `http://localhost:5001`. Stamping begins.

## When you're called in to diagnose

Two cases — same diagnosis steps, different source of truth for "what's
on screen":

### A) Live mid-stream question — "is the current candidate right?"

The human hasn't verdicted yet. The currently displayed candidate is
**not in session.json yet**; it's in `/state`. Read it:

```
curl -s http://localhost:5001/state | python -m json.tool
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
  - `candidate.yellow_flags` — list of strings from analyzer's structural
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
  - `candidate.partners` — addresses already partnered with this
    function in yaml (mega-function: one logical C function whose
    code is split across disjoint address ranges).
  - `candidate.suggested_partners` — addresses the analyzer proposes
    as partners based on stack-frame imbalance + transfer signals.
    Each: `{addr, addr_hex, reason}`. Empty = function is balanced
    on its own.
  - `candidate.pending_partners` — partner addresses queued for the
    next approve (set via `/queue-partner`, written to yaml on
    approve).
  - `candidate.partner_balanced` — true when the verdict has been
    upgraded because partners cover the imbalance.
  - `candidate.entries` — alt entry addrs declared on this function
    in yaml (multi-entry function: several callable entries sharing
    one body — one stamp, no overlap). Distinct from partners: same
    body, multiple entries vs. disjoint bodies, one logical function.
  - `candidate.pending_entries` — alt entry addrs queued for the next
    approve (set via `/queue-entry`, written to yaml on approve).
    While queued, the analyzer treats them as if already declared —
    walker seeds them, midpoints suppress them, `function_entry_confidence`
    scores them HIGH — so you can audit the multi-entry shape before
    stamping.
  - `analyze_mode` — non-null when the user/AI is exploring a
    multi-block synthetic candidate (e.g. switch dispatcher + case
    bodies). See "Analyze mode" below.
  - `internal_gaps` — list of uncovered byte ranges between verified
    subsegs. Each entry: `{start_hex, end_hex, size, preceding_name,
    preceding_start}`. Non-empty = the red gap banner is firing.

### Endpoints (prefer these over editing session.json directly)

- **`POST /unstamp {"start": "0x..."}`** — remove a verified subseg so the
  human can re-review with current analyzer logic. Accepts int or `"0x..."` hex.
- **`POST /pin-start {"addr": "0x..."}`** — pin the candidate's start
  address. Replaces any existing override. Use when forward-sweep
  can't find the function naturally, or after an `/unstamp` to jump
  to a specific position.
- **`POST /pin-end {"next_start": "0x..."}`** — pin the candidate's
  end to the byte BEFORE `next_start`. Pass the address you'd like
  to be the START of the next function; the pin lands at
  `next_start - 1`. Rejects if `next_start` lands strictly inside a
  verified subseg.
- **`POST /unpin-end`** — clear just the end pin. If no other
  override fields remain (start, attn, previous_subseg), the entire
  override is cleared.
- **`POST /unpin-all`** — clear the entire `ai_override` block.
- **`POST /queue-partner {"partner": "0x..."}`** — queue a partner
  address for the next approve. Toggles if already queued. The
  partner is written to the yaml's `partners:` list on the candidate's
  next approve verdict; no yaml mutation happens before that.
- **`POST /queue-entry {"entry": "0x..."}`** — queue an alt entry
  address for the next approve. Toggles if already queued. Must sit
  strictly inside the current candidate's `(start, end]` and not
  fall in another stamped subseg. The entry is written to the yaml's
  `entries:` list on the next approve. Golden path for adding alt
  entries — there is intentionally no retroactive `/add-entry`; to
  add an entry to an already-stamped function, `/unstamp` it first
  and re-queue.
- **`POST /remove-entry {"main": "0x...", "entry": "0x..."}`** —
  drop an alt entry from a stamped subseg's `entries:` list.
  Backout-only; for adds use `/queue-entry`.

### Islands (windowed coverage)

For binaries where the goal is a few verified windows rather than full
coverage.  An island is a verified-coverage window seeded at a chosen
address, with legally-unswept territory before/between/after islands.
Declare all the windows up front and the tool forward-sweeps through
them like it sweeps a full-coverage binary.

```yaml
islands:          # top-level, sibling of subsegments (keep it ABOVE them)
  - seed: 0x0602C690      # declaration order = work order
    end:  0x06030100      # soft target; omit for an open-ended window
  - seed: 0x06027344
    end:  0x060275FF
subsegments: [...]
```

Semantics:

- **No `islands:` key = legacy full-coverage mode**, byte-identical to
  before islands existed (sweep from vram, every inter-subseg gap
  illegal).  Full coverage is the degenerate case of one island at vram.
- **Declaration order is work order.**  The sweep proposes from the
  first declared island that still yields a candidate, then auto-
  advances to the next.  A window only auto-advances when its whole
  [seed, end] range is COVERED — never while it still has uncovered
  bytes.  All windows fully covered = "all caught up".
- **Nothing inside a window is silently skipped.**  If forward-sweep
  finds no function-start signal (prologue / reference label / caller)
  in the remaining window, but uncovered bytes remain, the tool
  surfaces the first uncovered address as a candidate anyway — a
  declared window is the user's assertion that the whole range matters.
  This catches prologue-less leaf functions and code the reference
  didn't label.  If that leftover is really data/padding, "approve as
  data" stamps it (covers it → window completes); if it's a function
  whose body crosses the boundary, it renders in full past `end`,
  which is the signal the declared end is too small.
- **`end` is soft.**  A function straddling the end stamps normally
  (pin-end past the boundary).  To keep sweeping past a declared end,
  raise it in the yaml.  An entry without `end` (or a bare `- 0x...`
  addr) is an open-ended window: it has no bounded remainder, so it
  advances when no function-start signal is found (no leftover
  surfacing).
- Every stamp belongs to the island with the **greatest seed at or
  below its start**.  A gap between consecutive stamps is legal iff an
  island seed sits inside it (it spans an island boundary); gaps
  *within* an island fire the red banner exactly as before.
- An uncovered seed proposes a candidate exactly at the seed (no
  prologue scan second-guesses the human's address); a covered seed
  sweeps forward from the island's coverage.  Seeds are durable in
  yaml — `/unstamp` of an island's first stamp returns the candidate
  to the seed, not to the binary head.
- When an island's sweep reaches a later island's stamps, coverage
  **merges**: no banner, the frontier skips past, and the interior
  seed stays in yaml harmlessly (progress reports it
  `merged_with_prev`; a window covered by a merged neighbor still
  reports `complete`).
- On approve, if the active island's first stamp starts a few bytes
  *before* its seed (start was pinned earlier after seeding), the seed
  **auto-snaps down** to the stamp's start.
- `progress.islands` in `/state` reports per-island `{seed_hex,
  end_hex, verified_bytes, target_bytes, complete, frontier_end_hex,
  merged_with_prev}` in declaration order — whole-binary percent alone
  would misread on island projects.

Endpoints:

- **`POST /island/seed {"addr": "0x...", "end": "0x..."}`** — open a
  new island (writes `{seed, end}` to yaml; `end` optional, appended
  at the END of the work order) **or re-activate an existing one** by
  addr (jumps the sweep to that island ahead of declaration order;
  validation is skipped for known seeds so a covered seed still
  activates).  Clears any `ai_override`.
- **`POST /island/remove {"seed": "0x..."}`** — backout for a
  mis-seeded island.  Refused if stamps depend on the seed (they'd be
  orphaned or legal unswept space would become internal gaps);
  merged-interior seeds are always removable.

### Analyze mode (multi-block exploration)

Switch dispatchers can have case bodies that live at disjoint
addresses (the dispatcher absorbs the immediate case via switch
absorption, but other cases may be a partner block elsewhere).
Analyze mode lets you stage a multi-block view to discover the shape
before committing partners.

- **`POST /analyze-mode/enter {"blocks": [{"start": 0x..., "end": 0x...}, ...], "label": "..."}`**
  — define the synthetic multi-block candidate. No yaml mutation,
  no history. The UI's `analyze_mode` slot is populated and the
  candidate view switches to multi-block.
- **`POST /analyze-mode/add {"start": "0x..."}`** — incremental
  entry point used by the UI's alt-click on a hex address. Server
  computes the block end (stamped subseg's end if verified, else
  CFG walker via `model.analyze_function`). When analyze mode is
  not yet active, enters with two blocks — live candidate as
  block 1, alt-clicked addr as block 2. When already active,
  appends; toggles a block out if its start is already present;
  clears the mode entirely on toggling away the last block.
- **`POST /analyze-mode/cycle {"direction": "next" | "prev"}`** —
  navigate between blocks (also wired to ←/→ keys in the UI).
- **`POST /analyze-mode/clear`** — exit analyze mode. Sweep resumes.

### `ai_override` (advanced — usually let the pin endpoints manage it)

The pin/unpin endpoints write `ai_override` for you. Edit it directly
only when you need the `attn` field, which the endpoints don't set:

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

`attn` highlights specific addresses in the listing (orange box on
the address column, orange-bold tail on the last 4 hex digits) —
useful when you want to draw the human's eye to a specific
boundary-defining instruction.

## Rules

1. **No internal gaps.** The red banner fires whenever there's
   uncovered bytes between two stamps (or between latest stamp and
   proposed candidate). Address the gap before advancing.  On island
   projects this applies *within* each island — unswept territory
   between islands is legal (see "Islands").
2. **No auto-approve.** Human verdicts, you diagnose.
3. **Trailing pool stamps with the function.** When a function ends
   with a pool it references (constants loaded via PC-relative
   `mov.l @(disp,PC),Rn`), extend the stamp's `end` to include the
   pool. The data belongs with the code that owns it.

