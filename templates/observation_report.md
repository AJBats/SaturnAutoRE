---
function: FUN_XXXXXXXX
address: 0xXXXXXXXX
address_end: 0xXXXXXXXX
source_file: src/FUN_XXXXXXXX.s
explored: YYYY-MM-DD
scenarios_tested: [straight_throttle]
reachable: true
---

## Call Frequency

| Scenario | Calls/Frame | Notes |
|----------|-------------|-------|
| straight_throttle | N | |

## Register Context at Entry

| Register | Value (first hit) | Notes |
|----------|-------------------|-------|
| R0 | 0xXXXXXXXX | |
| R14 | 0xXXXXXXXX | |
| PC | 0xXXXXXXXX | |
| PR | 0xXXXXXXXX | return address |

## Memory Writes (Watchpoint Data)

| Target | Hits | PCs That Wrote | Sample Old→New |
|--------|------|----------------|----------------|
| car[+0xNN] | N | 0xXXXXXXXX | 0x0000→0x1234 |

## Per-Frame Field Analysis

Classify fields from sample CSVs. MANDATORY — do not defer.

| Offset | Idle behavior | Input behavior | Category | Notes |
|--------|---------------|----------------|----------|-------|
| +0xNN | static at 0x0 | monotonic increase | input-responsive | |

### Sample captures
- `tt_idle_300f.csv` — baseline
- `tt_throttle_300f.csv` — input comparison

## Other Observations

Describe what happened, not what it means.
