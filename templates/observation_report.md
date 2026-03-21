---
function: FUN_XXXXXXXX
address: 0xXXXXXXXX
address_end: 0xXXXXXXXX
source_file: src/FUN_XXXXXXXX.s
explored: YYYY-MM-DD
scenarios_tested: [scenario_name]
reachable: true
---

## Call Frequency

| Scenario | Calls/Frame | Notes |
|----------|-------------|-------|
| scenario_name | N | |

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
| +0xNN | N | 0xXXXXXXXX | 0x0000→0x1234 |

## Per-Frame Field Analysis

Classify fields from sample CSVs. MANDATORY — do not defer.

| Offset | Idle behavior | Input behavior | Category | Notes |
|--------|---------------|----------------|----------|-------|
| +0xNN | static at 0x0 | monotonic increase | input-responsive | |

### Sample captures
- List which CSV captures were used in this analysis

## Other Observations

Describe what happened, not what it means.
