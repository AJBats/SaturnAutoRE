# auto_re.py — CLI Harness Rules

## Never truncate auto_re.py output

Every auto_re.py command ends with instructions telling you exactly what
to do next. If you pipe the output through `grep`, `head`, `tail`, or
any filter, you will miss those instructions and go off-track.

**Always read the full, unfiltered output of every auto_re.py command.**

Bad:
```bash
python auto_re.py verify FUN_X 2>&1 | head -10
python auto_re.py integrate 2>&1 | grep "PASS\|FAIL"
```

Good:
```bash
python auto_re.py verify FUN_X
python auto_re.py integrate
```

## Follow the chain

The last lines of every command tell you the next command to run.
Follow them. Do not skip steps, reorder the pipeline, or decide
on your own what to do next. The tool decides.

## NOP tests are interactive

NOP tests require the human to observe visual behavior in the emulator
window. You cannot judge rendering, car movement, or camera changes
from screenshots. Brief the human on what you're about to do and what
to look for, then let them report the result.
