"""For each over-absorbing stamp (natural walk past stamp end), find the
first out-of-range branch target and score it via walker_stop_confidence:
  - static_callers >= 2 (HIGH stop)
  - static_callers == 1 (MEDIUM stop)
  - nothing else: NONE (walker would still over-absorb)

Strict mode: no user-stamps (circular), no switch_dispatcher_of (handled
by switch absorption, not stops), no runtime_hits (Ghidra-derived,
inherits hallucinated boundaries), no reference_starts (too noisy).

Outputs:
  - per-grow case: stamp range, natural-walk end, the first
    branch-target past stamp.end, that target's confidence + signals
  - summary: how many grows have a HIGH/MEDIUM target (would be
    prevented by a tail-call-detecting walker) vs LOW/NONE (still
    over-absorb)
"""
import sys
from collections import Counter
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
import analyzer

PR = Path("d:/Projects/DaytonaCCEReverse")
YAML_PATH = PR / "config/race.bin.yaml"


def main():
    cfg = yaml.safe_load(open(YAML_PATH))
    opt = cfg["options"]
    binary = open(PR / opt["target_path"], "rb").read()
    vram = int(opt["vram"])

    def _resolve(p):
        if not p: return None
        pp = Path(p)
        return pp if pp.is_absolute() else (PR / pp).resolve()

    priors_path = YAML_PATH.parent / (YAML_PATH.stem + ".pool_priors.txt")
    model = analyzer.BinaryModel(
        binary=binary, vram=vram,
        pool_priors_path=priors_path if priors_path.exists() else None,
        reference_dir=_resolve(opt.get("reference_dir")),
        reference_scan_dir=_resolve(opt.get("reference_scan_dir")),
        runtime_hits_dirs=[_resolve(d) for d in (opt.get("runtime_hits_dirs") or [])],
    )

    stamps = sorted([
        (int(s["start"]), int(s["end"]))
        for s in cfg.get("subsegments", [])
        if s.get("type") == "code"
    ])

    grow_diagnostics = []
    for start, end in stamps:
        fa = model.analyze_function(start)   # no hint_end (binary_max)
        if fa.end <= end:
            continue   # no grow

        # Find OUT-OF-STAMP-RANGE branch targets in the walked fa.
        out_of_range = []
        for b in fa.branches:
            if b.target is None:
                continue
            if b.target <= end:
                continue
            if b.mnem not in ("bra", "jmp", "braf"):
                continue
            out_of_range.append(b)

        # Also include indirect jmp/braf resolutions that go past stamp end.
        for src_pc, tgt in fa.indirect_resolutions.items():
            if tgt <= end:
                continue
            out_of_range.append(("indirect", src_pc, tgt))

        # The first one (lowest src) is where over-absorption begins.
        def _src_of(item):
            return item.src if hasattr(item, "src") else item[1]
        out_of_range.sort(key=_src_of)

        if not out_of_range:
            grow_diagnostics.append((start, end, fa.end, None, "no_out_branch", []))
            continue

        first = out_of_range[0]
        if hasattr(first, "src"):
            src_pc = first.src
            tgt = first.target
            kind = first.mnem
        else:
            src_pc = first[1]
            tgt = first[2]
            kind = "indirect"

        level, reasons = model.walker_stop_confidence(tgt)
        grow_diagnostics.append((start, end, fa.end, (src_pc, tgt, kind), level, reasons))

    grows = [d for d in grow_diagnostics if d[3] is not None]
    print(f"Audit: signal coverage for {len(grows)} over-absorbing stamps")
    print()
    print(f"  {'STAMP':<12} {'BRANCH SRC':<12} {'TARGET':<12} {'KIND':<8} {'CONF':<12} REASONS")
    print(f"  {'-'*12} {'-'*12} {'-'*12} {'-'*8} {'-'*12} {'-'*40}")
    level_counts = Counter()
    for start, end, fa_end, branch, level, reasons in grows:
        if branch is None:
            continue
        src_pc, tgt, kind = branch
        reason_str = "; ".join(reasons) if reasons else "(none)"
        print(f"  0x{start:08X}  0x{src_pc:08X}    0x{tgt:08X}    {kind:<8} {level:<12} {reason_str}")
        level_counts[level] += 1
    print()
    print("Summary (walker-stop signal coverage):")
    for level in ("HIGH", "MEDIUM", "NONE"):
        n = level_counts.get(level, 0)
        prevented = {
            "HIGH":   "yes (walker would stop)",
            "MEDIUM": "marginal (ambiguous — could be us calling)",
            "NONE":   "no (walker would over-absorb)",
        }[level]
        print(f"  {level:<8} {n:4}  {prevented}")
    print()
    print(f"Total grows analyzed: {sum(level_counts.values())}")


if __name__ == "__main__":
    main()
