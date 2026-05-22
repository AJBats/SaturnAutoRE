"""Print every stamped function whose end disagrees with the current
analyzer (no hint_end, should_stop active).  Sorted by start address
for top-to-bottom human review.
"""
import sys
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

    drift = []
    for start, end in stamps:
        fa = model.analyze_function(start)
        if fa.end != end:
            drift.append((start, end, fa.end, fa.end - end))

    # Already sorted by start since stamps was sorted
    print(f"Analyzer-vs-stamp drift after TU retirement + Phase 2 walker change.")
    print(f"  Total stamps: {len(stamps)}   matches: {len(stamps) - len(drift)}   "
          f"drift: {len(drift)}")
    print()
    print(f"  {'FUNCTION':<14} {'STAMP END':<12} {'ANALYZER END':<14} {'DELTA':>9}   NOTE")
    print(f"  {'-'*14} {'-'*12} {'-'*14} {'-'*9}   {'-'*40}")

    pre_existing_note = {
        0x06029588: "pre-existing trailing-pool quirk (dead rts+nop after jmp)",
        0x0603083C: "pre-existing trailing-pool quirk (dead rts+nop after bra)",
        0x06030E44: "pre-existing — known walker quirk",
        0x060352E8: "EXPECTED — switch dispatcher absorbing cases 1-9 (partnered)",
    }

    for start, sub_end, fa_end, delta in drift:
        note = pre_existing_note.get(start, "")
        sign = "+" if delta > 0 else ""
        print(f"  FUN_{start:08X}   0x{sub_end:08X}   0x{fa_end:08X}     {sign}{delta:>6}    {note}")


if __name__ == "__main__":
    main()
