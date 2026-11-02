r"""Measure detection quality on two folders of files whose answer you already know.

    python scripts/evaluate.py --bad "D:\samples\malicious" --good "C:\Windows\System32"

--bad   files known to be malicious (keep these in an isolated virtual machine!)
--good  files known to be clean
Nothing is executed. Files are only read and scanned.
"""
import argparse
import csv
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.static_analysis.scanner import scan_file  # noqa: E402

LEVELS = ("none", "low", "medium", "high")
MAX_SIZE = 50 * 1024 * 1024


def collect(folder, limit):
    files = []
    for root, _dirs, names in os.walk(folder, onerror=lambda e: None):
        for n in names:
            p = Path(root) / n
            try:
                if p.is_file() and 0 < p.stat().st_size <= MAX_SIZE:
                    files.append(p)
            except OSError:
                pass
    if len(files) > limit:
        files = random.Random(1).sample(files, limit)  # same sample every run
    return files


def scan_all(files, label):
    rows = []
    for i, p in enumerate(files, 1):
        print(f"\r  {label:<4}: {i}/{len(files)}", end="", flush=True)
        r = scan_file(p)
        s = r["summary"]
        rows.append({
            "label": label, "name": p.name, "path": str(p), "risk": s["risk_level"], "score": s["score"],
            "sha256": r["hashes"].get("sha256", ""),
            "top": ", ".join(f["id"] for f in r["findings"] if f["severity"] != "info")[:90],
            "incomplete": not s.get("complete", True),
            "failed": "; ".join(f"{n}: {(e.get('error') or '')[:70]}"
                                for n, e in r["analyzers"].items() if e["status"] == "error"),
        })
    print()
    return rows


def flagged(rows, level):
    i = LEVELS.index(level)
    return [r for r in rows if LEVELS.index(r["risk"]) >= i]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bad", required=True)
    ap.add_argument("--good", required=True)
    ap.add_argument("--limit", type=int, default=300, help="max files taken from each folder")
    ap.add_argument("--level", choices=LEVELS[1:], default="medium", help="risk level that counts as 'flagged'")
    ap.add_argument("--csv", default="evaluation.csv")
    a = ap.parse_args()

    bad = scan_all(collect(a.bad, a.limit), "bad")
    good = scan_all(collect(a.good, a.limit), "good")
    if not bad or not good:
        print("Need at least one file in each folder.")
        return 1

    print(f"\n{len(bad)} malicious files, {len(good)} clean files\n")
    print(f"{'flag at':10} {'caught (bad)':>14} {'false alarms (good)':>22}")
    for lvl in LEVELS[1:]:
        c, f = len(flagged(bad, lvl)), len(flagged(good, lvl))
        print(f"{lvl + ' +':10} {c:>5}/{len(bad):<4}{100 * c / len(bad):>5.0f}% {f:>9}/{len(good):<4}{100 * f / len(good):>5.1f}%")

    missed = [r for r in bad if r not in flagged(bad, a.level)]
    alarms = flagged(good, a.level)
    print(f"\nMISSED malicious files at '{a.level}+' ({len(missed)}):")
    for r in missed[:15]:
        print(f"  {r['risk']:6} {r['score']:>3}  {r['name']}  [{r['sha256'][:12]}]")
    print(f"\nFALSE ALARMS on clean files at '{a.level}+' ({len(alarms)}):")
    for r in alarms[:15]:
        print(f"  {r['risk']:6} {r['score']:>3}  {r['name']}  <- {r['top']}")
    incomplete = sum(r["incomplete"] for r in bad + good)
    if incomplete:
        print(f"\nNote: {incomplete} scans were incomplete (an analyzer failed):")
        for r in [x for x in bad + good if x["incomplete"]][:10]:
            print(f"  {r['name']}  <- {r['failed']}")

    with open(a.csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(bad[0].keys()))
        w.writeheader()
        w.writerows(bad + good)
    print(f"\nFull results saved to {a.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())