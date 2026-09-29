"""
Deep File Analysis - command line entry point.

Current pipeline:  Step 1 YARA  (hashing, PE and report are added in later steps)

Usage:  python main.py <file>
"""
import sys
from pathlib import Path

from app.static_analysis.yara_scanner import YaraScanner


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python main.py <file>")
        return 2

    target = Path(sys.argv[1])
    if not target.is_file():
        print(f"File not found: {target}")
        return 2

    scanner = YaraScanner()
    result = scanner.scan_file(target)

    print(f"File          : {target.name}")
    print(f"Rules loaded  : {result.rules_loaded}")

    if result.error:
        print(f"ERROR         : {result.error}")
        return 1

    print(f"Rules matched : {len(result.matches)}")
    print(f"Evasive       : {'YES' if result.is_evasive else 'no'}")
    print(f"YARA points   : {result.total_points}")

    for m in result.matches:
        mitre = f" [{m.mitre}]" if m.mitre else ""
        print(f"\n  [{m.severity.upper()}] {m.rule}{mitre}")
        print(f"      {m.description}")
        for s in m.strings[:3]:
            print(f"      {s.identifier} @ offset {s.offset}: {s.preview!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())