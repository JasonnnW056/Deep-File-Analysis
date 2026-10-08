import json
import sys
from pathlib import Path 

from app.static_analysis.scanner import scan_file


def print_report(report):
    f = report["file"]
    h = report["hashes"]
    s = report["summary"]

    print("File   :", f["path"])
    print("Size   :", f["size"], "bytes")
    print("MD5    :", h.get("md5"))
    print("SHA-1  :", h.get("sha1"))
    print("SHA-256:", h.get("sha256"))
    if h.get("imphash"):
        print("Imphash:", h["imphash"])

    print("\nAnalyzers:")
    for name, env in report["analyzers"].items():
        note = f" ({env['error']})" if env["error"] else ""
        print(f"  {name:<6}: {env['status']}{note}")

    print(f"\nRisk   : {s['risk_level']}  (score {s['score']}/100)")
    if s["risk_level"] == "none":
        print("         nothing flagged, which is NOT proof the file is safe")

    if report["findings"]:
        print("\nFindings:")
        for item in report["findings"]:
            print(f"  [{item['severity'].upper():<6}] {item['analyzer']}: {item['message']}")

    for err in report["errors"]:
        print("Error  :", err)


def main(argv):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    as_json = "--json" in argv[1:]
    args = [a for a in argv[1:] if a != "--json"]

    if len(args) != 1:
        print("Usage: python main.py <file> [--json]")
        return 1

    file_path = args[0]
    if not Path(file_path).is_file():
        print("File not found:", file_path, file=sys.stderr)
        return 1
    
    report = scan_file(file_path)

    if as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)
    failed = report["summary"]["analyzers_failed"]
    return 2 if (report["errors"] or failed) else 0    #Exit codes are 0 for a clean scan, 1 for bad usage or a missing file, and 2 when the scan itself had errors.

if __name__ == "__main__":
    sys.exit(main(sys.argv))






# Run this command: 
# python main.py abc.txt
# python main.py "C:\path\to\program.exe"
# python main.py "C:\path\to\program.exe" --json

#cd Deep-File-Analysis                                                                                                                         
# python -m unittest tests.pe.test_pe_analyzer -v










# import sys
# from app.static_analysis.hasher import get_hashes

# if len(sys.argv) != 2:
#     print("Usage: python main.py <file>")
#     sys.exit()

# file_path = sys.argv[1]

# try:
#     result = get_hashes(file_path)
# except FileNotFoundError:
#     print("File not found:", file_path)
#     sys.exit()

# print("File   :", file_path)
# print("Size   :", result["size"], "bytes")
# print("MD5    :", result["md5"])
# print("SHA-1  :", result["sha1"])
# print("SHA-256:", result["sha256"])

# Run this command: 
# python main.py abc.txt