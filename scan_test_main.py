from dynamic_analysis.scan import dynamic_scan
from dynamic_analysis.backend_base import detonation_error
from pathlib import Path

def main():
    path= Path("/home/jason/eicar.txt")

    try:
        report= dynamic_scan(path, status=print)
    except detonation_error as exc:
        print(f"Dynamic analysis failed: {exc}")

if __name__ == "__main__":
    main()
