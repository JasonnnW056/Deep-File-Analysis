from dynamic_analysis.scan import scan
from dynamic_analysis.backend_base import detonation_error
from pathlib import Path

def main():
    path= Path("/home/jason/test.txt")

    try:
        report= scan(path, status=print)
    except detonation_error as exc:
        print(f"Dynamic analysis failed: {exc}")

if __name__ == "__main__":
    main()
