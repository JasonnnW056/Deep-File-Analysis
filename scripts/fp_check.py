import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analyzer import analyze

files = glob.glob(r"C:\Windows\System32\*.exe")[:100]
flagged = 0

for p in files:
    try:
        r = analyze(p)
    except Exception as e:
        print("ERROR", p, e)
        continue
    if r["yara"]:
        flagged += 1
        print(p, [m["rule"] for m in r["yara"]])

print(f"\n{flagged} of {len(files)} clean files flagged")