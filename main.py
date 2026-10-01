import sys
from app.static_analysis.hasher import get_hashes

if len(sys.argv) != 2:
    print("Usage: python main.py <file>")
    sys.exit()

file_path = sys.argv[1]

try:
    result = get_hashes(file_path)
except FileNotFoundError:
    print("File not found:", file_path)
    sys.exit()

print("File   :", file_path)
print("Size   :", result["size"], "bytes")
print("MD5    :", result["md5"])
print("SHA-1  :", result["sha1"])
print("SHA-256:", result["sha256"])

# Run this command: 
#python main.py abc.txt
