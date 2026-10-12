import os
from app.static_analysis.hasher import get_hashes
from app.static_analysis.yara_scanner import scan_file


def analyze(path):
    return {
        "file": os.path.basename(path),
        "hashes": get_hashes(path),
        "yara": scan_file(path),
    }