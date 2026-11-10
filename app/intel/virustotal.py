# VirusTotal hash lookup. Sends only the SHA-256 (never the file). Opt-in via VT_API_KEY.
import datetime
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from app.static_analysis.common import make_helpers

from app.static_analysis.hasher import get_hashes

API_URL = "https://www.virustotal.com/api/v3/files/"
GUI_URL = "https://www.virustotal.com/gui/file/"
REQUEST_TIMEOUT = 20

# Detection count -> severity. One or two detections are often false positives, so they stay low.
HIGH_AT, MEDIUM_AT = 10, 3

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")   # project root; real env vars win
except ImportError:
    pass

_result, _finding = make_helpers("virustotal")

def _lookup(sha256, key):
    req = urllib.request.Request(API_URL + sha256,
                                 headers={"x-apikey": key, "accept": "application/json"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.load(resp)


def analyze_virustotal(path):
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return _result("skipped", "VT_API_KEY is not set")

    try:
        sha256 = get_hashes(path)["sha256"]
    except OSError as e:
        return _result("error", f"Cannot hash file: {e}")

    link = GUI_URL + sha256
    try:
        body = _lookup(sha256, key)
    except urllib.error.HTTPError as e:      # must come before URLError (its parent class)
        if e.code == 404:
            return _result(
                "ok", data={"found": False, "sha256": sha256, "link": link},
                findings=[_finding(
                    "VT_NOT_FOUND", "info",
                    "Hash not known to VirusTotal (new or rare file; this is not proof the file is safe)",
                    sha256=sha256)])
        reasons = {401: "invalid API key", 403: "API key not allowed to do this lookup",
                   429: "rate limit reached (free keys allow only a few lookups per minute)"}
        return _result("error", f"VirusTotal: {reasons.get(e.code, f'HTTP {e.code}')}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return _result("error", f"Could not reach VirusTotal: {type(e).__name__}")

    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious", 0))
    sus = int(stats.get("suspicious", 0))
    total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    ts = attrs.get("last_analysis_date")
    last = (datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
            if isinstance(ts, int) else None)

    if mal >= HIGH_AT:
        sev = "high"
    elif mal >= MEDIUM_AT:
        sev = "medium"
    elif mal or sus:
        sev = "low"
    else:
        sev = "info"

    if sev == "info":
        msg = f"VirusTotal: no engine flags this file ({total} engines checked)"
    else:
        msg = f"VirusTotal: {mal} of {total} engines flag this file as malicious"
        if sus:
            msg += f" ({sus} suspicious)"

    return _result(
        "ok",
        data={"found": True, "sha256": sha256, "malicious": mal, "suspicious": sus,
              "total": total, "threat_label": label, "last_analysis": last, "link": link},
        findings=[_finding("VT_DETECTIONS", sev, msg, malicious=mal, suspicious=sus,
                           total=total, threat_label=label)])


if __name__ == "__main__":      # quick manual check: python -m app.intel.virustotal <file>
    import pprint
    import sys
    pprint.pprint(analyze_virustotal(sys.argv[1]))