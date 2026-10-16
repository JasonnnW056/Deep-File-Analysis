import datetime
from pathlib import Path
from .hasher import get_hashes
from .pe_analyzer import analyze_pe
from .yara_scanner import analyze_yara
from collections import Counter
from .filetype_analyzer import analyze_filetype

SCHEMA_VERSION = 1

SEVERITY_ORDER = ("info", "low", "medium", "high")

# Scoring model: each finding has a strength. Strengths combine as
#   score = 100 * (1 - product(1 - strength))
# so the score can never pass 100, one strong signal outweighs many weak ones,
# and a finding repeated under the same id counts less each time.
# "info" findings are context only and never change the score.
RISK_ORDER = ("none", "low", "medium", "high")
SEVERITY_WEIGHTS = {"info": 0.0, "low": 0.05, "medium": 0.18, "high": 0.45}
REPEAT_DECAY = 0.5
RISK_BANDS = (("high", 60), ("medium", 25), ("low", 1))


VALID_STATUS = ("ok", "skipped", "error")

_ANALYZERS = {}


def register_analyzer(name, func):
    """Register func(path) -> envelope under name (replaces an existing one)."""
    _ANALYZERS[name] = func


def unregister_analyzer(name):
    _ANALYZERS.pop(name, None)


def registered_analyzers():
    return list(_ANALYZERS)

register_analyzer("filetype", analyze_filetype)
register_analyzer("pe", analyze_pe)
register_analyzer("yara", analyze_yara)

def _failed(name, message):
    return {"analyzer": name, "status": "error", "error": message, "data": {}, "findings": []}


def _run_analyzer(name, func, path):
    try:
        env = func(path)
    except Exception as e:
        return _failed(name, f"{type(e).__name__}: {e}")
    if not isinstance(env, dict):
        return _failed(name, "Analyzer returned a non-dict result")

    status = env.get("status", "ok")
    if status not in VALID_STATUS:
        return _failed(name, f"Invalid status: {status!r}")

    env["status"] = status
    env.setdefault("analyzer", name)
    env["error"] = env.get("error")
    env["data"] = env.get("data") or {}

    clean = []
    for f in env.get("findings") or []:
        if not isinstance(f, dict):
            continue
        f.setdefault("id", "UNKNOWN")
        f.setdefault("analyzer", env["analyzer"])
        f.setdefault("message", "")
        f.setdefault("detail", {})
        if f.get("severity") not in SEVERITY_ORDER:
            f["severity"] = "info"
        clean.append(f)
    env["findings"] = clean
    return env

def _score(findings):
    """Return (score 0-100, breakdown). Breakdown = each finding's share of the score."""
    seen = Counter()
    weighted = []
    for f in findings:
        base = SEVERITY_WEIGHTS[f["severity"]]
        w = base * (REPEAT_DECAY ** seen[f["id"]])
        seen[f["id"]] += 1
        if w > 0:
            weighted.append((w, f))
    weighted.sort(key=lambda t: -t[0])

    remaining = 1.0
    breakdown = []
    for w, f in weighted:
        before = 1.0 - remaining
        remaining *= 1.0 - w
        breakdown.append({"id": f["id"], "analyzer": f["analyzer"], "severity": f["severity"],
                          "points": round(((1.0 - remaining) - before) * 100, 1)})
    return round((1.0 - remaining) * 100), breakdown


def _summarize(findings, analyzers):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev if sev in counts else "info"] += 1

    score, breakdown = _score(findings)

    by_score = "none"
    for level, floor in RISK_BANDS:
        if score >= floor:
            by_score = level
            break
    by_severity = "none"
    for s in ("high", "medium", "low"):
        if counts[s]:
            by_severity = s
            break
    # "none" means nothing was flagged, NOT that the file is safe.
    risk = max(by_score, by_severity, key=RISK_ORDER.index)

    failed = [n for n, e in analyzers.items() if e["status"] == "error"]
    return {
        "risk_level": risk,
        "score": score,
        "severity_counts": counts,
        "finding_count": len(findings),
        "breakdown": breakdown[:10],
        "complete": not failed,
        "analyzers_ok": [n for n, e in analyzers.items() if e["status"] == "ok"],
        "analyzers_skipped": [n for n, e in analyzers.items() if e["status"] == "skipped"],
        "analyzers_failed": failed,
    }



def scan_file(path, analyzers=None):
    """Scan one file. Always returns a JSON-serialisable report; never raises."""
    path = Path(path)
    report = {
        "schema_version": SCHEMA_VERSION,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "file": {"path": str(path), "name": path.name, "size": None},
        "hashes": {},
        "analyzers": {},
        "findings": [],
        "summary": {},
        "errors": [],
    }

    if not path.is_file():
        report["errors"].append("File not found")
        report["summary"] = _summarize([], {})
        return report

    try:
        report["file"]["size"] = path.stat().st_size
    except OSError as e:
        report["errors"].append(f"Cannot stat file: {type(e).__name__}: {e}")
        report["summary"] = _summarize([], {})
        return report

    try:
        report["hashes"] = {k: v for k, v in get_hashes(path).items() if k != "size"}
    except Exception as e:
        report["errors"].append(f"Hashing failed: {type(e).__name__}: {e}")

    names = list(analyzers) if analyzers is not None else registered_analyzers()
    for name in names:
        func = _ANALYZERS.get(name)
        if func is None:
            report["errors"].append(f"Unknown analyzer: {name}")
            continue
        report["analyzers"][name] = _run_analyzer(name, func, path)

    # promote imphash into the shared hashes block
    pe_env = report["analyzers"].get("pe")
    if pe_env and pe_env["status"] == "ok" and pe_env["data"].get("imphash"):
        report["hashes"]["imphash"] = pe_env["data"]["imphash"]

    findings = [f for env in report["analyzers"].values() for f in env["findings"]]
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"])
                  if f.get("severity") in SEVERITY_ORDER else 0, reverse=True)
    report["findings"] = findings
    report["summary"] = _summarize(findings, report["analyzers"])
    return report


# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: python -m app.static_analysis.scanner <file>")
#         sys.exit(1)
#     print(json.dumps(scan_file(sys.argv[1]), indent=2))