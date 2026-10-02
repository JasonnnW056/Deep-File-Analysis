import datetime
import json
import sys
from pathlib import Path

from .hasher import get_hashes
from .pe_analyzer import analyze_pe

SCHEMA_VERSION = 1

SEVERITY_ORDER = ("info", "low", "medium", "high")
SEVERITY_WEIGHTS = {"info": 0, "low": 5, "medium": 15, "high": 30}

_ANALYZERS = {}


def register_analyzer(name, func):
    """Register func(path) -> envelope under name (replaces an existing one)."""
    _ANALYZERS[name] = func


def unregister_analyzer(name):
    _ANALYZERS.pop(name, None)


def registered_analyzers():
    return list(_ANALYZERS)


register_analyzer("pe", analyze_pe)


def _failed(name, message):
    return {"analyzer": name, "status": "error", "error": message, "data": {}, "findings": []}


def _run_analyzer(name, func, path):
    try:
        env = func(path)
    except Exception as e:
        return _failed(name, f"{type(e).__name__}: {e}")
    if not isinstance(env, dict):
        return _failed(name, "Analyzer returned a non-dict result")
    env.setdefault("analyzer", name)
    env.setdefault("status", "ok")
    env.setdefault("error", None)
    env.setdefault("data", {})
    env.setdefault("findings", [])
    return env


def _summarize(findings, analyzers):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev if sev in counts else "info"] += 1
    score = min(100, sum(SEVERITY_WEIGHTS[s] * n for s, n in counts.items()))
    # Highest severity present, ignoring info. "none" means nothing was flagged,
    # NOT that the file is safe.
    risk = "none"
    for s in ("high", "medium", "low"):
        if counts[s]:
            risk = s
            break
    return {
        "risk_level": risk,
        "score": score,
        "severity_counts": counts,
        "finding_count": len(findings),
        "analyzers_ok": [n for n, e in analyzers.items() if e["status"] == "ok"],
        "analyzers_skipped": [n for n, e in analyzers.items() if e["status"] == "skipped"],
        "analyzers_failed": [n for n, e in analyzers.items() if e["status"] == "error"],
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

    report["file"]["size"] = path.stat().st_size

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


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m app.static_analysis.scanner <file>")
        sys.exit(1)
    print(json.dumps(scan_file(sys.argv[1]), indent=2))