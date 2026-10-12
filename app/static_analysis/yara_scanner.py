import os
import yara

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_PATH = "rules/yara-rules-full.yar"
COMPILED_PATH = "rules/compiled_full.yarc"

_rules = None

def get_rules():
    global _rules
    if _rules is not None:
        return _rules

    # Try the cached file if it exists and is newer than the .yar file
    if (
        os.path.exists(COMPILED_PATH)
        and os.path.getmtime(COMPILED_PATH) >= os.path.getmtime(RULES_PATH)
    ):
        try:
            _rules = yara.load(COMPILED_PATH)
        except yara.Error:
            _rules = None  # cache unreadable or from another yara-python version

    # Fall back to compiling from source and refresh the cache
    if _rules is None:
        _rules = yara.compile(filepath=RULES_PATH)
        _rules.save(COMPILED_PATH)

    return _rules


def scan_file(file_path, timeout=60):
    rules = get_rules()
    try:
        matches = rules.match(file_path, timeout=timeout)
    except yara.TimeoutError:
        return [{"rule": "SCAN_TIMEOUT", "tags": [], "meta": {}}]
    except yara.Error as e:
        raise RuntimeError(f"YARA scan failed for {file_path}: {e}") from e
    return [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches]


def _severity_from_meta(meta):
    try:
        score = int(meta.get("score"))
    except (TypeError, ValueError):
        return "medium"

    if score >= 75:
        sev = "high"
    elif score >= 50:
        sev = "medium"
    elif score >= 25:
        sev = "low"
    else:
        sev = "info"

    # Low-quality rules are less trustworthy, so step the severity down one level
    try:
        quality = int(meta.get("quality"))
    except (TypeError, ValueError):
        quality = 100
    if quality < 50:
        order = ["info", "low", "medium", "high"]
        sev = order[max(0, order.index(sev) - 1)]

    return sev


def analyze_yara(path):
    """Analyzer for scanner.py: returns the standard envelope."""
    try:
        matches = scan_file(str(path))
    except Exception as e:
        return {
            "analyzer": "yara",
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "data": {},
            "findings": [],
        }

    findings = []
    for m in matches:
        meta = m["meta"]
        findings.append({
            "id": f"YARA_{m['rule']}",
            "analyzer": "yara",
            "severity": _severity_from_meta(meta),
            "message": f"{m['rule']}: {meta.get('description', 'no description')}",
            "detail": {"rule": m["rule"], "tags": m["tags"], "meta": meta},
        })

    return {
        "analyzer": "yara",
        "status": "ok",
        "error": None,
        "data": {"match_count": len(matches)},
        "findings": findings,
    }