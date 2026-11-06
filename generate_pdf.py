from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm


from dynamic_analysis.backend_base import sandbox_report
from style.pdf_style import table, styles

MALWARE_MIN_SCORE= 0.5
MAX_CONFIDENCE_SCORE= 95.0

VERDICT_COLORS={
    "MALWARE": colors.red(),
    "BENIGN": colors.green(),
    "INCONCLUSIVE": colors.gray()
}

@dataclass
class verdict:
    verdict:str #MALWARE, BENIGN, INCONCLUSIVE
    confidence_score: float| None
    risk_score: float| None
    reasons: list[str]

def detection_findings(detections:Any)-> list[str]:
    if not detections:
        return []
    if isinstance(detections, (str,dict)):
        detections = [detections]
    findings = []
    for d in detections:
        if isinstance(d, dict):
            d = d.get("family") or d.get("name") or str(d)
        findings.append(str(d))
    return findings

def set_verdict(report: sandbox_report)-> verdict:
    if report.cape_score is None:
        return verdict("INCONCLUSIVE", None, None, ["CAPE did not return a score for the sampe submitted"])
    
    max_score = report.max_score or 10.0
    score = float(report.cape_score)
    risk = min(max(score / max_score, 0.0), 1.0)
    reasons = [f"CAPE score: {score:g} out of {max_score:g}."]

    malware_found= detection_findings(report.malware_detected)
    if malware_found:
        risk += 0.3
        reasons.append("CAPE matched known malware: " + ", ".join(malware_found[:5]) + ".")

    high = [s for s in report.signatures if (s.get("severity") or 0) >= 3]
    if high:
        risk += 0.05 * min(len(high), 4)
        reasons.append(f"{len(high)} high-severity behavior signature"
                       + ("s" if len(high)>1 else "")
                       + " triggered.")

    if not malware_found and not high:
        reasons.append("No known malware family matched and no high-severity signatures triggered.")

    risk = min(risk, 1.0)
    label = "MALWARE" if risk >= MALWARE_MIN_SCORE else "BENIGN"
    confidence = min(50.0 + abs(risk - MALWARE_MIN_SCORE) * 100.0, MAX_CONFIDENCE_SCORE)
    return verdict(label, confidence, risk, reasons)

def make_to_text(item: Any, limit: int = 140):
    if isinstance(item, dict):
        if "uri" in item:
            item = f"{item.get('method', '')} {item['uri']}".strip()
        elif "name" in item:
            item = item["name"]
        else:
            item = ", ".join(f"{k}={v}" for k, v in item.items())
    s = str(item)
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return escape(s)


SEVERITY_LABELS = {1: "Low", 2: "Medium", 3: "High"}
def severity_label(severity: Any) -> str:
    try:
        severity = int(severity or 0)
    except (TypeError, ValueError):
        return "Unknown"
    return SEVERITY_LABELS.get(min(severity, 3), "Info") if severity > 0 else "Info"

def generate_report(report: sandbox_report, out_path: str | Path, max_items: int = 15) -> Path:
    
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
 
    st = styles()
    verdict = set_verdict(report)
    vcolor = VERDICT_COLORS[verdict.label]
    width = A4[0] - 40 * mm   # usable width
    story: list = []