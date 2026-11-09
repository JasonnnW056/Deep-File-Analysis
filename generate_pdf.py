from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from dynamic_analysis.backend_base import sandbox_report
from style.pdf_style import table, styles

from datetime import datetime

MALWARE_MIN_SCORE= 0.5
MAX_CONFIDENCE_SCORE= 95.0

VERDICT_COLORS={
    "MALWARE": colors.red,
    "BENIGN": colors.green,
    "INCONCLUSIVE": colors.gray
}

@dataclass
class verdict:
    label:str #MALWARE, BENIGN, INCONCLUSIVE
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
    file_content: list = []

    # ---- title
    file_content.append(Paragraph("Dynamic Analysis Report", st["title"]))
    file_content.append(Paragraph(
        f"Generated {datetime.now():%Y-%m-%d %H:%M} &nbsp;|&nbsp; "
        f"CAPE task {escape(str(report.task_id))}", st["sub"]))
    file_content.append(Spacer(1, 10))
 
    # ---- verdict banner
    verdict_cell = Paragraph(
        f'<font size="9" color="white">FINAL VERDICT</font><br/>'
        f'<font size="26" color="white"><b>{verdict.label}</b></font>', st["banner_l"])
    if verdict.confidence_score is None:
        confmake_to_text, scoremake_to_text = "n/a", "n/a"
    else:
        confmake_to_text = f"{verdict.confidence_score:.0f}%"
        scoremake_to_text = f"{float(report.cape_score):g} / {report.max_score:g}"
    stats_cell = Paragraph(
        f'<font size="9" color="#555555">CONFIDENCE</font><br/><font size="18"><b>{confmake_to_text}</b></font>'
        f'<br/><br/><font size="9" color="#555555">CAPE SCORE</font><br/>'
        f'<font size="18"><b>{scoremake_to_text}</b></font>', st["banner_r"])
    banner = Table([[verdict_cell, stats_cell]], colWidths=[width * 0.6, width * 0.4])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), vcolor),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F5F7F8")),
        ("BOX", (0, 0), (-1, -1), 1, vcolor),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    file_content.append(banner)
 
    file_content.append(Paragraph("Why this verdict", st["h"]))
    for r in verdict.reasons:
        file_content.append(Paragraph(f"&bull; {escape(r)}", st["body"]))
    file_content.append(Paragraph(
        "Confidence reflects how far the evidence sits from the malware/benign boundary. "
        "It is a heuristic, not a calibrated probability.", st["note"]))
 
    # ---- sample details
    f = report.file or {}
    file_content.append(Paragraph("Sample details", st["h"]))
    rows = [
        ("File name", f.get("name")), ("File type", f.get("type")), ("Size", f"{f.get('size')} bytes" if f.get("size") is not None else None),
        ("MD5", f.get("md5")), ("SHA-1", f.get("sha1")), ("SHA-256", f.get("sha256")),
        ("Run time in guest", f"{report.detonation_duration} s" if report.detonation_duration is not None else None),
        ("Total scan time", f"{report.total_seconds} s" if report.total_seconds is not None else None),
    ]
    data = [[Paragraph(k, st["cellb"]), Paragraph(make_to_text(v) if v is not None else "-", st["cell"])] for k, v in rows]
    file_content.append(table(data, [width * 0.25, width * 0.75], header=False))
 
    # ---- signatures
    file_content.append(Paragraph(f"Behavior signatures ({len(report.signatures)})", st["h"]))
    if report.signatures:
        data = [[Paragraph(h, st["head"]) for h in ("Severity", "Signature", "Description")]]
        for s in report.signatures[:max_items]:
            data.append([
                Paragraph(severity_label(s.get("severity")), st["cellb"]),
                Paragraph(make_to_text(s.get("name") or "-"), st["cell"]),
                Paragraph(make_to_text(s.get("description") or "-", 220), st["cell"]),
            ])
        file_content.append(table(data, [width * 0.13, width * 0.27, width * 0.60]))
        if len(report.signatures) > max_items:
            file_content.append(Paragraph(
                f"Showing the {max_items} highest-severity signatures of {len(report.signatures)}. "
                "The rest are in the saved raw report.", st["note"]))
    else:
        file_content.append(Paragraph("No signatures triggered.", st["muted"]))
 
    # ---- TTPs
    file_content.append(Paragraph(f"MITRE ATT&amp;CK techniques ({len(report.ttps)})", st["h"]))
    if report.ttps:
        file_content.append(Paragraph(", ".join(make_to_text(t, 40) for t in report.ttps), st["body"]))
    else:
        file_content.append(Paragraph("None reported.", st["muted"]))
 
    # ---- behavior
    file_content.append(Paragraph("Observed behavior", st["h"]))
    labels = {
        "executed_commands": "Commands executed", "files_written": "Files written",
        "files_deleted": "Files deleted", "registry_written": "Registry keys written",
        "mutexes": "Mutexes", "services_created": "Services created",
    }
    behavior = report.behavior or {}
    data = []
    for key, label in labels.items():
        items = behavior.get(key) or []
        shown = items[:10]
        text = "<br/>".join(make_to_text(i) for i in shown) if shown else "-"
        if len(items) > len(shown):
            text += f"<br/>... and {len(items) - len(shown)} more"
        data.append([Paragraph(f"{label} ({len(items)})", st["cellb"]), Paragraph(text, st["cell"])])
    file_content.append(table(data, [width * 0.25, width * 0.75], header=False))
 
    # ---- network
    net = report.network or {}
    file_content.append(Paragraph("Network activity", st["h"]))
    data = []
    for key, label in (("hosts", "Hosts contacted"), ("domains", "Domains"), ("http", "HTTP requests")):
        items = net.get(key) or []
        shown = items[:10]
        text = "<br/>".join(make_to_text(i) for i in shown) if shown else "-"
        if len(items) > len(shown):
            text += f"<br/>... and {len(items) - len(shown)} more"
        data.append([Paragraph(f"{label} ({len(items)})", st["cellb"]), Paragraph(text, st["cell"])])
    data.append([Paragraph("TCP / UDP connections", st["cellb"]),
                 Paragraph(f"{net.get('tcp_count', 0)} TCP, {net.get('udp_count', 0)} UDP", st["cell"])])
    file_content.append(table(data, [width * 0.25, width * 0.75], header=False))
 
    # ---- dropped files
    file_content.append(Paragraph(
        f"Dropped files ({len(report.dropped_files)}) and extracted payloads "
        f"({report.total_extracted_payloads})", st["h"]))
    if report.dropped_files:
        data = [[Paragraph(h, st["head"]) for h in ("Name", "Type", "Size", "SHA-256")]]
        for d in report.dropped_files[:max_items]:
            data.append([Paragraph(make_to_text(d.get("name") or "-", 60), st["cell"]),
                         Paragraph(make_to_text(d.get("type") or "-", 50), st["cell"]),
                         Paragraph(make_to_text(d.get("size") if d.get("size") is not None else "-"), st["cell"]),
                         Paragraph(make_to_text(d.get("sha256") or "-", 70), st["cell"])])
        file_content.append(table(data, [width * 0.22, width * 0.23, width * 0.10, width * 0.45]))
    else:
        file_content.append(Paragraph("No files dropped.", st["muted"]))
 
    # ---- disclaimer
    file_content.append(Spacer(1, 16))
    file_content.append(Paragraph(
        "This verdict comes from automated dynamic analysis in a sandbox with a limited run time. "
        "Malware that waits, detects the sandbox or needs user interaction can look benign. "
        "A BENIGN verdict does not guarantee a file is safe.", st["note"]))
 
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(20 * mm, 10 * mm, f"Verdict: {verdict.label}  |  Task {report.task_id}")
        canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()
 
    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Dynamic Analysis Report - {report.task_id}", author="Dynamic analysis pipeline",
    )
    doc.build(file_content, onFirstPage=footer, onLaterPages=footer)
    return out_path

