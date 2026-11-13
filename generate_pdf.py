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

# If the sandbox run looks benign but the static scan flagged the file, the two
# disagree, so the confidence is capped. Set STATIC_CONFLICT_LEVELS = () to disable.
STATIC_CONFLICT_LEVELS= ("medium", "high")
STATIC_CONFLICT_MAX_CONFIDENCE= 60.0

STATIC_RISK_COLORS= {
    "high": "#B71C1C", "medium": "#E65100", "low": "#F9A825", "info": "#607D8B", "none": "#2E7D32",
}
ANALYZER_STATUS_COLORS= {"ok": "#2E7D32", "skipped": "#607D8B", "error": "#B71C1C"}

VERDICT_COLORS = {
    "MALWARE": colors.red,
    "SUSPICIOUS": colors.orange,
    "LIKELY BENIGN": colors.HexColor("#66BB6A"),
    "BENIGN": colors.green,
    "INCONCLUSIVE": colors.gray,
}

@dataclass
class verdict:
    label:str #MALWARE, SUSPICIOUS, LIKELY BENIGN, BENIGN, INCONCLUSIVE
    confidence_score: float| None
    risk_score: float| None
    reasons: list[str]

#Get the dectection findings actual content from the list
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

def static_note(static_report: dict | None):
    # One line for the verdict reasons, plus the static risk level (None if no static scan)
    if not static_report:
        return None, None
    summary = static_report.get("summary") or {}
    level = summary.get("risk_level")
    if level is None:
        return None, None
    line = f"Static analysis risk: {level} (score {summary.get('score', 0)}/100)."
    if not summary.get("complete", True):
        line += " Some analyzers failed, so this may be incomplete."
    return line, level

#Set the verdict for the static analysis (MALWARE, SUSPICIOUS, LIKELY BENIGN, BENIGN, INCONCLUSIVE)
def set_static_verdict(static_report: dict) -> verdict:
    line, level = static_note(static_report)
    reasons = [line or "No static risk level available."]
    reasons.append("No sandbox run was performed, so behavior was not observed.")
    summary = static_report.get("summary") or {}
 
    if level in ("high", "medium"):
        return verdict("SUSPICIOUS", None, None, reasons)
 
    # Clean or low-risk result from a complete static scan: say so, but not "BENIGN",
    # because a static scan alone can't prove a file is safe.
    if level in ("none", "low") and summary.get("complete", True):
        reasons.append("No analyzer flagged anything significant. This is based on static inspection only.")
        return verdict("LIKELY BENIGN", None, None, reasons)
 
    return verdict("INCONCLUSIVE", None, None, reasons)

 #For static analysis
def dynamic_recommendation(label: str, static_report: dict) -> str | None:
    """Text telling the reader what to do next when no sandbox run is behind the verdict."""
    mode_note = static_report.get("mode_note")
    fast_mode = static_report.get("scan_mode") == "fast"
 
    if label == "SUSPICIOUS":
        return ("Static analysis flagged this file. Run dynamic analysis before trusting or opening it."
                + (" Choose Hybrid scan mode." if fast_mode else ""))
    if label == "LIKELY BENIGN":
        if mode_note:
            return ("Dynamic analysis is recommended to confirm, but it could not be completed this time. "
                    "Try the hybrid scan again later.")
        if fast_mode:
            return "Dynamic analysis is recommended to confirm. Run a hybrid scan to check how the file behaves."
        return "Dynamic analysis is recommended to confirm."
    return None

#Set the verdict for dynamic analysis (MALWARE, SUSPICIOUS, LIKELY BENIGN, BENIGN, INCONCLUSIVE)
MAX_BENIGN_CONFIDENCE = 80.0
SUSPICIOUS_MIN_SCORE = 0.3
def set_verdict(report: sandbox_report, static_report: dict | None= None)-> verdict:
    static_line, static_level = static_note(static_report)
    if report.cape_score is None:
        return verdict("INCONCLUSIVE", None, None, ["CAPE did not return a score for the sample submitted"])
    
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
    if static_line:
        reasons.append(static_line)

        risk = min(risk, 1.0)
    if malware_found:
        risk = max(risk, 0.6)

    # Did the sample actually do anything in the sandbox?
    observed = any((report.behavior or {}).values())
    executed = observed and (report.detonation_duration or 0) > 0
    if risk < 0.2 and not executed:
        return verdict("INCONCLUSIVE", None, risk,
                       reasons + ["No activity was observed, so the sample may not have run."])

    if risk >= MALWARE_MIN_SCORE:
        label = "MALWARE"
        confidence = min(50.0 + (risk - MALWARE_MIN_SCORE) * 100.0, MAX_CONFIDENCE_SCORE)
    elif risk >= SUSPICIOUS_MIN_SCORE:
        label = "SUSPICIOUS"
        confidence = 55.0
        reasons.append("The evidence falls between benign and malicious. Review this file manually.")
    else:
        label = "BENIGN"
        confidence = min(50.0 + (MALWARE_MIN_SCORE - risk) * 100.0, MAX_BENIGN_CONFIDENCE)

    if label == "BENIGN" and static_level in STATIC_CONFLICT_LEVELS:
        confidence = min(confidence, STATIC_CONFLICT_MAX_CONFIDENCE)
        reasons.append("Static analysis flagged this file, but the sandbox run looked benign. "
                       "The sample may not have run fully (for example, it may wait or detect "
                       "the sandbox), so this verdict is less certain.")
    return verdict(label, confidence, risk, reasons)

#Helper function
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

def risk_text(level: str) -> str:
    color = STATIC_RISK_COLORS.get(level, "#607D8B")
    return f'<font color="{color}"><b>{escape(str(level).upper())}</b></font>'

def virustotal_text(env: dict) -> str:
    status = env.get("status")
    data = env.get("data") or {}
    if status == "skipped":
        return f"not run ({make_to_text(env.get('error') or 'skipped')})"
    if status == "error":
        return f"lookup failed ({make_to_text(env.get('error') or 'unknown error')})"
    if not data.get("found"):
        return "hash not known to VirusTotal (this is not proof the file is safe)"
    text = f"{data.get('malicious', 0)} of {data.get('total', 0)} engines flag this file as malicious"
    if data.get("suspicious"):
        text += f" ({data['suspicious']} suspicious)"
    if data.get("threat_label"):
        text += f", label: {data['threat_label']}"
    text = make_to_text(text, 200)
    link = data.get("link")
    if link and str(link).startswith("https://"):
        text += f' - <link href="{escape(str(link), {chr(34): "&quot;"})}" color="blue">view on VirusTotal</link>'
    return text

def yara_text(env: dict) -> str:
    if env.get("status") != "ok":
        return f"not run ({make_to_text(env.get('error') or env.get('status') or 'unknown')})"
    return f"{(env.get('data') or {}).get('match_count', 0)} rule match(es)"

#Add static findings section to the pdf if there is static analysis run
def add_static_section(file_content: list, static_report: dict, st: dict, width: float,
                       max_items: int, dynamic_sha256: str | None= None) -> None:
    summary = static_report.get("summary") or {}
    analyzers = static_report.get("analyzers") or {}
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings = sorted(static_report.get("findings") or [],
                      key=lambda f: severity_rank.get(f.get("severity"), 3))
    hashes = static_report.get("hashes") or {}
    level = summary.get("risk_level", "none")
    filetype = (analyzers.get("filetype") or {}).get("data") or {}
    generic = (analyzers.get("generic") or {}).get("data") or {}

    file_content.append(Paragraph("Static analysis", st["h"]))
    file_content.append(Paragraph(
        "The file was inspected without running it. A risk of NONE means nothing was flagged, "
        "which is not proof the file is safe.", st["note"]))
    file_content.append(Spacer(1, 4))

    rows = [("Static risk", f"{risk_text(level)} (score {summary.get('score', 0)}/100)")]
    if filetype:
        text = make_to_text(filetype.get("description") or filetype.get("detected_type") or "-")
        if filetype.get("extension_matches") is False:
            text += " - the extension does NOT match the content"
        rows.append(("Detected file type", text))
    if generic.get("entropy") is not None:
        rows.append(("Entropy", f"{generic['entropy']} out of 8 (above 7.5 suggests packing or encryption)"))
    if hashes.get("imphash"):
        rows.append(("Imphash", make_to_text(hashes["imphash"])))
    for key, label in (("urls", "URLs in file"), ("public_ips", "Public IPs in file")):
        items = generic.get(key) or []
        if items:
            text = "<br/>".join(make_to_text(i) for i in items[:10])
            if len(items) > 10:
                text += f"<br/>... and {len(items) - 10} more"
            rows.append((f"{label} ({len(items)})", text))
    if "yara" in analyzers:
        rows.append(("YARA", yara_text(analyzers["yara"])))
    if "virustotal" in analyzers:
        rows.append(("VirusTotal", virustotal_text(analyzers["virustotal"])))
    static_sha = hashes.get("sha256")
    if dynamic_sha256 and static_sha and str(dynamic_sha256).lower() != str(static_sha).lower():
        rows.append(("Hash check", '<font color="#B71C1C"><b>MISMATCH</b></font>: the sandbox and the '
                                   'static scan saw different files'))
    data = [[Paragraph(k, st["cellb"]), Paragraph(v, st["cell"])] for k, v in rows]
    file_content.append(table(data, [width * 0.25, width * 0.75], header=False))

    for err in static_report.get("errors") or []:
        file_content.append(Paragraph(f"Static scan error: {make_to_text(err, 200)}", st["note"]))

    # Which analyzers actually checked the file
    if analyzers:
        data = [[Paragraph(h, st["head"]) for h in ("Analyzer", "Status", "Result")]]
        for name, env in analyzers.items():
            status = env.get("status", "?")
            color = ANALYZER_STATUS_COLORS.get(status, "#607D8B")
            note = f"{len(env.get('findings') or [])} finding(s)" if status == "ok" else (env.get("error") or "-")
            data.append([Paragraph(make_to_text(name, 30), st["cellb"]),
                         Paragraph(f'<font color="{color}">{escape(str(status))}</font>', st["cell"]),
                         Paragraph(make_to_text(note, 160), st["cell"])])
        file_content.append(Spacer(1, 6))
        file_content.append(table(data, [width * 0.18, width * 0.12, width * 0.70]))
        if any(env.get("status") != "ok" for env in analyzers.values()):
            file_content.append(Paragraph(
                "Skipped analyzers did not apply to this file type. Failed analyzers did not check "
                "the file, so no findings from them does not mean it is clean.", st["note"]))

    # Findings
    file_content.append(Paragraph(f"Static findings ({len(findings)})", st["h"]))
    if findings:
        data = [[Paragraph(h, st["head"]) for h in ("Severity", "Analyzer", "Finding")]]
        for f in findings[:max_items]:
            sev = str(f.get("severity", "info"))
            analyzer = str(f.get("analyzer", "-")).removesuffix("_analyzer")
            data.append([Paragraph(risk_text(sev), st["cell"]),
                         Paragraph(make_to_text(analyzer, 30), st["cell"]),
                         Paragraph(make_to_text(f.get("message") or f.get("id") or "-", 220), st["cell"])])
        file_content.append(table(data, [width * 0.13, width * 0.15, width * 0.72]))
        if len(findings) > max_items:
            file_content.append(Paragraph(
                f"Showing the {max_items} most severe findings of {len(findings)}. "
                "The rest are in the full static scan result.", st["note"]))
    else:
        file_content.append(Paragraph("No static findings.", st["muted"]))

    # ---- PE details
    pe = analyzers.get("pe") or {}
    if pe.get("status") == "ok":
        d = pe.get("data") or {}
        file_content.append(Paragraph("PE file details", st["h"]))
        rows = [
            ("Format", f"{d.get('file_type')}, {d.get('bitness')}, machine {d.get('machine')}"),
            ("Compiled", d.get("compile_timestamp") or "-"),
            ("Entry point", d.get("entry_point") or "-"),
            ("Digital signature", "present (not validated)" if d.get("has_signature") else "none"),
            ("Imports", f"{d.get('import_count', 0)} functions from {len(d.get('imports') or {})} DLLs"),
        ]
        if d.get("overlay_size"):
            rows.append(("Overlay", f"{d['overlay_size']} bytes appended after the last section"))
        data = [[Paragraph(k, st["cellb"]), Paragraph(make_to_text(v), st["cell"])] for k, v in rows]
        file_content.append(table(data, [width * 0.25, width * 0.75], header=False))

        sections = d.get("sections") or []
        if sections:
            data = [[Paragraph(h, st["head"]) for h in ("Section", "Raw size", "Entropy", "Flags")]]
            for s in sections[:max_items]:
                flags = ("W" if s.get("writable") else "") + ("X" if s.get("executable") else "")
                if flags == "WX":
                    flags = '<font color="#B71C1C"><b>WX</b></font>'
                data.append([Paragraph(make_to_text(s.get("name") or "-", 20), st["cell"]),
                             Paragraph(make_to_text(s.get("raw_size", "-")), st["cell"]),
                             Paragraph(make_to_text(s.get("entropy", "-")), st["cell"]),
                             Paragraph(flags or "-", st["cell"])])
            file_content.append(Spacer(1, 6))
            file_content.append(table(data, [width * 0.35, width * 0.20, width * 0.20, width * 0.25]))

#Add dynamic findings section to the pdf if there is dynamic analysis run
def add_dynamic_section(file_content: list, sandbox_report, st: dict, width: float,
                        max_items: int) -> None:
    # ---- signatures
    file_content.append(Paragraph(f"Behavior signatures ({len(sandbox_report.signatures)})", st["h"]))
    if sandbox_report.signatures:
        data = [[Paragraph(h, st["head"]) for h in ("Severity", "Signature", "Description")]]
        for s in sandbox_report.signatures[:max_items]:
            data.append([
                Paragraph(severity_label(s.get("severity")), st["cellb"]),
                Paragraph(make_to_text(s.get("name") or "-"), st["cell"]),
                Paragraph(make_to_text(s.get("description") or "-", 220), st["cell"]),
            ])
        file_content.append(table(data, [width * 0.13, width * 0.27, width * 0.60]))
        if len(sandbox_report.signatures) > max_items:
            file_content.append(Paragraph(
                f"Showing the {max_items} highest-severity signatures of {len(sandbox_report.signatures)}. "
                "The rest are in the saved raw report.", st["note"]))
    else:
        file_content.append(Paragraph("No signatures triggered.", st["muted"]))

    # TTPs
    file_content.append(Paragraph(f"MITRE ATT&amp;CK techniques ({len(sandbox_report.ttps)})", st["h"]))
    if sandbox_report.ttps:
        file_content.append(Paragraph(", ".join(make_to_text(t, 40) for t in sandbox_report.ttps), st["body"]))
    else:
        file_content.append(Paragraph("None reported.", st["muted"]))

    # Behavior
    file_content.append(Paragraph("Observed behavior", st["h"]))
    labels = {
        "executed_commands": "Commands executed", "files_written": "Files written",
        "files_deleted": "Files deleted", "registry_written": "Registry keys written",
        "mutexes": "Mutexes", "services_created": "Services created",
    }
    behavior = sandbox_report.behavior or {}
    data = []
    for key, label in labels.items():
        items = behavior.get(key) or []
        shown = items[:10]
        text = "<br/>".join(make_to_text(i) for i in shown) if shown else "-"
        if len(items) > len(shown):
            text += f"<br/>... and {len(items) - len(shown)} more"
        data.append([Paragraph(f"{label} ({len(items)})", st["cellb"]), Paragraph(text, st["cell"])])
    file_content.append(table(data, [width * 0.25, width * 0.75], header=False))

    # Network
    net = sandbox_report.network or {}
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

    # Dropped files
    file_content.append(Paragraph(
        f"Dropped files ({len(sandbox_report.dropped_files)}) and extracted payloads "
        f"({sandbox_report.total_extracted_payloads})", st["h"]))
    if sandbox_report.dropped_files:
        data = [[Paragraph(h, st["head"]) for h in ("Name", "Type", "Size", "SHA-256")]]
        for d in sandbox_report.dropped_files[:max_items]:
            data.append([Paragraph(make_to_text(d.get("name") or "-", 60), st["cell"]),
                         Paragraph(make_to_text(d.get("type") or "-", 50), st["cell"]),
                         Paragraph(make_to_text(d.get("size") if d.get("size") is not None else "-"), st["cell"]),
                         Paragraph(make_to_text(d.get("sha256") or "-", 70), st["cell"])])
        file_content.append(table(data, [width * 0.22, width * 0.23, width * 0.10, width * 0.45]))
    else:
        file_content.append(Paragraph("No files dropped.", st["muted"]))

#Generating the final report
def generate_report(sandbox_report: sandbox_report|None, out_path: str | Path, max_items: int = 15,
                    static_report: dict | None= None) -> Path:

    if sandbox_report is None and not static_report:
        raise ValueError("Need a sandbox report, a static report, or both")
    
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
 
    st = styles()
    verdict = (set_verdict(sandbox_report, static_report) if sandbox_report
               else set_static_verdict(static_report))
    sha = ((static_report or {}).get("hashes") or {}).get("sha256", "unknown")
    task_id = sandbox_report.task_id if sandbox_report else sha[:12]
    vcolor = VERDICT_COLORS[verdict.label]
    width = A4[0] - 40 * mm   # usable width
    file_content: list = []

    # Title
    if sandbox_report and static_report:
        title = "Static and Dynamic Analysis Report"
    elif static_report:
        title = "Static Analysis Report"
    else:
        title = "Dynamic Analysis Report"
    file_content.append(Paragraph(title, st["title"]))
    file_content.append(Paragraph(
    f"Generated {datetime.now():%Y-%m-%d %H:%M} &nbsp;|&nbsp; "
    + (f"CAPE task {escape(str(task_id))}" if sandbox_report
       else f"SHA-256 {escape(sha[:16])}"), st["sub"]))
    file_content.append(Spacer(1, 10))
 
    # Verdict banner
    verdict_cell = Paragraph(
        f'<font size="9" color="white">FINAL VERDICT</font><br/>'
        f'<font size="26" color="white"><b>{verdict.label}</b></font>', st["banner_l"])
    confmake_to_text = f"{verdict.confidence_score:.0f}%" if verdict.confidence_score is not None else "N/A"
    if sandbox_report is not None and sandbox_report.cape_score is not None:
        scoremake_to_text = f"{float(sandbox_report.cape_score):g} / {sandbox_report.max_score or 10.0:g}"
    else:
        scoremake_to_text = "N/A"

    if sandbox_report is None and static_report:
        if static_report.get("mode_note"):
            # Hybrid was requested but the sandbox missing/offline/timed out/errored
            why = static_report["mode_note"]
        elif static_report.get("scan_mode") == "fast":
            # The user chose fast mode, so nothing went wrong
            why = "Fast scan mode was selected, so dynamic analysis was not requested."
        else:
            why = "Dynamic analysis was not run for this sample."
        verdict.reasons.append(why)

         #(Only for SUSPICIOUS / LIKELY BENIGN)
        advice = dynamic_recommendation(verdict.label, static_report)
        if advice:
            verdict.reasons.append(advice)

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
 
    # Sample details
    if sandbox_report:
        f = sandbox_report.file or {}
    else:
        sf = static_report.get("file") or {}
        h = static_report.get("hashes") or {}
        ft = ((static_report.get("analyzers") or {}).get("filetype") or {}).get("data") or {}
        f = {"name": sf.get("name"), "type": ft.get("description") or ft.get("detected_type"),
             "size": sf.get("size"), "md5": h.get("md5"), "sha1": h.get("sha1"), "sha256": h.get("sha256")}

    file_content.append(Paragraph("Sample details", st["h"]))
    rows = [
        ("File name", f.get("name")), ("File type", f.get("type")),
        ("Size", f"{f.get('size')} bytes" if f.get("size") is not None else None),
        ("MD5", f.get("md5")), ("SHA-1", f.get("sha1")), ("SHA-256", f.get("sha256")),
    ]
    if sandbox_report:
        rows += [
            ("Run time in guest", f"{sandbox_report.detonation_duration} s" if sandbox_report.detonation_duration is not None else None),
            ("Total scan time", f"{sandbox_report.total_seconds} s" if sandbox_report.total_seconds is not None else None),
        ]
    data = [[Paragraph(k, st["cellb"]), Paragraph(make_to_text(v) if v is not None else "-", st["cell"])] for k, v in rows]
    file_content.append(table(data, [width * 0.25, width * 0.75], header=False))

    # Static analysis
    if static_report:
        add_static_section(file_content, static_report, st, width, max_items,
                           dynamic_sha256=f.get("sha256"))

    # Dynamic analysis   
    if sandbox_report:
        add_dynamic_section(file_content, sandbox_report, st, width, max_items)
    else:
        file_content.append(Paragraph("Dynamic analysis", st["h"]))
        file_content.append(Paragraph("Dynamic analysis was not run for this sample.", st["muted"]))
        
    # Disclaimer
    file_content.append(Spacer(1, 16))
    if sandbox_report:
        disclaimer = ("This verdict comes from automated dynamic analysis in a sandbox with a limited run time. "
                    "Malware that waits, detects the sandbox or needs user interaction can look benign. "
                    "A BENIGN verdict does not guarantee a file is safe."
                    + (" Static analysis only reads the file, so packed or encrypted samples can look clean."
                        if static_report else ""))
    else:
        disclaimer = ("This verdict is based on static inspection only. The file was never executed, so "
                    "packed, encrypted or obfuscated samples can look clean. No verdict here is a "
                    "guarantee that a file is safe.")
    file_content.append(Paragraph(disclaimer, st["note"]))

    id_label = "Task" if sandbox_report else "SHA-256"

    #Set footer content for the pdf file
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(20 * mm, 10 * mm, f"Verdict: {verdict.label}  |  {id_label} {task_id}")
        canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()
 
    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"{title} - {task_id}", author="Analysis pipeline"
    )
    doc.build(file_content, onFirstPage=footer, onLaterPages=footer)
    return out_path

