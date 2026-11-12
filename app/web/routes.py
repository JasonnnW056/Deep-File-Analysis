import os
import re
import requests
import tempfile
import json
from flask import Blueprint, abort, current_app, jsonify, render_template, request, send_from_directory
from app.static_analysis.scanner import scan_file
from app.db import save_scan, get_history, get_scan
from pathlib import Path
from dynamic_analysis.backend_base import sandbox_report

#To delete the report generated
import atexit
import shutil
import sys
import signal

try:
    from dynamic_analysis.scan import dynamic_scan
    from dynamic_analysis.backend_base import detonation_error, detonation_timeout
    from generate_pdf import generate_report, set_verdict
except ImportError:
    dynamic_scan = None
    detonation_error = detonation_timeout = Exception  

bp = Blueprint("web", __name__)

_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")

_PDF_DIR= Path(tempfile.mkdtemp(prefix="temp_reports"))
atexit.register(shutil.rmtree, _PDF_DIR, ignore_errors=True)

_PDF_NAME= re.compile(r"^[A-Za-z0-9_-]+_report\.pdf$")

_LEVELS = ["none", "low", "medium", "high"]
def _safe_name(name):
    """Keep the real file name (extensions matter for analysis) but make it safe to write."""
    base = (name or "upload").replace("\\", "/").rsplit("/", 1)[-1]
    base = _BAD_CHARS.sub("_", base).strip(" .") or "upload"
    if base.split(".", 1)[0].upper() in _RESERVED:
        base = "_" + base
    if len(base) > 120:
        root, ext = os.path.splitext(base)
        base = root[:100] + ext[:20]
    return base


def _display_name(name):
    """Show the uploaded name, but never let direction-override characters spoof it."""
    return _BIDI.sub(lambda m: f"<U+{ord(m.group()):04X}>", name or "upload")


def _tmpdir():
    try:
        return tempfile.TemporaryDirectory(prefix="dfa_", ignore_cleanup_errors=True)
    except TypeError:  # Python < 3.10
        return tempfile.TemporaryDirectory(prefix="dfa_")

# =============================================================================
# SUPABASE: HASH & REPORT HISTORY
# Everything related to Supabase lives in this section.
#   - _json_safe / _summarize / _store : save a finished scan (called from _scan_upload)
#   - /history, /history/<id>          : list and re-open past scans
# The only other Supabase touchpoint is the `_store(report)` line in _scan_upload().
# =============================================================================

def _json_safe(report): # Make the report storable as jsonb: bytes/sets -> strings, and strip NUL chars (Postgres jsonb rejects \\u0000, and malware metadata often contains them).
    text = json.dumps(report, default=str)
    return json.loads(text.replace("\\u0000", ""))


def _file_type(report):   # File type lives in the filetype analyzer's data block, not in report["file"].
    env = report.get("analyzers", {}).get("filetype") or {}
    data = env.get("data") or {}
    return data.get("description") or data.get("detected_type")


def _summarize(report):   # Pull the indexed columns out of the report (matches scan_file() output).
    f = report.get("file", {})
    summary = report.get("summary", {})
    return {
        "filename": f.get("name"),
        "file_type": _file_type(report),
        "file_size": f.get("size"),
        "hashes": report.get("hashes") or {},
        "verdict": summary.get("risk_level"),  # none / low / medium / high
    }

def _store(report):
    """Best-effort save. A Supabase outage must never break the scan."""
    try:
        s = _summarize(report)
        if not s["hashes"].get("sha256"):
            current_app.logger.warning("No sha256 in report; skipping history save")
            return
        save_scan(s["filename"], s["file_type"], s["file_size"],
                  s["hashes"], s["verdict"], _json_safe(report))
    except Exception as e:
        current_app.logger.warning("Failed to save history: %s", e)

#---------------------------------------------------------------------------------------

SCAN_MODES = ("fast", "hybrid")
DEFAULT_MODE = "hybrid"


def _get_mode():
    """Read the requested scan mode; anything unknown falls back to the default."""
    mode = (request.form.get("mode") or request.args.get("mode") or DEFAULT_MODE).lower()
    return mode if mode in SCAN_MODES else DEFAULT_MODE

def is_sandbox_up():
    url = os.getenv("CAPE_URL", "http://localhost:8000").rstrip("/") + "/apiv2/"
    try:
        requests.get(url, timeout=3)   # any HTTP response means the server is up
        return True
    except requests.RequestException:
        return False

def _merge_sandbox_into_summary(report, v):
    """Make the page header reflect static + sandbox, keeping the static values."""
    summary = report.setdefault("summary", {})
    static_level = summary.get("risk_level") or "none"
    static_score = summary.get("score") or 0

    sandbox_level = "high" if v.label == "MALWARE" else "none"
    sandbox_score = round((v.risk_score or 0) * 100)

    # keep the originals for display
    summary["static_risk_level"] = static_level
    summary["static_score"] = static_score

    # the final header values: the more severe of the two
    summary["risk_level"] = max(static_level, sandbox_level, key=_LEVELS.index)
    summary["score"] = max(static_score, sandbox_score)
    summary["verdict_source"] = "static+sandbox"

def _run_hybrid_stage(path, report):
    """Hybrid = the fast static pass plus dynamic analysis.

    Plug the sandbox / behavioural timeline / MITRE mapping / VirusTotal lookup in here.
    Until one exists, say so in the report instead of pretending it ran.
    """

    if dynamic_scan is None:
        report["mode_note"] = ("Hybrid scan requested, but the sandbox is not installed. "
                               "Only the static (fast) analysis was run.")
        return

    if not is_sandbox_up():
        report["mode_note"] = "Sandbox is offline. Showing static analysis only."
        report["sandbox_offline"] = True      # the result page shows a red alert box for this
        return
    
    try:
        sb_report = dynamic_scan(path, status=print)             # sandbox_report object
    except detonation_timeout as e:
        current_app.logger.warning("Sandbox timed out: %s", e)
        report["mode_note"] = f"Sandbox timed out: {e}. Showing static analysis only."
        return
    except detonation_error as e:
        current_app.logger.warning("Sandbox error: %s", e)
        report["mode_note"] = f"Sandbox could not analyse this file: {e}. Showing static analysis only."
        return
    except Exception as e:
        current_app.logger.exception("Dynamic analysis failed")
        report["mode_note"] = f"Sandbox stage failed ({type(e).__name__}). Showing static analysis only."
        return

    report_dict = sb_report.to_dict()                                    # plain dict, no raw CAPE report
    try:
        v = set_verdict(sb_report, report)
        report_dict["verdict"] = {"label": v.label, "confidence": v.confidence_score, "reasons": v.reasons}
        _merge_sandbox_into_summary(report, v)
    except Exception:
        current_app.logger.exception("Verdict failed")

    report["dynamic"] = report_dict
    return sb_report

#---------------------------------------------------------------------------------------

def _scan_upload(uploaded, mode=DEFAULT_MODE):
    """Save under the original name in a private temp folder, scan, delete everything.

    scan_file() never raises, so failures show up in report["errors"] and in each
    analyzer's status instead of as a 500 page.
    """
    with _tmpdir() as tmpdir:
        path = os.path.join(tmpdir, _safe_name(uploaded.filename))
        uploaded.save(path)
        report = scan_file(path)          # fast pass runs in both modes
        report["scan_mode"] = mode
        dynamic_report = None
        if mode == "hybrid":
            dynamic_report=_run_hybrid_stage(path, report)
        try:
            sha = (report.get("hashes") or {}).get("sha256", "unknown")
            name = dynamic_report.task_id if dynamic_report else sha[:12]
            pdf = generate_report(dynamic_report, _PDF_DIR / f"{name}_report.pdf", static_report=report)
            report["pdf_name"] = pdf.name
        except Exception:
            current_app.logger.exception("PDF generation failed")

    report["file"]["name"] = _display_name(uploaded.filename)
    report["file"].pop("path", None)
    pdf_name = report.pop("pdf_name", None)   # don't save it in history, the file won't outlive the app
    _store(report)
    if pdf_name:
        report["pdf_name"] = pdf_name
    return report


# @bp.route("/", methods=["GET"])
# def index():
#     return render_template("index.html")

@bp.route("/", methods=["GET"])
def home():
    return render_template("homepage.html")

@bp.route("/upload", methods=["GET"])
def index():
    return render_template("index.html")

@bp.route("/scan", methods=["POST"])
def scan():
    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        return render_template("index.html", error="Choose a file to scan."), 400
    return render_template("result.html", result=_scan_upload(uploaded, _get_mode()))


@bp.route("/api/scan", methods=["POST"])
def api_scan():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify(error="No file provided"), 400
    return jsonify(_scan_upload(uploaded, _get_mode()))

@bp.route("/report/<name>", methods=["GET"])
def download_pdf(name):
    if not _PDF_NAME.match(name) or not (_PDF_DIR / name).is_file():
        abort(404)
    return send_from_directory(_PDF_DIR, name, as_attachment=True, mimetype="application/pdf")

@bp.route("/history", methods=["GET"])
def history():
    try:
        rows = get_history()
    except Exception as e:
        current_app.logger.warning("History unavailable: %s", e)
        rows = []
    return render_template("history.html", rows=rows)


@bp.route("/history/<scan_id>", methods=["GET"])
def history_item(scan_id):
    try:
        row = get_scan(scan_id)
    except Exception:
        abort(404)
    return render_template("result.html", result=row["report"])

@bp.errorhandler(413)
def too_large(_):
    return render_template("index.html", error="File is larger than 50 MB."), 413