import os
import re
import tempfile

from flask import Blueprint, jsonify, render_template, request

from app.static_analysis.scanner import scan_file

bp = Blueprint("web", __name__)

_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")


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


def _scan_upload(uploaded):
    """Save under the original name in a private temp folder, scan, delete everything.

    scan_file() never raises, so failures show up in report["errors"] and in each
    analyzer's status instead of as a 500 page.
    """
    with _tmpdir() as tmpdir:
        path = os.path.join(tmpdir, _safe_name(uploaded.filename))
        uploaded.save(path)
        report = scan_file(path)

    report["file"]["name"] = _display_name(uploaded.filename)
    report["file"].pop("path", None)  # don't leak the temp path
    return report


@bp.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@bp.route("/scan", methods=["POST"])
def scan():
    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        return render_template("index.html", error="Choose a file to scan."), 400
    return render_template("result.html", result=_scan_upload(uploaded))


@bp.route("/api/scan", methods=["POST"])
def api_scan():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify(error="No file provided"), 400
    return jsonify(_scan_upload(uploaded))


@bp.errorhandler(413)
def too_large(_):
    return render_template("index.html", error="File is larger than 50 MB."), 413