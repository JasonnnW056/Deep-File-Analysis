import os
import tempfile

from flask import Blueprint, jsonify, render_template, request

from app.static_analysis.scanner import scan_file

bp = Blueprint("web", __name__)


def _scan_upload(uploaded):
    """Save the upload to a temp file, scan it, always delete the temp file."""
    suffix = os.path.splitext(uploaded.filename or "")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        uploaded.save(tmp.name)
        path = tmp.name
    try:
        report = scan_file(path)
    finally:
        os.remove(path)

    # Show the name the user uploaded, not the temp file, and don't leak the temp path
    report["file"]["name"] = uploaded.filename
    report["file"].pop("path", None)
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