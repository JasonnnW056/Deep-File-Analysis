"""pdf_analyzer.py - static PDF triage. No parsing library: it scans the raw bytes
(and the contents of object streams) for risky PDF keywords."""

import re
import zlib
from collections import Counter
from pathlib import Path

ANALYZER_NAME = "pdf"

MAX_PDF_SIZE = 64 * 1024 * 1024
MAX_OBJSTM = 200
MAX_DECOMPRESSED = 4 * 1024 * 1024
MAX_LIST = 50

WATCHED = {"JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles",
           "URI", "SubmitForm", "ImportData", "RichMedia", "XFA", "AcroForm", "Encrypt",
           "GoToR", "GoToE", "ObjStm", "JBIG2Decode"}

_NAME = re.compile(rb"/([A-Za-z0-9_.#\-]{1,60})")
_HEX_ESC = re.compile(rb"#([0-9A-Fa-f]{2})")
_URI = re.compile(rb"/URI\s*\(((?:[^()\\]|\\.){1,300})\)")
_EXEC_FILE = re.compile(
    rb"(?i)/U?F\s*\(((?:[^()\\]|\\.){1,200}\.(?:exe|scr|dll|js|jse|vbs|vbe|bat|cmd|ps1|hta|lnk|jar|msi))\)")
_STREAM = re.compile(rb"(?<!end)stream\r?\n")
_JS_KEY = re.compile(rb"/(?:JS|JavaScript)(?![A-Za-z0-9])")
# /JavaScript used as a name-tree key = document-level script, which runs when the file opens
_DOC_LEVEL_JS = re.compile(rb"/JavaScript\s*(?:\d+\s+\d+\s+R|<<)")


def _result(status, error=None, data=None, findings=None):
    return {"analyzer": ANALYZER_NAME, "status": status, "error": error,
            "data": data or {}, "findings": findings or []}


def _finding(fid, severity, message, **detail):
    return {"id": fid, "analyzer": ANALYZER_NAME, "severity": severity,
            "message": message, "detail": detail}


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def _js_contexts(blobs, limit=3):
    """A few short snippets around JavaScript keywords, so a person can see what it is."""
    out = []
    for blob in blobs:
        for m in _JS_KEY.finditer(blob):
            if len(out) >= limit:
                return out
            out.append(_printable(blob[max(0, m.start() - 80):m.end() + 160]))
    return out


def _decode_name(raw: bytes) -> str:
    return _HEX_ESC.sub(lambda m: bytes([int(m.group(1), 16)]), raw).decode("latin-1")


def _count_names(buf: bytes, counter: Counter, obfuscated: set):
    for m in _NAME.finditer(buf):
        raw = m.group(1)
        name = _decode_name(raw)
        if name in WATCHED:
            counter[name] += 1
            if b"#" in raw:
                obfuscated.add(name)


def _object_streams(data: bytes):
    """Yield decompressed contents of /ObjStm streams (where hidden objects live)."""
    n = 0
    for m in _STREAM.finditer(data):
        if n >= MAX_OBJSTM:
            return
        start = m.end()
        if b"/ObjStm" not in data[max(0, m.start() - 400):m.start()]:
            continue
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        n += 1
        try:
            d = zlib.decompressobj()
            yield d.decompress(data[start:end], MAX_DECOMPRESSED)
        except zlib.error:
            continue


def analyze_pdf(path) -> dict:
    path = Path(path)
    if not path.is_file():
        return _result("error", error="File not found")
    try:
        size = path.stat().st_size
        if size > MAX_PDF_SIZE:
            return _result("skipped", error=f"File too large (> {MAX_PDF_SIZE // 2**20} MB)")
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return _result("error", error=f"Cannot read file: {e}")

    header = data.find(b"%PDF-", 0, 1024)
    if header < 0:
        return _result("skipped", error="Not a PDF file (no %PDF- header)")

    try:
        counts, obfuscated = Counter(), set()
        _count_names(data, counts, obfuscated)
        hidden = Counter()
        extra_text = []
        for blob in _object_streams(data):
            extra_text.append(blob)
            _count_names(blob, hidden, obfuscated)
        counts.update(hidden)
        searchable = data + b"\n".join(extra_text)

        uris = []
        for m in _URI.finditer(searchable):
            u = m.group(1).decode("latin-1")
            if u not in uris:
                uris.append(u)
            if len(uris) >= MAX_LIST:
                break
        exec_files = sorted({m.group(1).decode("latin-1") for m in _EXEC_FILE.finditer(searchable)})[:MAX_LIST]

        version = re.search(rb"%PDF-(\d\.\d)", data[header:header + 16])
        js = counts["JavaScript"] + counts["JS"]
        all_blobs = [data] + extra_text
        doc_level_js = bool(js) and any(_DOC_LEVEL_JS.search(b) for b in all_blobs)
        contexts = _js_contexts(all_blobs) if js else []
        findings = []

        if counts["Launch"]:
            findings.append(_finding("PDF_LAUNCH_ACTION", "high",
                                     "PDF can launch external programs or files (/Launch)",
                                     count=counts["Launch"]))
        if js and counts["OpenAction"]:
            findings.append(_finding("PDF_AUTO_JAVASCRIPT", "high",
                                     "JavaScript combined with an automatic open action",
                                     javascript=js, open_action=counts["OpenAction"],
                                     context=contexts))
        elif js and doc_level_js:
            findings.append(_finding("PDF_DOCUMENT_JAVASCRIPT", "medium",
                                     "Document-level JavaScript (runs when the file is opened)",
                                     count=js, context=contexts))
        elif js:
            findings.append(_finding("PDF_JAVASCRIPT", "low",
                                     f"PDF contains JavaScript that does not run automatically ({js} reference(s))",
                                     count=js, context=contexts))
        if exec_files:
            findings.append(_finding("PDF_EMBEDDED_EXECUTABLE_NAME", "high",
                                     "PDF references an executable or script file name",
                                     files=exec_files))
        if counts["EmbeddedFile"] or counts["EmbeddedFiles"]:
            findings.append(_finding("PDF_EMBEDDED_FILES", "medium", "PDF contains embedded files",
                                     count=counts["EmbeddedFile"] + counts["EmbeddedFiles"]))
        if counts["RichMedia"]:
            findings.append(_finding("PDF_RICH_MEDIA", "medium",
                                     "PDF contains rich media (Flash/video objects)"))
        if obfuscated:
            findings.append(_finding("PDF_OBFUSCATED_NAMES", "medium",
                                     "Risky keywords are hidden with #-escapes in their names",
                                     names=sorted(obfuscated)))
        if counts["GoToR"] or counts["GoToE"]:
            findings.append(_finding("PDF_REMOTE_GOTO", "low",
                                     "PDF links to remote or embedded documents"))
        if counts["SubmitForm"] or counts["ImportData"]:
            findings.append(_finding("PDF_FORM_SUBMIT", "low", "PDF can submit or import form data"))
        if counts["XFA"]:
            findings.append(_finding("PDF_XFA_FORMS", "low", "PDF uses XFA forms (larger attack surface)"))
        if counts["Encrypt"]:
            findings.append(_finding("PDF_ENCRYPTED", "low",
                                     "PDF is encrypted: some content could not be inspected"))
        if header > 0:
            findings.append(_finding("PDF_HEADER_OFFSET", "low",
                                     f"Data before the %PDF header ({header} bytes)", offset=header))
        if b"%%EOF" not in data[-2048:]:
            findings.append(_finding("PDF_NO_EOF", "low", "No %%EOF marker at the end (truncated or malformed)"))
        if uris:
            findings.append(_finding("PDF_URIS", "info", f"{len(uris)} URI(s) in the document", uris=uris))

        out = {
            "version": version.group(1).decode() if version else None,
            "size": size,
            "objects": len(re.findall(rb"\b\d+\s+\d+\s+obj\b", data)),
            "pages_estimate": len(re.findall(rb"/Type\s*/Page\b", searchable)),
            "keywords": {k: counts[k] for k in sorted(counts)},
            "object_streams_inspected": len(extra_text),
            "keywords_hidden_in_object_streams": dict(hidden),
            "encrypted": bool(counts["Encrypt"]),
            "uris": uris,
        }
        return _result("ok", data=out, findings=findings)
    except Exception as e:  # one weird file must never stop a scan
        return _result("error", error=f"Unexpected parse failure: {type(e).__name__}: {e}")