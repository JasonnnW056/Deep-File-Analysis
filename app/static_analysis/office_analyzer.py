# office_analyzer.py
import re
import zipfile
from collections import Counter
from pathlib import Path

ANALYZER_NAME = "office"

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_READ = 64 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_XML_READ = 4 * 1024 * 1024
MAX_LIST = 50
EXEC_EXTS = (".exe", ".scr", ".dll", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd",
             ".ps1", ".hta", ".lnk", ".jar", ".msi", ".cpl", ".com", ".pif", ".wsf")

_REL_TAG = re.compile(rb"<Relationship\b[^>]*>", re.I)
_ATTR = re.compile(rb'([A-Za-z:]+)\s*=\s*"([^"]*)"')
_DDE = re.compile(rb'(?:<w:instrText[^>]*>|w:instr=")\s*(DDEAUTO|DDE)\b')


def _result(status, error=None, data=None, findings=None):
    return {"analyzer": ANALYZER_NAME, "status": status, "error": error,
            "data": data or {}, "findings": findings or []}


def _finding(fid, severity, message, **detail):
    return {"id": fid, "analyzer": ANALYZER_NAME, "severity": severity,
            "message": message, "detail": detail}


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le")


def _oletools_macros(path):
    """Deeper macro analysis when oletools is installed. Returns None if unavailable."""
    try:
        from oletools.olevba import VBA_Parser
    except Exception:
        return None
    vp = None
    try:
        vp = VBA_Parser(str(path))
        if not vp.detect_vba_macros():
            return {"macros": False}
        res = vp.analyze_macros()
        return {
            "macros": True,
            "autoexec": sorted({k for t, k, _ in res if t == "AutoExec"}),
            "suspicious": sorted({k for t, k, _ in res if t == "Suspicious"}),
            "iocs": sorted({k for t, k, _ in res if t == "IOC"})[:20],
            "counts": dict(Counter(t for t, _, _ in res)),
        }
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        if vp is not None:
            try:
                vp.close()
            except Exception:
                pass


def _macro_findings(info, findings):
    if not info or not info.get("macros"):
        return
    auto, susp = info.get("autoexec"), info.get("suspicious")
    if auto and susp:
        findings.append(_finding(
            "OFFICE_MACRO_AUTOEXEC_SUSPICIOUS", "high",
            "Macro runs automatically and uses suspicious functions (Shell, download, etc.)",
            autoexec=auto, suspicious=susp))
    elif auto:
        findings.append(_finding("OFFICE_MACRO_AUTOEXEC", "low",
                                 "Macro runs automatically when the file is opened", autoexec=auto))
    elif susp:
        findings.append(_finding("OFFICE_MACRO_SUSPICIOUS", "low",
                                 "Macro uses suspicious functions", suspicious=susp))


def _xml_meta(zf, name):
    try:
        return zf.read(name)[:MAX_XML_READ]
    except KeyError:
        return b""


def _analyze_ooxml(path):
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return _result("error", error="Corrupt ZIP / OOXML container")
    with zf:
        names = zf.namelist()
        truncated = len(names) > MAX_ENTRIES
        names = names[:MAX_ENTRIES]
        lower = [n.lower() for n in names]
        if "[content_types].xml" not in lower:
            return _result("skipped", error="ZIP archive, not an Office package")

        findings = []
        kind = ("word" if any(n.startswith("word/") for n in lower) else
                "excel" if any(n.startswith("xl/") for n in lower) else
                "powerpoint" if any(n.startswith("ppt/") for n in lower) else "other")

        vba = [n for n, l in zip(names, lower) if l.endswith("vbaproject.bin")]
        if vba:
            findings.append(_finding("OFFICE_VBA_MACROS", "medium",
                                     "Document contains VBA macros", files=vba))
        if any(l.startswith("xl/macrosheets/") for l in lower):
            findings.append(_finding("OFFICE_XLM_MACRO", "high",
                                     "Excel 4.0 (XLM) macro sheet present (rare in legitimate files)"))
        activex = [n for n, l in zip(names, lower) if "/activex/" in l]
        if activex:
            findings.append(_finding("OFFICE_ACTIVEX", "medium", "Document contains ActiveX controls",
                                     files=activex[:10]))

        embedded = [n for n, l in zip(names, lower) if "/embeddings/" in l and not l.endswith("/")]
        if embedded:
            exec_emb = [n for n in embedded if n.lower().endswith(EXEC_EXTS)]
            ole_emb = [n for n in embedded if n.lower().endswith((".bin", ".ole"))]
            if exec_emb:
                findings.append(_finding("OFFICE_EMBEDDED_EXECUTABLE", "high",
                                         "Executable or script embedded in the document", files=exec_emb))
            elif ole_emb:
                findings.append(_finding("OFFICE_EMBEDDED_OBJECTS", "medium",
                                         "Embedded OLE objects", files=ole_emb[:10]))
            else:
                findings.append(_finding("OFFICE_EMBEDDED_FILES", "low",
                                         "Embedded files (often charts or workbooks)", files=embedded[:10]))

        external, hyperlinks = [], []
        for n, l in zip(names, lower):
            if not l.endswith(".rels"):
                continue
            for tag in _REL_TAG.findall(_xml_meta(zf, n)):
                attrs = {k.decode().lower(): v.decode("utf-8", "replace") for k, v in _ATTR.findall(tag)}
                if attrs.get("targetmode", "").lower() != "external":
                    continue
                rtype = attrs.get("type", "").rsplit("/", 1)[-1]
                target = attrs.get("target", "")
                if rtype == "hyperlink":
                    if target not in hyperlinks and len(hyperlinks) < MAX_LIST:
                        hyperlinks.append(target)
                    continue
                if len(external) < MAX_LIST:
                    external.append({"part": n, "type": rtype, "target": target})

        remote_tpl = [e for e in external if e["type"] == "attachedTemplate"]
        ole_ext = [e for e in external if e["type"] in ("oleObject", "package", "frame")]
        unc = [e for e in external if e["target"].lower().startswith(("\\\\", "file:", "//"))]
        other = [e for e in external if e not in remote_tpl and e not in ole_ext and e not in unc]
        if remote_tpl:
            findings.append(_finding("OFFICE_REMOTE_TEMPLATE", "high",
                                     "Document loads a remote template (template injection)",
                                     items=remote_tpl))
        if ole_ext:
            findings.append(_finding("OFFICE_EXTERNAL_OBJECT", "high",
                                     "Document loads an external OLE object or frame (e.g. Follina-style)",
                                     items=ole_ext))
        if unc:
            findings.append(_finding("OFFICE_UNC_PATH", "medium",
                                     "Document references a network share or local file path (can leak credentials)",
                                     items=unc))
        if other:
            findings.append(_finding("OFFICE_EXTERNAL_RESOURCE", "low",
                                     "Document loads external resources (remote images or content)",
                                     items=other))

        doc = _xml_meta(zf, "word/document.xml") if kind == "word" else b""
        m = _DDE.search(doc)
        if m:
            findings.append(_finding(
                "OFFICE_DDE", "high" if m.group(1) == b"DDEAUTO" else "medium",
                f"Document contains a {m.group(1).decode()} field (can run commands)"))

        meta = {}
        core = _xml_meta(zf, "docProps/core.xml") + _xml_meta(zf, "docProps/app.xml")
        for key, tag in (("creator", "dc:creator"), ("last_modified_by", "cp:lastModifiedBy"),
                         ("created", "dcterms:created"), ("modified", "dcterms:modified"),
                         ("application", "Application")):
            mm = re.search(rb"<" + tag.encode() + rb"[^>]*>([^<]{1,200})</", core)
            if mm:
                meta[key] = mm.group(1).decode("utf-8", "replace")

    deep = _oletools_macros(path) if vba else None
    _macro_findings(deep, findings)

    data = {"container": "ooxml", "app_kind": kind, "entry_count": len(names),
            "entries_truncated": truncated, "has_macros": bool(vba),
            "external_relationships": external, "hyperlinks": hyperlinks,
            "embedded_files": embedded[:MAX_LIST], "metadata": meta,
            "macro_analysis": deep if deep is not None else "oletools not installed" if vba else None}
    return _result("ok", data=data, findings=findings)


def _analyze_ole(raw, path):
    findings = []
    kind = ("word" if _u16("WordDocument") in raw else
            "excel" if _u16("Workbook") in raw or _u16("Book") in raw else
            "powerpoint" if _u16("PowerPoint Document") in raw else "other")
    has_macros = _u16("_VBA_PROJECT") in raw
    if has_macros:
        findings.append(_finding("OFFICE_VBA_MACROS", "medium", "Document contains VBA macros"))
    if _u16("Ole10Native") in raw:
        findings.append(_finding("OFFICE_OLE_PACKAGE", "medium",
                                 "Embedded file or object package (Ole10Native stream)"))
    if b"Equation.3" in raw or b"Microsoft Equation 3.0" in raw:
        findings.append(_finding("OFFICE_EQUATION_EDITOR", "medium",
                                 "Uses the legacy Equation Editor (target of CVE-2017-11882)"))
    deep = _oletools_macros(path) if has_macros else None
    _macro_findings(deep, findings)
    data = {"container": "ole2", "app_kind": kind, "has_macros": has_macros,
            "macro_analysis": deep if deep is not None else "oletools not installed" if has_macros else None}
    return _result("ok", data=data, findings=findings)


def _analyze_rtf(raw):
    findings = []
    classes = sorted({m.group(1).decode("latin-1")
                      for m in re.finditer(rb"(?i)\\objclass\s+([A-Za-z0-9_.\-]+)", raw)})[:20]
    if b"\\objdata" in raw:
        findings.append(_finding("OFFICE_RTF_OBJECT", "medium",
                                 "RTF contains an embedded OLE object", classes=classes))
    if any("equation" in c.lower() for c in classes):
        findings.append(_finding("OFFICE_EQUATION_EDITOR", "medium",
                                 "Uses the legacy Equation Editor (target of CVE-2017-11882)"))
    if b"\\objupdate" in raw:
        findings.append(_finding("OFFICE_RTF_OBJUPDATE", "low", "RTF forces object updates on open"))
    tpl = [m.group(1).decode("latin-1") for m in
           re.finditer(rb"\\\*\\template\s+(https?:[^\s}]+|\\\\[^\s}]+)", raw)]
    if tpl:
        findings.append(_finding("OFFICE_REMOTE_TEMPLATE", "high",
                                 "RTF loads a remote template", items=tpl[:10]))
    return _result("ok", data={"container": "rtf", "object_classes": classes}, findings=findings)


def analyze_office(path) -> dict:
    path = Path(path)
    if not path.is_file():
        return _result("error", error="File not found")
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_READ)
    except OSError as e:
        return _result("error", error=f"Cannot read file: {e}")
    try:
        if raw.startswith(b"PK"):
            return _analyze_ooxml(path)
        if raw.startswith(OLE_MAGIC):
            return _analyze_ole(raw, path)
        if raw.lstrip()[:5] == b"{\\rtf":
            return _analyze_rtf(raw)
        return _result("skipped", error="Not an Office document")
    except Exception as e:
        return _result("error", error=f"Unexpected parse failure: {type(e).__name__}: {e}")