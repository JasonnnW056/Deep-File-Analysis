# filetype_analyzer.py - identify what a file really is from its bytes, not its name.
import struct
import zipfile
from pathlib import Path

ANALYZER_NAME = "filetype"
NEUTRAL_EXTS = {"", ".bin", ".dat", ".tmp", ".out", ".upload"}
STRICT_PE_EXTS = {".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl"}
EXEC_EXTS = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
             ".vbe", ".wsf", ".hta", ".lnk", ".ps1", ".jar", ".cpl", ".msi"}
DECOY_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
              ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".zip", ".rar", ".7z", ".mp3", ".mp4",
              ".avi", ".mov", ".csv", ".html", ".htm", ".xml", ".json", ".log"}
BIDI_CHARS = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
EXECUTABLE_TYPES = {"pe", "dos", "elf", "macho", "macho_fat", "java_class"}

# type id -> (description, extensions that are normal for it; empty set = don't check)
TYPES = {
    "pe": ("Windows executable (PE)", {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi",
                                       ".drv", ".mui", ".ax", ".com", ".tsp", ".mun", ".winmd",
                                       ".pyd", ".node", ".ime", ".acm", ".msstyles"}),
    "dos": ("DOS / legacy MZ executable", {".exe", ".com", ".sys", ".dll", ".scr", ".ovl", ".drv"}),
    "elf": ("ELF executable / library (Linux)", {".elf", ".so", ".o", ".ko", ".axf", ".prx"}),
    "macho": ("Mach-O executable (macOS)", {".dylib", ".bundle", ".o", ".macho", ".kext"}),
    "macho_fat": ("Mach-O universal binary (macOS)", {".dylib", ".bundle", ".o", ".macho"}),
    "java_class": ("Java class file", {".class"}),
    "pdf": ("PDF document", {".pdf"}),
    "ole": ("Microsoft OLE2 container (legacy Office, MSI)",
            {".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot", ".pps", ".ppa", ".msi",
             ".msg", ".vsd", ".pub", ".mpp", ".msp", ".mst"}),
    "docx": ("Word document (OOXML)", {".docx", ".docm", ".dotx", ".dotm"}),
    "xlsx": ("Excel workbook (OOXML)", {".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb", ".xlam"}),
    "pptx": ("PowerPoint presentation (OOXML)",
             {".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".ppam"}),
    "ooxml": ("Office Open XML package", {".vsdx", ".vsdm", ".vssx", ".xps", ".oxps", ".thmx"}),
    "odf": ("OpenDocument file", {".odt", ".ods", ".odp", ".odg", ".odf", ".ott", ".ots", ".otp"}),
    "jar": ("Java archive", {".jar", ".war", ".ear"}),
    "apk": ("Android package", {".apk", ".aab"}),
    "zip": ("ZIP archive", {".zip", ".zipx", ".nupkg", ".whl", ".xpi", ".vsix", ".egg",
                            ".epub", ".appx", ".msix", ".crx"}),
    "gzip": ("gzip archive", {".gz", ".tgz", ".svgz"}),
    "bzip2": ("bzip2 archive", {".bz2", ".tbz2"}),
    "xz": ("xz archive", {".xz", ".txz"}),
    "7z": ("7-Zip archive", {".7z"}),
    "rar": ("RAR archive", {".rar"}),
    "cab": ("Cabinet archive", {".cab", ".msu"}),
    "rtf": ("Rich Text Format", {".rtf", ".doc"}),
    "png": ("PNG image", {".png"}),
    "jpeg": ("JPEG image", {".jpg", ".jpeg", ".jpe", ".jfif"}),
    "gif": ("GIF image", {".gif"}),
    "lnk": ("Windows shortcut (.lnk)", {".lnk"}),
    "sqlite": ("SQLite database", {".db", ".sqlite", ".sqlite3", ".db3"}),
    "script": ("Script (shebang line)", set()),
    "text": ("Text file", set()),
    "empty": ("Empty file", set()),
    "unknown": ("Unknown binary data", set()),
}

_SIMPLE_MAGIC = [
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho"), (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"{\\rtf", "rtf"),
    (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
    (b"MSCF", "cab"),
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"#!", "script"),
]


def _result(status, error=None, data=None, findings=None):
    return {"analyzer": ANALYZER_NAME, "status": status, "error": error,
            "data": data or {}, "findings": findings or []}


def _finding(fid, severity, message, **detail):
    return {"id": fid, "analyzer": ANALYZER_NAME, "severity": severity,
            "message": message, "detail": detail}


def _looks_text(buf: bytes) -> bool:
    if not buf:
        return True
    if buf.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in buf:
        return False
    try:
        s = buf.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = buf[:-3].decode("utf-8")  # sample may end mid-character
        except UnicodeDecodeError:
            return False
    ctrl = sum(1 for ch in s if ord(ch) < 32 and ch not in "\t\n\r\f")
    return ctrl / max(len(s), 1) < 0.02


def _is_pe(f, head: bytes, size: int) -> bool:
    if len(head) < 0x40 or not head.startswith(b"MZ"):
        return False
    off = struct.unpack_from("<I", head, 0x3C)[0]
    if off + 4 > size:
        return False
    f.seek(off)
    return f.read(4) == b"PE\x00\x00"


def _classify_zip(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()[:5000]
    except Exception:
        return "zip"
    s = set(names)
    if "[Content_Types].xml" in s:
        if any(n.startswith("word/") for n in names):
            return "docx"
        if any(n.startswith("xl/") for n in names):
            return "xlsx"
        if any(n.startswith("ppt/") for n in names):
            return "pptx"
        return "ooxml"
    if "mimetype" in s and "META-INF/manifest.xml" in s:
        return "odf"
    if "AndroidManifest.xml" in s:
        return "apk"
    if "META-INF/MANIFEST.MF" in s:
        return "jar"
    return "zip"


def detect_type(path) -> str:
    """Return a type id from TYPES, based on file content."""
    path = Path(path)
    size = path.stat().st_size
    if size == 0:
        return "empty"
    with open(path, "rb") as f:
        head = f.read(4096)
        if _is_pe(f, head, size):
            return "pe"
    if head.startswith(b"MZ") and len(head) >= 64 and not _looks_text(head[:512]):
        return "dos"
    if head.startswith(b"\xca\xfe\xba\xbe"):
        # Java class files and Mach-O universal binaries share this magic
        n = struct.unpack_from(">I", head, 4)[0] if len(head) >= 8 else 0
        return "macho_fat" if n < 45 else "java_class"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return _classify_zip(path)
    for magic, tid in _SIMPLE_MAGIC:
        if head.startswith(magic):
            return tid
    return "text" if _looks_text(head) else "unknown"


def analyze_filetype(path) -> dict:
    path = Path(path)
    if not path.is_file():
        return _result("error", error="File not found")
    try:
        tid = detect_type(path)
    except OSError as e:
        return _result("error", error=f"Cannot read file: {e}")

    description, expected = TYPES[tid]
    ext = path.suffix.lower()
    suffixes = [s.lower() for s in path.suffixes]
    findings = []

    if ext in STRICT_PE_EXTS and tid not in ("pe", "dos", "empty"):
        findings.append(_finding(
            "FT_EXT_MISMATCH", "medium",
            f"Extension {ext!r} says Windows executable, but the content is: {description}",
            extension=ext, detected=tid))
    elif expected and ext not in NEUTRAL_EXTS and ext not in expected \
            and not (tid == "elf" and ".so" in suffixes):  # libfoo.so.4 is a normal library name
        if tid in EXECUTABLE_TYPES and ext in DECOY_EXTS:
            findings.append(_finding(
                "FT_DISGUISED_EXECUTABLE", "high",
                f"Content is {description} but the extension is {ext!r}",
                extension=ext, detected=tid))
        elif tid in EXECUTABLE_TYPES:
            findings.append(_finding(
                "FT_UNUSUAL_EXTENSION", "low",
                f"Content is {description} but the extension is the unusual {ext!r}",
                extension=ext, detected=tid))
        else:
            findings.append(_finding(
                "FT_EXT_MISMATCH", "low",
                f"Content is {description} but the extension is {ext!r}",
                extension=ext, detected=tid))

    if len(suffixes) >= 2 and suffixes[-1] in EXEC_EXTS and suffixes[-2] in DECOY_EXTS:
        findings.append(_finding(
            "FT_DOUBLE_EXTENSION", "high" if tid in EXECUTABLE_TYPES else "medium",
            f"Double extension {''.join(suffixes[-2:])!r}: executable disguised as a document or image",
            extensions=suffixes[-2:]))
    if any(ch in BIDI_CHARS for ch in path.name):
        findings.append(_finding(
            "FT_BIDI_SPOOFING", "high",
            "File name contains a right-to-left override character (can reverse the displayed extension)"))

    data = {
        "detected_type": tid,
        "description": description,
        "extension": ext or None,
        "extension_matches": (ext in expected) if (expected and ext) else None,
        "is_executable_format": tid in EXECUTABLE_TYPES,
    }
    return _result("ok", data=data, findings=findings)