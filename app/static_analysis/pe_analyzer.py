#pe_analyzer.py - static PE analysis (pefile based).
"""
Every analyzer in this project (PE now, YARA later) returns the same envelope,
so the scanner can merge results without knowing who produced them:

    {
      "analyzer": "pe",
      "status":   "ok" | "skipped" | "error",
      "error":    None | "message",
      "data":     {...analyzer-specific, JSON-serialisable...},
      "findings": [{"id", "analyzer", "severity", "message", "detail"}, ...],
    }

status:
    ok       analysis ran
    skipped  not applicable (e.g. the file is not a PE). NOT a failure.
    error    something went wrong (missing file, malformed PE, ...)

severity: "info" | "low" | "medium" | "high"
Findings are triage leads, not verdicts: packed legitimate software trips several.
"""
import datetime
from pathlib import Path

import pefile

ANALYZER_NAME = "pe"

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
MAX_PE_SIZE = 256 * 1024 * 1024
MAX_LIST_ITEMS = 500


STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata",
    ".pdata", ".bss", ".tls", ".didat", ".crt", ".gfids", ".00cfg",
}

# Presence alone proves nothing: plenty of legitimate software imports these.
NOTABLE_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "ReadProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "WinExec",
    "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "AdjustTokenPrivileges", "CryptEncrypt",
}


# ---------- envelope helpers ----------

def _result(status, error=None, data=None, findings=None):
    return {
        "analyzer": ANALYZER_NAME,
        "status": status,
        "error": error,
        "data": data or {},
        "findings": findings or [],
    }


def _finding(fid, severity, message, **detail):
    return {
        "id": fid,
        "analyzer": ANALYZER_NAME,
        "severity": severity,
        "message": message,
        "detail": detail,
    }


# ---------- parsing helpers ----------

def _has_mz_header(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip("\x00")
    return str(value)


def _parse_sections(pe) -> list:
    out = []
    for s in pe.sections:
        chars = s.Characteristics
        out.append({
            "name": _decode(s.Name),
            "virtual_address": hex(s.VirtualAddress),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 3),
            "executable": bool(chars & IMAGE_SCN_MEM_EXECUTE),
            "writable": bool(chars & IMAGE_SCN_MEM_WRITE),
        })
    return out


def _parse_imports(pe) -> dict:
    imports = {}
    entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) + \
              list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))
    for entry in entries:
        dll = _decode(entry.dll).lower()
        funcs = []
        for imp in entry.imports:
            funcs.append(_decode(imp.name) if imp.name else f"ordinal_{imp.ordinal}")
        imports.setdefault(dll, []).extend(funcs)
    return imports


def _parse_exports(pe) -> list:
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not exp:
        return []
    return [_decode(s.name) if s.name else f"ordinal_{s.ordinal}" for s in exp.symbols]


def _parse_version_info(pe) -> dict:
    info = {}
    for fi in getattr(pe, "FileInfo", None) or []:
        for entry in fi:
            if getattr(entry, "Key", b"") == b"StringFileInfo":
                for table in entry.StringTable:
                    for k, v in table.entries.items():
                        info[_decode(k)] = _decode(v)
    return info


# ---------- findings ----------

def _build_findings(data: dict) -> list:
    findings = []

    for s in data["sections"]:
        name = s["name"]
        if s["entropy"] > 7.2 and s["raw_size"] >= 1024:
            findings.append(_finding(
                "PE_HIGH_ENTROPY", "medium",
                f"Section {name} has high entropy ({s['entropy']}): possibly packed or encrypted",
                section=name, entropy=s["entropy"]))
        if s["executable"] and s["writable"]:
            findings.append(_finding(
                "PE_WX_SECTION", "medium",
                f"Section {name} is both writable and executable",
                section=name))
        if name.lower() not in STANDARD_SECTIONS:
            findings.append(_finding(
                "PE_ODD_SECTION_NAME", "low",
                f"Non-standard section name: {name!r}",
                section=name))
        if s["raw_size"] == 0 and s["virtual_size"] > 0 and s["executable"]:
            findings.append(_finding(
                "PE_EMPTY_EXEC_SECTION", "medium",
                f"Section {name} is executable but has no raw data (may unpack at runtime)",
                section=name))

    all_funcs = [f for fs in data["imports"].values() for f in fs]
    total_imports = len(all_funcs)
    if data["file_type"] == "exe":
        if total_imports == 0:
            findings.append(_finding("PE_NO_IMPORTS", "low", "No imports found"))
        elif total_imports < 5:
            findings.append(_finding(
                "PE_FEW_IMPORTS", "low",
                f"Very small import table ({total_imports}): common with packers",
                count=total_imports))

    found = sorted(set(all_funcs) & NOTABLE_APIS)
    if found:
        findings.append(_finding(
            "PE_NOTABLE_APIS", "low",
            f"Notable APIs imported ({len(found)}): {', '.join(found)}",
            apis=found))

    ts = data["compile_timestamp"]
    if ts is None:
        findings.append(_finding(
            "PE_BAD_TIMESTAMP", "low", "Timestamp is zero or invalid (stripped or forged?)"))
    else:
        dt = datetime.datetime.fromisoformat(ts)
        if dt > datetime.datetime.now(datetime.timezone.utc):
            findings.append(_finding(
                "PE_BAD_TIMESTAMP", "low", "Compile timestamp is in the future", timestamp=ts))
        elif dt.year < 1995:
            findings.append(_finding(
                "PE_BAD_TIMESTAMP", "low", "Compile timestamp predates 1995", timestamp=ts))

    if data["overlay_size"] > 0:
        findings.append(_finding(
            "PE_OVERLAY", "info",
            f"Overlay data present ({data['overlay_size']} bytes)",
            size=data["overlay_size"]))
    if data["checksum_valid"] is False:
        findings.append(_finding(
            "PE_CHECKSUM_MISMATCH", "info",
            "PE checksum mismatch (normal for many unsigned files)"))
    if data["parser_warnings"]:
        findings.append(_finding(
            "PE_PARSER_WARNINGS", "low",
            f"pefile reported {len(data['parser_warnings'])} structural warning(s)",
            warnings=data["parser_warnings"]))

    return findings


# ---------- public API ----------

def analyze_pe(path, verify_checksum=False) -> dict:
    """Analyze a PE file. Always returns the standard envelope; never raises on bad input."""
    path = Path(path)

    if not path.is_file():
        return _result("error", error="File not found")
    try:
        if path.stat().st_size > MAX_PE_SIZE:
            return _result("skipped", error=f"File too large (> {MAX_PE_SIZE // 2**20} MB)")
    except OSError as e:
        return _result("error", error=f"Cannot stat file: {e}")

    if not _has_mz_header(path):
        return _result("skipped", error="Not a PE file (no MZ header)")

    pe = None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ])

        try:
            ts_raw = pe.FILE_HEADER.TimeDateStamp
            ts = (datetime.datetime.fromtimestamp(ts_raw, tz=datetime.timezone.utc).isoformat()
                  if ts_raw else None)
        except (OverflowError, OSError, ValueError):
            ts = None

        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        overlay_offset = pe.get_overlay_data_start_offset()
        file_size = path.stat().st_size

        if pe.is_dll():
            file_type = "dll"
        elif pe.is_driver():
            file_type = "sys"
        else:
            file_type = "exe"

        data = {
            "file_type": file_type,
            "machine": hex(pe.FILE_HEADER.Machine),
            "bitness": "64-bit" if pe.OPTIONAL_HEADER.Magic == 0x20B else "32-bit",
            "compile_timestamp": ts,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "imphash": pe.get_imphash() or None,
            "sections": _parse_sections(pe),
            "imports": _parse_imports(pe),
            "exports": _parse_exports(pe)[:MAX_LIST_ITEMS],
            "version_info": _parse_version_info(pe),
            "has_signature": sec_dir.Size > 0,  # presence only; NOT validated
            "overlay_size": (file_size - overlay_offset) if overlay_offset else 0,
            "checksum_valid":pe.verify_checksum() if verify_checksum else None,
            "parser_warnings": [str(w) for w in pe.get_warnings()[:10]],
        }
        findings = _build_findings(data)
        data["import_count"] = sum(len(v) for v in data["imports"].values())
        data["imports"] = {dll: funcs[:MAX_LIST_ITEMS] for dll, funcs in data["imports"].items()}
        return _result("ok", data=data, findings=findings)

    except pefile.PEFormatError as e:
        return _result("error", error=f"Malformed PE: {e}")
    except Exception as e:  # one weird file must never stop a scan
        return _result("error", error=f"Unexpected parse failure: {type(e).__name__}: {e}")
    finally:
        if pe is not None:
            pe.close()