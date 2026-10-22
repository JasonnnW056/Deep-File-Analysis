"""generic_analyzer.py - checks that make sense for ANY file: entropy, URLs/IPs,
suspicious command strings and embedded Windows executables."""

import ipaddress
import math
import re
from pathlib import Path

ANALYZER_NAME = "generic"

MAX_READ = 32 * 1024 * 1024
ENTROPY_SAMPLE = 4 * 1024 * 1024      # first and last 4 MB are used for big files
TEXT_CAP = 8 * 1024 * 1024
MAX_LIST = 50

# Formats that are naturally high-entropy: don't flag them
_COMPRESSED_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"\xff\xd8\xff",
                     b"\x89PNG", b"BZh", b"\xfd7zXZ", b"GIF8", b"%PDF", b"ID3", b"OggS",
                     b"fLaC", b"RIFF", b"MZ", b"\x7fELF")

_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_URL = re.compile(rb"(?i)\b(?:https?|ftp)://[^\s\"'<>\\^`{}|\x00-\x1f\x7f-\xff]{4,200}")
_IPV4 = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# (id, severity, description, regex, noisy_in_executables)
# "Noisy" ones are skipped for PE/ELF files, where system strings make them meaningless.
_INDICATORS = [
    ("PS_ENCODED_COMMAND", "medium", "PowerShell encoded command",
     rb"(?i)powershell(?:\.exe)?[^\r\n]{0,80}\s-(?:e|ec|enc|encodedcommand)\b", False),
    ("PS_DOWNLOAD_EXEC", "medium", "PowerShell download-and-execute pattern",
     rb"(?i)(?:iex|invoke-expression)[^\r\n]{0,80}(?:downloadstring|net\.webclient|invoke-webrequest)", False),
    ("PS_DOWNLOAD", "low", "PowerShell download functions",
     rb"(?i)downloadstring|downloadfile|start-bitstransfer", True),
    ("PS_HIDDEN_BYPASS", "low", "PowerShell hidden window or policy bypass",
     rb"(?i)-(?:w|windowstyle)\s+hidden|-(?:ep|executionpolicy)\s+bypass", True),
    ("CERTUTIL_DOWNLOAD", "medium", "certutil used to download files",
     rb"(?i)certutil(?:\.exe)?[^\r\n]{0,60}-urlcache", False),
    ("MSHTA_REMOTE", "medium", "mshta running remote or script content",
     rb"(?i)mshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)", False),
    ("REGSVR32_SCRIPTLET", "medium", "regsvr32 loading a remote scriptlet",
     rb"(?i)regsvr32[^\r\n]{0,40}/i:(?:https?:|\\\\)", False),
    ("SHADOW_COPY_DELETE", "medium", "Shadow copy / recovery deletion (ransomware behaviour)",
     rb"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\r\n]{0,40}recoveryenabled\s+no", False),
    ("WMIC_PROCESS_CREATE", "medium", "WMIC process creation",
     rb"(?i)wmic[^\r\n]{0,60}process\s+call\s+create", False),
    ("NET_USER_ADD", "medium", "Adds a user or group member via net.exe",
     rb"(?i)\bnet1?\s+(?:user|localgroup)[^\r\n]{0,60}/add", False),
    ("DISABLE_DEFENDER", "medium", "Disables or excludes paths from Windows Defender",
     rb"(?i)set-mppreference\s+-disablerealtimemonitoring|disableantispyware|add-mppreference\s+-exclusionpath", False),
    ("BITSADMIN_TRANSFER", "low", "bitsadmin file transfer",
     rb"(?i)bitsadmin[^\r\n]{0,40}/transfer", True),
    ("SCHTASKS_CREATE", "low", "Creates a scheduled task",
     rb"(?i)schtasks(?:\.exe)?\s+/create", True),
    ("RUN_KEY_PERSISTENCE", "low", "References a Windows Run registry key",
     rb"(?i)CurrentVersion\\Run(?:Once)?\b", True),
    ("WSCRIPT_SHELL", "low", "Scripting host objects (WScript.Shell and similar)",
     rb"(?i)wscript\.shell|shell\.application|scripting\.filesystemobject", True),
    ("CMD_EXEC", "low", "cmd.exe command execution",
     rb"(?i)\bcmd(?:\.exe)?\s+/[ck]\s", True),
    ("BASE64_DECODE", "low", "Base64 decoding calls",
     rb"(?i)frombase64string|certutil[^\r\n]{0,40}-decode", True),
]
_INDICATORS = [(i, s, d, re.compile(rx), n) for i, s, d, rx, n in _INDICATORS]

_DOS_STUBS = (b"This program cannot be run in DOS mode",
              b"This program must be run under Win32")


def _result(status, error=None, data=None, findings=None):
    return {"analyzer": ANALYZER_NAME, "status": status, "error": error,
            "data": data or {}, "findings": findings or []}


def _finding(fid, severity, message, **detail):
    return {"id": fid, "analyzer": ANALYZER_NAME, "severity": severity,
            "message": message, "detail": detail}


def _entropy(buf: bytes) -> float:
    n = len(buf)
    if n == 0:
        return 0.0
    h = 0.0
    for b in range(256):
        c = buf.count(bytes((b,)))
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _text_blob(data: bytes) -> bytes:
    """ASCII and UTF-16LE strings joined by newlines (capped)."""
    parts, total = [], 0
    for rx, wide in ((_ASCII, False), (_WIDE, True)):
        for m in rx.finditer(data):
            s = m.group()
            if wide:
                s = s.replace(b"\x00", b"")
            parts.append(s)
            total += len(s) + 1
            if total > TEXT_CAP:
                return b"\n".join(parts)
    return b"\n".join(parts)


def _embedded_pe_offsets(data: bytes) -> list:
    offsets = []
    for stub in _DOS_STUBS:
        start = 0
        while len(offsets) < 20:
            i = data.find(stub, start)
            if i < 0:
                break
            mz = data.rfind(b"MZ", max(0, i - 0x100), i)
            if mz >= 0:
                offsets.append(mz)
            start = i + 1
    return sorted(set(offsets))


def analyze_generic(path) -> dict:
    path = Path(path)
    if not path.is_file():
        return _result("error", error="File not found")
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
    except OSError as e:
        return _result("error", error=f"Cannot read file: {e}")
    if not data:
        return _result("skipped", error="File is empty")

    findings = []
    is_exec = data.startswith((b"MZ", b"\x7fELF"))

    sample = data if len(data) <= 2 * ENTROPY_SAMPLE else data[:ENTROPY_SAMPLE] + data[-ENTROPY_SAMPLE:]
    entropy = round(_entropy(sample), 3)
    if entropy >= 7.5 and len(data) >= 4096 and not data.startswith(_COMPRESSED_MAGIC) \
            and data[4:8] != b"ftyp":
        findings.append(_finding(
            "GEN_HIGH_ENTROPY", "low",
            f"Whole-file entropy is very high ({entropy}): content may be encrypted or packed",
            entropy=entropy))

    blob = _text_blob(data)

    urls = []
    for m in _URL.finditer(blob):
        u = m.group().rstrip(b".,;:)").decode("latin-1")
        if u not in urls:
            urls.append(u)
        if len(urls) >= MAX_LIST:
            break
    if urls:
        findings.append(_finding("GEN_URLS", "info", f"{len(urls)} URL(s) found in the file", urls=urls))

    ips = []
    for m in _IPV4.finditer(blob):
        ip = m.group().decode()
        try:
            if ipaddress.ip_address(ip).is_global and ip not in ips:
                ips.append(ip)
        except ValueError:
            pass
        if len(ips) >= MAX_LIST:
            break
    if ips:
        findings.append(_finding("GEN_PUBLIC_IPS", "info",
                                 f"{len(ips)} public IPv4 address(es) found", ips=ips))

    indicators = {}
    for fid, sev, desc, rx, noisy in _INDICATORS:
        if noisy and is_exec:
            continue
        matches = []
        count = 0
        for m in rx.finditer(blob):
            count += 1
            if len(matches) < 3:
                matches.append(m.group()[:120].decode("latin-1"))
        if count:
            indicators[fid] = {"count": count, "samples": matches}
            findings.append(_finding(f"GEN_{fid}", sev, f"{desc} ({count}x)",
                                     count=count, samples=matches))

    offsets = _embedded_pe_offsets(data)
    if offsets:
        if not data.startswith(b"MZ"):
            findings.append(_finding(
                "GEN_EMBEDDED_PE", "medium",
                f"Embedded Windows executable found inside a non-executable file ({len(offsets)} location(s))",
                offsets=offsets[:10]))
        elif len(offsets) > 1:
            findings.append(_finding(
                "GEN_NESTED_PE", "low",
                "Executable contains another embedded Windows executable (dropper or installer pattern)",
                offsets=offsets[:10]))

    out = {
        "size": size,
        "bytes_analyzed": len(data),
        "truncated": size > len(data),
        "entropy": entropy,
        "urls": urls,
        "public_ips": ips,
        "indicators": indicators,
        "embedded_pe_offsets": offsets[:10],
    }
    return _result("ok", data=out, findings=findings)

# D:\Users\270492384\AppData\Local\Temp\dfa_test
# C:\Windows\System32\notepad.exe