import tempfile
import unittest
import zlib
from pathlib import Path

from app.static_analysis.pdf_analyzer import analyze_pdf

CLEAN = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF\n"


class PdfTests(unittest.TestCase):
    def run_on(self, content, name="a.pdf"):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_bytes(content)
            env = analyze_pdf(p)
        return env, {f["id"]: f["severity"] for f in env["findings"]}

    def test_not_a_pdf_is_skipped(self):
        self.assertEqual(self.run_on(b"hello", "a.txt")[0]["status"], "skipped")

    def test_clean_pdf_has_no_findings(self):
        env, found = self.run_on(CLEAN)
        self.assertEqual(env["status"], "ok")
        self.assertEqual(found, {})

    def test_javascript_with_open_action_is_high(self):
        pdf = b"%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n%%EOF"
        self.assertEqual(self.run_on(pdf)[1]["PDF_AUTO_JAVASCRIPT"], "high")

    def test_javascript_without_auto_trigger_is_low(self):
        pdf = b"%PDF-1.4\n<< /S /JavaScript /JS (this.print()) >>\n%%EOF"
        env, found = self.run_on(pdf)
        self.assertEqual(found, {"PDF_JAVASCRIPT": "low"})
        self.assertIn("this.print()", env["findings"][0]["detail"]["context"][0])

    def test_document_level_javascript_is_medium(self):
        pdf = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Names << /JavaScript 5 0 R >> >>\nendobj\n"
               b"5 0 obj\n<< /S /JavaScript /JS (x) >>\nendobj\n%%EOF")
        self.assertEqual(self.run_on(pdf)[1], {"PDF_DOCUMENT_JAVASCRIPT": "medium"})

    def test_obfuscated_keyword_is_decoded(self):
        pdf = b"%PDF-1.4\n<< /S /J#61vaScript /JS (x) >>\n%%EOF"
        found = self.run_on(pdf)[1]
        self.assertIn("PDF_OBFUSCATED_NAMES", found)
        self.assertIn("PDF_JAVASCRIPT", found)

    def test_javascript_hidden_in_object_stream(self):
        inner = zlib.compress(b"1 0 << /S /JavaScript /JS (x) >>")
        pdf = (b"%PDF-1.5\n5 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\n" + inner +
               b"\nendstream\nendobj\n%%EOF")
        env, found = self.run_on(pdf)
        self.assertIn("PDF_JAVASCRIPT", found)
        self.assertEqual(env["data"]["object_streams_inspected"], 1)

    def test_launch_action_and_exe_attachment(self):
        pdf = b"%PDF-1.4\n<< /S /Launch >> /F (evil.exe)\n%%EOF"
        found = self.run_on(pdf)[1]
        self.assertIn("PDF_LAUNCH_ACTION", found)
        self.assertIn("PDF_EMBEDDED_EXECUTABLE_NAME", found)


if __name__ == "__main__":
    unittest.main()