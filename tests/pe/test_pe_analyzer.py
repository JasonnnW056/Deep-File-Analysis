import os
import tempfile
import unittest

from app.static_analysis.pe_analyzer import analyze_pe
from tests.pe.pe_builder import build_minimal_pe


class PeAnalyzerTests(unittest.TestCase):

    def make_file(self, content):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def ids(self, result):
        return {f["id"] for f in result["findings"]}

    # ---- envelope / bad input ----

    def test_missing_file_is_error(self):
        result = analyze_pe("this_file_does_not_exist.exe")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "File not found")

    def test_non_pe_file_is_skipped_not_error(self):
        result = analyze_pe(self.make_file(b"just some text"))
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["findings"], [])

    def test_empty_file_is_skipped(self):
        self.assertEqual(analyze_pe(self.make_file(b""))["status"], "skipped")

    def test_garbage_with_mz_does_not_crash(self):
        result = analyze_pe(self.make_file(b"MZ" + b"\x00" * 10))
        self.assertEqual(result["status"], "error")
        self.assertIsNotNone(result["error"])

    def test_envelope_keys(self):
        result = analyze_pe(self.make_file(build_minimal_pe()))
        self.assertEqual(set(result), {"analyzer", "status", "error", "data", "findings"})
        self.assertEqual(result["analyzer"], "pe")

    # ---- parsing a valid PE ----

    def test_valid_pe_parses(self):
        result = analyze_pe(self.make_file(build_minimal_pe()))
        self.assertEqual(result["status"], "ok")
        data = result["data"]
        self.assertEqual(data["bitness"], "32-bit")
        self.assertEqual(data["file_type"], "exe")
        self.assertEqual(data["sections"][0]["name"], ".text")
        self.assertEqual(data["entry_point"], hex(0x1000))

    def test_every_finding_has_the_standard_shape(self):
        result = analyze_pe(self.make_file(build_minimal_pe()))
        for f in result["findings"]:
            self.assertEqual(set(f), {"id", "analyzer", "severity", "message", "detail"})
            self.assertIn(f["severity"], ("info", "low", "medium", "high"))

    # ---- indicators ----

    def test_no_imports_flagged(self):
        result = analyze_pe(self.make_file(build_minimal_pe()))
        self.assertIn("PE_NO_IMPORTS", self.ids(result))

    def test_high_entropy_section_flagged(self):
        pe = build_minimal_pe(section_data=os.urandom(4096))
        self.assertIn("PE_HIGH_ENTROPY", self.ids(analyze_pe(self.make_file(pe))))

    def test_low_entropy_section_not_flagged(self):
        result = analyze_pe(self.make_file(build_minimal_pe()))
        self.assertNotIn("PE_HIGH_ENTROPY", self.ids(result))

    def test_writable_executable_section_flagged(self):
        pe = build_minimal_pe(characteristics=0xE0000020)
        self.assertIn("PE_WX_SECTION", self.ids(analyze_pe(self.make_file(pe))))

    def test_odd_section_name_flagged(self):
        pe = build_minimal_pe(section_name=b".upx0")
        self.assertIn("PE_ODD_SECTION_NAME", self.ids(analyze_pe(self.make_file(pe))))

    def test_overlay_detected(self):
        pe = build_minimal_pe(overlay=b"EXTRA")
        result = analyze_pe(self.make_file(pe))
        self.assertEqual(result["data"]["overlay_size"], 5)
        self.assertIn("PE_OVERLAY", self.ids(result))

    def test_zero_timestamp_flagged(self):
        pe = build_minimal_pe(timestamp=0)
        self.assertIn("PE_BAD_TIMESTAMP", self.ids(analyze_pe(self.make_file(pe))))


if __name__ == "__main__":
    unittest.main()

# Run this command:
# python -m unittest tests.test_scanner -v                                                                                   
# python -m unittest discover -s tests -t . -v   
# python main.py "C:\Windows\System32\notepad.exe"