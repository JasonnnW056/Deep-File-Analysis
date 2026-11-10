import struct
import tempfile
import unittest
from pathlib import Path

from app.static_analysis.filetype_analyzer import analyze_filetype


def fake_pe():
    b = bytearray(0x200)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\x00\x00"
    return bytes(b)


class FileTypeTests(unittest.TestCase):
    def check(self, name, content):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_bytes(content)
            env = analyze_filetype(p)
        return env, {f["id"]: f["severity"] for f in env["findings"]}

    def test_text_file_is_clean(self):
        env, found = self.check("notes.txt", b"hello world\n")
        self.assertEqual(env["data"]["detected_type"], "text")
        self.assertEqual(found, {})

    def test_real_exe_is_clean(self):
        env, found = self.check("setup.exe", fake_pe())
        self.assertEqual(env["data"]["detected_type"], "pe")
        self.assertEqual(found, {})

    def test_exe_disguised_as_pdf(self):
        self.assertEqual(self.check("invoice.pdf", fake_pe())[1], {"FT_DISGUISED_EXECUTABLE": "high"})

    def test_double_extension(self):
        self.assertEqual(self.check("invoice.pdf.exe", fake_pe())[1], {"FT_DOUBLE_EXTENSION": "high"})

    def test_exe_name_but_pdf_content(self):
        self.assertIn("FT_EXT_MISMATCH", self.check("report.exe", b"%PDF-1.4\n%%EOF")[1])

    def test_text_starting_with_mz_is_not_an_exe(self):
        env, _ = self.check("note.txt", b"MZ is a prefix used in this file\n" * 5)
        self.assertEqual(env["data"]["detected_type"], "text")


if __name__ == "__main__":
    unittest.main()