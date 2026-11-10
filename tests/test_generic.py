import os
import struct
import tempfile
import unittest
from pathlib import Path

from app.static_analysis.generic_analyzer import analyze_generic


def fake_pe():
    b = bytearray(0x200)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\x00\x00"
    b[0x4E:0x4E + 39] = b"This program cannot be run in DOS mode."
    return bytes(b)


class GenericTests(unittest.TestCase):
    def run_on(self, name, content):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_bytes(content if isinstance(content, bytes) else content.encode())
            env = analyze_generic(p)
        return env, {f["id"] for f in env["findings"]}

    def test_urls_and_public_ips(self):
        env, _ = self.run_on("a.txt", "see http://evil.example/payload.bin and 8.8.8.8 or 192.168.1.1")
        self.assertEqual(env["data"]["urls"], ["http://evil.example/payload.bin"])
        self.assertEqual(env["data"]["public_ips"], ["8.8.8.8"])  # private IP ignored

    def test_encoded_powershell(self):
        _, found = self.run_on("a.bat", "powershell.exe -nop -w hidden -enc SQBFAFgA")
        self.assertIn("GEN_PS_ENCODED_COMMAND", found)

    def test_embedded_exe_inside_non_exe(self):
        _, found = self.run_on("report.dat", b"some header\n" * 20 + fake_pe())
        self.assertIn("GEN_EMBEDDED_PE", found)

    def test_noisy_strings_ignored_inside_executables(self):
        _, found = self.run_on("a.exe", fake_pe() + b"cmd.exe /c dir")
        self.assertNotIn("GEN_CMD_EXEC", found)

    def test_clean_text_has_no_findings(self):
        _, found = self.run_on("notes.txt", "Meeting notes: buy milk and call the dentist.\n")
        self.assertEqual(found, set())

    def test_high_entropy_only_for_unknown_formats(self):
        noise = os.urandom(65536)
        self.assertIn("GEN_HIGH_ENTROPY", self.run_on("blob.xyz", noise)[1])
        self.assertNotIn("GEN_HIGH_ENTROPY", self.run_on("a.zip", b"PK\x03\x04" + noise)[1])

    def test_empty_file_is_skipped(self):
        self.assertEqual(self.run_on("e.txt", b"")[0]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()