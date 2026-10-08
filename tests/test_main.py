import contextlib
import io
import json
import os
import tempfile
import unittest

from main import main
from tests.pe.pe_builder import build_minimal_pe


class MainTests(unittest.TestCase):

    def make_file(self, content):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["main.py", *args])
        return code, out.getvalue(), err.getvalue()

    def test_missing_file_returns_1(self):
        code, _, err = self.run_main("nope.exe")
        self.assertEqual(code, 1)
        self.assertIn("File not found", err)

    def test_directory_path_returns_1(self):
        code, _, err = self.run_main(tempfile.gettempdir())
        self.assertEqual(code, 1)
        self.assertIn("File not found", err)

    def test_valid_pe_returns_0(self):
        code, _, _ = self.run_main(self.make_file(build_minimal_pe()))
        self.assertEqual(code, 0)

    def test_malformed_pe_returns_2(self):
        code, _, _ = self.run_main(self.make_file(b"MZ" + b"\x00" * 10))
        self.assertEqual(code, 2)

    def test_json_output_parses(self):
        code, out, _ = self.run_main(self.make_file(build_minimal_pe()), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()