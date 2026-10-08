import os
import tempfile
import unittest

from app.static_analysis import scanner
from tests.pe.pe_builder import build_minimal_pe


def make_env(name, findings=(), status="ok", error=None):
    return lambda path: {"analyzer": name, "status": status, "error": error,
                         "data": {}, "findings": list(findings)}


class ScannerTests(unittest.TestCase):

    def make_file(self, content):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def register(self, name, func):
        scanner.register_analyzer(name, func)
        self.addCleanup(scanner.unregister_analyzer, name)

    def test_missing_file(self):
        r = scanner.scan_file("nope.exe")
        self.assertEqual(r["errors"], ["File not found"])
        self.assertEqual(r["summary"]["risk_level"], "none")

    def test_pe_report_shape(self):
        r = scanner.scan_file(self.make_file(build_minimal_pe()))
        self.assertEqual(r["analyzers"]["pe"]["status"], "ok")
        self.assertEqual(set(r["hashes"]) & {"md5", "sha1", "sha256"},
                         {"md5", "sha1", "sha256"})
        self.assertNotIn("size", r["hashes"])

    def test_non_pe_is_skipped_not_failed(self):
        r = scanner.scan_file(self.make_file(b"hello"))
        self.assertEqual(r["summary"]["analyzers_skipped"], ["pe"])
        self.assertEqual(r["summary"]["analyzers_failed"], [])

    def test_raising_analyzer_is_contained(self):
        def boom(path):
            raise RuntimeError("bad")
        self.register("boom", boom)
        r = scanner.scan_file(self.make_file(b"x"), analyzers=["boom"])
        self.assertEqual(r["analyzers"]["boom"]["status"], "error")
        self.assertEqual(r["summary"]["analyzers_failed"], ["boom"])

    def test_non_dict_result_is_error(self):
        self.register("weird", lambda path: "nope")
        r = scanner.scan_file(self.make_file(b"x"), analyzers=["weird"])
        self.assertEqual(r["analyzers"]["weird"]["status"], "error")

    def test_unknown_analyzer_reported(self):
        r = scanner.scan_file(self.make_file(b"x"), analyzers=["ghost"])
        self.assertIn("Unknown analyzer: ghost", r["errors"])

    def test_findings_merged_sorted_and_scored(self):
        low = {"id": "A", "analyzer": "t", "severity": "low", "message": "", "detail": {}}
        med = {"id": "B", "analyzer": "t", "severity": "medium", "message": "", "detail": {}}
        self.register("t", make_env("t", [low, med]))
        r = scanner.scan_file(self.make_file(b"x"), analyzers=["t"])
        self.assertEqual([f["id"] for f in r["findings"]], ["B", "A"])
        self.assertEqual(r["summary"]["risk_level"], "medium")
        self.assertEqual(r["summary"]["score"], 20)   # 15 + 5

    # ---- the extra test from the excerpt ----

    def test_bad_findings_are_normalized(self):
        self.register("messy", lambda p: {"status": "ok",
                      "findings": ["junk", {"severity": "weird"}]})
        r = scanner.scan_file(self.make_file(b"x"), analyzers=["messy"])
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["findings"][0]["severity"], "info")
        self.assertEqual(r["findings"][0]["analyzer"], "messy")


if __name__ == "__main__":
    unittest.main()