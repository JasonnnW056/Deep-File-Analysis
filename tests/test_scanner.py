import json
import os
import tempfile
import unittest

from app.static_analysis import scanner
from app.static_analysis.scanner import (register_analyzer, registered_analyzers,
                                         scan_file, unregister_analyzer)
from tests.pe.pe_builder import build_minimal_pe


class ScannerTests(unittest.TestCase):

    def make_file(self, content):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def test_missing_file(self):
        report = scan_file("nope.exe")
        self.assertIn("File not found", report["errors"])
        self.assertEqual(report["summary"]["risk_level"], "none")

    def test_non_pe_file_gets_hashes_and_pe_skipped(self):
        report = scan_file(self.make_file(b"abc"))
        self.assertEqual(report["hashes"]["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertNotIn("size", report["hashes"])
        self.assertEqual(report["file"]["size"], 3)
        self.assertEqual(report["analyzers"]["pe"]["status"], "skipped")
        self.assertIn("pe", report["summary"]["analyzers_skipped"])
        self.assertEqual(report["findings"], [])

    def test_pe_file_runs_pe_analyzer(self):
        report = scan_file(self.make_file(build_minimal_pe()))
        self.assertEqual(report["analyzers"]["pe"]["status"], "ok")
        self.assertGreater(report["summary"]["finding_count"], 0)

    def test_report_is_json_serialisable(self):
        report = scan_file(self.make_file(build_minimal_pe(section_data=os.urandom(2048))))
        json.dumps(report)

    def test_score_and_risk_from_pe_findings(self):
        report = scan_file(self.make_file(build_minimal_pe(characteristics=0xE0000020)))
        self.assertEqual(report["summary"]["risk_level"], "medium")
        self.assertGreaterEqual(report["summary"]["score"], 15)

    def test_findings_sorted_most_severe_first(self):
        report = scan_file(self.make_file(build_minimal_pe(characteristics=0xE0000020)))
        order = ("info", "low", "medium", "high")
        ranks = [order.index(f["severity"]) for f in report["findings"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    # ---- plugging in a future analyzer (this is how YARA will connect) ----

    def test_new_analyzer_findings_merge_and_raise_risk(self):
        def fake_yara(path):
            return {"analyzer": "yara", "status": "ok", "error": None,
                    "data": {"rules_loaded": 1},
                    "findings": [{"id": "Fake_Rule", "analyzer": "yara", "severity": "high",
                                  "message": "matched Fake_Rule", "detail": {}}]}
        register_analyzer("yara", fake_yara)
        self.addCleanup(unregister_analyzer, "yara")

        report = scan_file(self.make_file(b"abc"))
        self.assertIn("yara", registered_analyzers())
        self.assertEqual(report["summary"]["risk_level"], "high")
        self.assertEqual(report["findings"][0]["id"], "Fake_Rule")

    def test_crashing_analyzer_is_isolated(self):
        def boom(path):
            raise RuntimeError("kaboom")
        register_analyzer("boom", boom)
        self.addCleanup(unregister_analyzer, "boom")

        report = scan_file(self.make_file(build_minimal_pe()))
        self.assertEqual(report["analyzers"]["boom"]["status"], "error")
        self.assertIn("kaboom", report["analyzers"]["boom"]["error"])
        self.assertIn("boom", report["summary"]["analyzers_failed"])
        self.assertEqual(report["analyzers"]["pe"]["status"], "ok")  # others unaffected

    def test_can_select_analyzers_and_unknown_is_reported(self):
        report = scan_file(self.make_file(b"abc"), analyzers=["pe", "nonexistent"])
        self.assertIn("Unknown analyzer: nonexistent", report["errors"])
        self.assertIn("pe", report["analyzers"])


if __name__ == "__main__":
    unittest.main()

# Run this command:
# cd Deep-File-Analysis                                                                                                                         
# python -m unittest tests.pe.test_pe_analyzer -v