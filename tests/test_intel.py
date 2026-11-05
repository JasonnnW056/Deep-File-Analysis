import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

from app.intel import virustotal


def vt_body(mal, sus=0, undetected=50, harmless=5):
    return io.BytesIO(json.dumps({"data": {"attributes": {
        "last_analysis_stats": {"malicious": mal, "suspicious": sus,
                                "undetected": undetected, "harmless": harmless},
        "popular_threat_classification": {"suggested_threat_label": "trojan.test"},
        "last_analysis_date": 1700000000}}}).encode())


class VirusTotalTests(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ["VT_API_KEY"] = "test-key"
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(b"hello")
        f.close()
        self.addCleanup(os.remove, f.name)
        self.path = f.name

    def run_with(self, **kw):
        with mock.patch("app.intel.virustotal.urllib.request.urlopen", **kw) as m:
            return virustotal.analyze_virustotal(self.path), m

    def test_no_key_is_skipped_and_makes_no_request(self):
        os.environ.pop("VT_API_KEY")
        r, m = self.run_with()
        self.assertEqual(r["status"], "skipped")
        m.assert_not_called()

    def test_many_detections_is_high(self):
        r, _ = self.run_with(return_value=vt_body(12, 1))
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["findings"][0]["severity"], "high")
        self.assertEqual(r["data"]["malicious"], 12)
        self.assertEqual(r["data"]["total"], 68)

    def test_zero_detections_is_info(self):
        r, _ = self.run_with(return_value=vt_body(0))
        self.assertEqual(r["findings"][0]["severity"], "info")

    def test_unknown_hash_is_info_not_error(self):
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        r, _ = self.run_with(side_effect=err)
        self.assertEqual(r["status"], "ok")
        self.assertFalse(r["data"]["found"])
        self.assertEqual(r["findings"][0]["id"], "VT_NOT_FOUND")

    def test_rate_limit_and_network_errors_are_errors(self):
        r, _ = self.run_with(side_effect=urllib.error.HTTPError("u", 429, "x", {}, None))
        self.assertEqual(r["status"], "error")
        self.assertIn("rate limit", r["error"])
        r, _ = self.run_with(side_effect=urllib.error.URLError("down"))
        self.assertEqual(r["status"], "error")