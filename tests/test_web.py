import io
import unittest

from app.web import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def post(self, url, data=b"hello", name="a.txt"):
        return self.client.post(url, data={"file": (io.BytesIO(data), name)},
                                content_type="multipart/form-data")

    def test_index_loads(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_api_scan_returns_report_without_temp_path(self):
        r = self.post("/api/scan")
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertNotIn("path", j["file"])
        self.assertEqual(j["file"]["name"], "a.txt")

    def test_scan_page_renders(self):
        r = self.post("/scan")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"a.txt", r.data)

    def test_missing_file_is_400(self):
        self.assertEqual(self.client.post("/scan").status_code, 400)
        self.assertEqual(self.client.post("/api/scan").status_code, 400)


if __name__ == "__main__":
    unittest.main()