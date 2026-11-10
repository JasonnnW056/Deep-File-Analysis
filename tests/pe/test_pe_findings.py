import unittest

from app.static_analysis import pe_analyzer as pa


def base_data(**over):
    d = {
        "sections": [],
        "imports": {"k.dll": list("abcdefghij")},
        "file_type": "exe",
        "compile_timestamp": "2020-01-01T00:00:00+00:00",
        "overlay_size": 0,
        "checksum_valid": None,
        "parser_warnings": [],
    }
    d.update(over)
    return d


class FindingRuleTests(unittest.TestCase):

    def ids(self, **over):
        return {f["id"] for f in pa._build_findings(base_data(**over))}

    def test_few_imports(self):
        self.assertIn("PE_FEW_IMPORTS", self.ids(imports={"k.dll": ["a", "b"]}))

    def test_no_imports(self):
        self.assertIn("PE_NO_IMPORTS", self.ids(imports={}))

    def test_notable_apis(self):
        self.assertIn("PE_NOTABLE_APIS",
                      self.ids(imports={"k.dll": ["VirtualAlloc"] * 6}))

    def test_checksum_mismatch(self):
        self.assertIn("PE_CHECKSUM_MISMATCH", self.ids(checksum_valid=False))

    def test_parser_warnings(self):
        self.assertIn("PE_PARSER_WARNINGS", self.ids(parser_warnings=["x"]))

    def test_future_timestamp(self):
        self.assertIn("PE_BAD_TIMESTAMP",
                      self.ids(compile_timestamp="2999-01-01T00:00:00+00:00"))

    def test_clean_data_has_no_findings(self):
        self.assertEqual(self.ids(), set())


if __name__ == "__main__":
    unittest.main()