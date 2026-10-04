import os
import tempfile
import unittest

from app.static_analysis.hasher import get_hashes


class HasherTests(unittest.TestCase):

    def make_file(self, content):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def test_abc(self):
        result = get_hashes(self.make_file(b"abc"))
        self.assertEqual(result["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(result["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(
            result["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(result["size"], 3)

    def test_empty_file(self):
        result = get_hashes(self.make_file(b""))
        self.assertEqual(
            result["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(result["size"], 0)

    def test_one_letter_changes_everything(self):
        a = get_hashes(self.make_file(b"abc"))["sha256"]
        b = get_hashes(self.make_file(b"abd"))["sha256"]
        self.assertNotEqual(a, b)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            get_hashes("this_file_does_not_exist.txt")


if __name__ == "__main__":
    unittest.main()

# Run in powershell using this command: 
# python -m unittest tests.test_hasher -v 




# import hashlib

# text = "abc"
# data = text.encode()          # hashlib works on bytes, not text

# print("MD5    :", hashlib.md5(data).hexdigest())
# print("SHA-1  :", hashlib.sha1(data).hexdigest())
# print("SHA-256:", hashlib.sha256(data).hexdigest())
