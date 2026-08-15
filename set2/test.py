import unittest

from challenge9 import add_pkcs7_padding


class TestChallenge9(unittest.TestCase):
    def test_zero_padding(self):
        self.assertEqual(add_pkcs7_padding(b"YELLOW SUBMARINE", 2), b"YELLOW SUBMARINE")

    def test_zero_padding_bis(self):
        self.assertEqual(
            add_pkcs7_padding(b"YELLOW SUBMARINE", 16), b"YELLOW SUBMARINE"
        )

    def test_nonzero_padding(self):
        self.assertEqual(
            add_pkcs7_padding(b"YELLOW SUBMARINE", 9),
            b"YELLOW SUBMARINE\x02\x02",
        )

    def test_nonzero_padding_bis(self):
        self.assertEqual(
            add_pkcs7_padding(b"YELLOW SUBMARINE", 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04",
        )


if __name__ == "__main__":
    unittest.main()
