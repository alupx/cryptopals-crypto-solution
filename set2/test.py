import sys
import unittest

from challenge9 import add_pkcs7_padding
from challenge10 import decrypt_aes_128_cbs

sys.path.append("..")

from utils import read_base64_file


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


class TestChallenge10(unittest.TestCase):
    def setUp(self):
        self.key = b"YELLOW SUBMARINE"
        self.ciphertext = read_base64_file("data/10.txt")

    def test_decryptionhead(self):
        expected_head = (
            b"I'm back and I'm ringin' the bell \nA rockin' on the mike while t"
        )

        self.assertEqual(
            decrypt_aes_128_cbs(bytes(16), self.key, self.ciphertext[:64]),
            expected_head,
        )

    def test_decryption_tail(self):
        expected_tail = b"white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
        self.assertEqual(
            decrypt_aes_128_cbs(bytes(16), self.key, self.ciphertext)[-64:],
            expected_tail,
        )


if __name__ == "__main__":
    unittest.main()
