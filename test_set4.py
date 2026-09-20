import random
import unittest

from set3.challenge18 import process_aes_128_ctr
from set4.challenge25 import break_editable_aes_128_ctr, edit_aes_128_ctr
from set4.challenge26 import do_bitflipping_attack
from utils import read_base64_file


class TestChallenge25(unittest.TestCase):
    def test_break_editable_ctr(self):
        nonce = random.randint(0, 2**8 - 1)
        key = random.randbytes(16)
        plaintext = read_base64_file("data/25.txt")
        ciphertext = process_aes_128_ctr(nonce, key, plaintext)
        edit = lambda offset, newtext, ciphertext: edit_aes_128_ctr(
            nonce, key, ciphertext, offset, newtext
        )
        recovered_plaintext = break_editable_aes_128_ctr(edit, ciphertext)
        self.assertEqual(recovered_plaintext, plaintext)

    def test_edit_ctr(self):
        nonce = random.randint(0, 2**8 - 1)
        key = random.randbytes(16)
        plaintext = b"AAAA"
        ciphertext = process_aes_128_ctr(nonce, key, plaintext)
        edited_ciphertext = edit_aes_128_ctr(nonce, key, ciphertext, 2, b"Z")
        recovered_plaintext = process_aes_128_ctr(nonce, key, edited_ciphertext)
        self.assertEqual(recovered_plaintext, b"AAZAA")

    def test_edit_ctr_append(self):
        nonce = random.randint(0, 2**8 - 1)
        key = random.randbytes(16)
        plaintext = b"AAAA"
        ciphertext = process_aes_128_ctr(nonce, key, plaintext)
        edited_ciphertext = edit_aes_128_ctr(nonce, key, ciphertext, 4, b"Z")
        recovered_plaintext = process_aes_128_ctr(nonce, key, edited_ciphertext)
        self.assertEqual(recovered_plaintext, b"AAAAZ")

    def test_edit_ctr_prepend(self):
        nonce = random.randint(0, 2**8 - 1)
        key = random.randbytes(16)
        plaintext = b"AAAA"
        ciphertext = process_aes_128_ctr(nonce, key, plaintext)
        edited_ciphertext = edit_aes_128_ctr(nonce, key, ciphertext, 0, b"Z")
        recovered_plaintext = process_aes_128_ctr(nonce, key, edited_ciphertext)
        self.assertEqual(recovered_plaintext, b"ZAAAA")


class TestChallenge26(unittest.TestCase):
    def test_bitflipping_attack(self):
        nonce, key = random.randint(0, 255), random.randbytes(16)
        ciphertext = do_bitflipping_attack(nonce, key)
        plaintext = process_aes_128_ctr(nonce, key, ciphertext)[35:46].decode()
        self.assertEqual(plaintext, ";admin=true")


if __name__ == "__main__":
    unittest.main()
