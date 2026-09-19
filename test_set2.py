import random
import unittest

from set2.challenge9 import add_pkcs7_padding
from set2.challenge10 import decrypt_aes_128_cbc, encrypt_aes_128_cbc
from set2.challenge11 import ecb_cbc_encryption_oracle, ecb_detector
from set2.challenge12 import decrypt_unknown_string
from set2.challenge13 import (
    aes_ecb_cut_and_paste_generate_admin,
    decode_profile,
    decrypt_profile,
    provide_encrypted_profile,
)
from set2.challenge14 import decrypt_unknown_string_hard, ecb_encryption_oracle_hard
from set2.challenge15 import strip_pkc7_padding
from set2.challenge16 import do_bitflipping_attack
from utils import read_base64_file, read_binary_file


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
            decrypt_aes_128_cbc(bytes(16), self.key, self.ciphertext[:64]),
            expected_head,
        )

    def test_decryption_tail(self):
        expected_tail = b"white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
        self.assertEqual(
            decrypt_aes_128_cbc(bytes(16), self.key, self.ciphertext)[-64:],
            expected_tail,
        )

    def test_encryption_decryption_single_block(self):
        key = random.randbytes(16)
        iv = random.randbytes(16)
        plaintext = random.randbytes(16)
        ciphertext = encrypt_aes_128_cbc(iv, key, plaintext)
        decrypted_text = decrypt_aes_128_cbc(iv, key, ciphertext)
        self.assertEqual(decrypted_text, plaintext)

    def test_encryption_decryption_multi_block(self):
        key = random.randbytes(16)
        iv = random.randbytes(16)
        plaintext = random.randbytes(2048)
        ciphertext = encrypt_aes_128_cbc(iv, key, plaintext)
        decrypted_text = decrypt_aes_128_cbc(iv, key, ciphertext)
        self.assertEqual(decrypted_text, plaintext)


class TestChallenge11(unittest.TestCase):
    def setUp(self):
        files_to_encrypt = ["set1/challenge1.py", "set1/challenge2.py", "utils.py"]
        data = b""
        for filename in files_to_encrypt:
            data += read_binary_file(filename)
        self.plaintext = data

    def test_ecb_detector(self):
        for _ in range(20):
            mode, ciphertext = ecb_cbc_encryption_oracle(self.plaintext)
            self.assertEqual(ecb_detector(ciphertext), mode == 0)


class TestChallenge12(unittest.TestCase):
    def test_decryption(self):
        block_size, is_ecb, message = decrypt_unknown_string()
        self.assertEqual(block_size, 16)
        self.assertEqual(is_ecb, True)
        self.assertEqual(
            message,
            (
                b"Rollin' in my 5.0\nWith my rag-top down so my hair can "
                b"blow\nThe girlies on standby waving just to say hi\nDid"
                b" you stop? No, I just drove by\n"
            ),
        )


class TestChallenge13(unittest.TestCase):
    def test_admin_account_forging(self):
        key = random.randbytes(16)
        encrypted_profile_getter = lambda email: provide_encrypted_profile(key, email)
        forged_ciphertext = aes_ecb_cut_and_paste_generate_admin(
            encrypted_profile_getter
        )
        plaintext = decrypt_profile(key, forged_ciphertext)
        _, _, role = decode_profile(plaintext.decode())
        self.assertEqual(role, "admin")


class TestChallenge14(unittest.TestCase):
    def verify_decryption(self, key, prefix, target):
        getter = lambda x: ecb_encryption_oracle_hard(key, prefix, x, target)
        block_size, is_ecb, initial_prefix_len, msg = decrypt_unknown_string_hard(
            getter
        )
        self.assertEqual(block_size, 16)
        self.assertEqual(is_ecb, True)
        self.assertEqual(initial_prefix_len, len(prefix))
        self.assertEqual(msg, target)

    def test_no_prefix(self):
        key = random.randbytes(16)
        prefix = b""
        target = b"qwertyuiopasdfghjklzxcvbnm"
        self.verify_decryption(key, prefix, target)

    def test_identical_blocks_in_prefix(self):
        key = random.randbytes(16)
        prefix = add_pkcs7_padding(b"prefix", 16) * 5
        target = b"qwertyuiopasdfghjklzxcvbnm"
        self.verify_decryption(key, prefix, target)

    def test_not_aligned_prefix(self):
        key = random.randbytes(16)
        prefix = b"prefix" * 3
        target = b"qwertyuiopasdfghjklzxcvbnm"
        self.verify_decryption(key, prefix, target)

    def test_short_target(self):
        key = random.randbytes(16)
        prefix = b"prefix"
        target = b"target"
        self.verify_decryption(key, prefix, target)


class TestChallenge15(unittest.TestCase):
    def test_padding_too_long(self):
        padded_data = b"x" + b"\x1f" * 31
        with self.assertRaises(ValueError):
            _ = strip_pkc7_padding(padded_data, 16)

    def test_padding_wrong_value(self):
        padded_data = b"x" * 12 + b"\x04\x05\x04\x04"
        with self.assertRaises(ValueError):
            _ = strip_pkc7_padding(padded_data, 16)


class TestChallenge16(unittest.TestCase):
    def test_bitflipping_attack(self):
        key, iv = random.randbytes(16), random.randbytes(16)
        ciphertext = do_bitflipping_attack(key, iv)
        plaintext = decrypt_aes_128_cbc(key, iv, ciphertext)[48:59].decode()
        self.assertEqual(plaintext, ";admin=true")


if __name__ == "__main__":
    unittest.main()
