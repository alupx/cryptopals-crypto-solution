import base64
import random
import unittest

from set2.challenge9 import add_pkcs7_padding
from set2.challenge10 import encrypt_aes_128_cbc
from set3.challenge17 import padding_oracle, padding_oracle_attack
from set3.challenge18 import process_aes_128_ctr
from set3.challenge20 import break_fixed_nonce
from set3.challenge21 import MT19937
from set3.challenge22 import bruteforce_MT19937
from set3.challenge23 import (
    clone_MT19937_from_output,
    invert_xor_lshift_and,
    invert_xor_rshift_and,
    xor_lshift_and,
    xor_rshift_and,
)
from set3.challenge24 import (
    bruteforce_MT19937_stream_cipher,
    process_MT19937_stream_cipher,
)
from utils import read_base64_file


class TestChallenge17(unittest.TestCase):
    def test_padding_oracle_attack(self):
        with open("data/17.txt", "r") as file:
            lines = [base64.b64decode(line) for line in file]

        for plaintext in lines:
            key, iv = random.randbytes(16), random.randbytes(16)
            padded_plaintext = add_pkcs7_padding(plaintext, 16)
            ciphertext = encrypt_aes_128_cbc(iv, key, padded_plaintext)
            oracle = lambda iv, ciphertext, key=key: padding_oracle(iv, key, ciphertext)
            msg = padding_oracle_attack(iv, ciphertext, oracle)
            self.assertEqual(msg, padded_plaintext)


class TestChallenge18(unittest.TestCase):
    def test_decryption_ice_baby(self):
        ciphertext = read_base64_file("data/18.txt")
        self.assertEqual(
            process_aes_128_ctr(0, b"YELLOW SUBMARINE", ciphertext),
            b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
        )

    def test_encryption_decryption(self):
        plaintext = random.randbytes(200)
        nonce = random.randint(0, 2**64 - 1)
        key = random.randbytes(16)
        ciphertext = process_aes_128_ctr(nonce, key, plaintext)
        self.assertEqual(plaintext, process_aes_128_ctr(nonce, key, ciphertext))


class TestChallenge20(unittest.TestCase):
    def test_break_fixed_nonce(self):
        key = random.randbytes(16)

        with open("data/19.txt", "r") as f:
            plaintexts = [base64.b64decode(line) for line in f]

        ciphertexts = [process_aes_128_ctr(0, key, pt) for pt in plaintexts]
        for decrypted, target in zip(break_fixed_nonce(ciphertexts), plaintexts):
            self.assertEqual(decrypted[:16].lower(), target[:16].decode().lower())


class TestChallenge21(unittest.TestCase):
    def test_known_sequence(self):
        mt = MT19937(5489)
        obtained = [mt.rand() for _ in range(5)]
        # https://oeis.org/A221557
        target = [3499211612, 581869302, 3890346734, 3586334585, 545404204]
        self.assertEqual(obtained, target)


class TestChallenge22(unittest.TestCase):
    def test_seed_cracking(self):
        fake_time_seed = random.randint(2880000000, 2880010000)
        first_output = MT19937(fake_time_seed).rand()
        cracked = bruteforce_MT19937(first_output, 2880020000)
        self.assertEqual(fake_time_seed, cracked)


class TestChallenge23(unittest.TestCase):
    def test_untempering_functions_edge_cases(self):
        for x in (0, 0xFFFFFFFF):
            for a in (0, 0xFFFFFFFF):
                for n in (1, 31):
                    q = xor_rshift_and(x, n, a)
                    self.assertEqual(invert_xor_rshift_and(q, n, a), x)
                    q = xor_lshift_and(x, n, a)
                    self.assertEqual(invert_xor_lshift_and(q, n, a), x)

    def test_untempering_functions_fuzzy(self):
        for _ in range(10):
            x = random.randint(0, 0xFFFFFFFF)
            a = random.randint(0, 0xFFFFFFFF)
            n = random.randint(1, 31)
            q = xor_rshift_and(x, n, a)
            self.assertEqual(invert_xor_rshift_and(q, n, a), x)
            q = xor_lshift_and(x, n, a)
            self.assertEqual(invert_xor_lshift_and(q, n, a), x)

    def test_MT19937_cloning(self):
        mt = MT19937(5489)
        clone = clone_MT19937_from_output(mt.rand)
        self.assertEqual(mt.x, clone.x)
        for _ in range(100):
            self.assertEqual(mt.rand(), clone.rand())


class TestChallenge24(unittest.TestCase):
    def test_encryption_decryption(self):
        plaintext = random.randbytes(200)
        key = random.randint(0, 2**16 - 1)
        ciphertext = process_MT19937_stream_cipher(key, plaintext)
        self.assertEqual(plaintext, process_MT19937_stream_cipher(key, ciphertext))

    def test_bruteforce(self):
        suffix = b"AAAAAAAAAAAAAA"
        plaintext = random.randbytes(200) + suffix
        key = random.randint(0, 2**16 - 1)
        ciphertext = process_MT19937_stream_cipher(key, plaintext)
        self.assertEqual(
            plaintext, bruteforce_MT19937_stream_cipher(ciphertext, suffix)
        )


if __name__ == "__main__":
    unittest.main()
