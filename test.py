import base64
import random
import unittest

from challenge1 import binary_to_base64
from challenge2 import fixed_byte_xor
from challenge3 import decrypt_english_single_byte_xor
from challenge4 import find_and_decrypt_single_byte_xor_in_file
from challenge5 import encrypt_repeating_key_xor
from challenge6 import decrypt_english_multi_byte_xor, guess_key_length
from challenge8 import aes128_ecb_likelyhood
from challenge9 import add_pkcs7_padding
from challenge10 import decrypt_aes_128_cbc, encrypt_aes_128_cbc
from challenge11 import ecb_cbc_encryption_oracle, ecb_detector
from challenge12 import decrypt_unknown_string
from challenge13 import (
    aes_ecb_cut_and_paste_generate_admin,
    decode_profile,
    decrypt_profile,
    provide_encrypted_profile,
)
from challenge14 import decrypt_unknown_string_hard, ecb_encryption_oracle_hard
from challenge15 import strip_pkc7_padding
from challenge16 import do_bitflipping_attack
from challenge17 import padding_oracle, padding_oracle_attack
from challenge18 import process_aes_128_ctr
from challenge20 import break_fixed_nonce
from utils import hamming_distance, read_base64_file, read_binary_file


class TestUtils(unittest.TestCase):
    def test_hamming_distance(self):
        self.assertEqual(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37)


class TestSet1(unittest.TestCase):
    def setUp(self):
        self.challenge6_ciphertext = read_base64_file("data/6.txt")

    def test_challenge1(self):
        self.assertEqual(
            binary_to_base64(
                bytes.fromhex(
                    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
                )
            ),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        )

        self.assertEqual(
            binary_to_base64(bytes.fromhex("4242")),
            "QkI=",
        )

        self.assertEqual(
            binary_to_base64(bytes.fromhex("42424242")),
            "QkJCQg==",
        )

    def test_challenge2(self):
        plaintext = bytes.fromhex("1c0111001f010100061a024b53535009181c")
        key = bytes.fromhex("686974207468652062756c6c277320657965")
        expected_output = "746865206b696420646f6e277420706c6179"
        self.assertEqual(fixed_byte_xor(plaintext, key).hex(), expected_output)

    def test_challenge3(self):
        testInput = (
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )
        test_output = "Cooking MC's like a pound of bacon"
        _, _, plaintext = decrypt_english_single_byte_xor(bytes.fromhex(testInput))
        self.assertEqual(plaintext, test_output)

    def test_challenge4(self):
        input_file = "data/4.txt"
        test_output = "Now that the party is jumping\n"
        self.assertEqual(
            find_and_decrypt_single_byte_xor_in_file(input_file), test_output
        )

    def test_challenge5(self):
        plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key = b"ICE"
        ciphertext = encrypt_repeating_key_xor(plaintext, key)
        expected_ciphertext = (
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
            "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        )
        self.assertEqual(ciphertext.hex(), expected_ciphertext)

    def test_challenge6_key_len(self):
        guesses = guess_key_length(self.challenge6_ciphertext)
        # test that the correct answer is among first 5 guesses
        most_likely_keylens = [key_len for key_len, _ in guesses[:6]]
        self.assertIn(116, most_likely_keylens)

    def test_challenge6_key(self):
        key, _ = decrypt_english_multi_byte_xor(self.challenge6_ciphertext, 116)
        expected_key = b"Terminator X: Bring the noiseTerminator X: Bring the noiseTerminator X: Bring the noiseTerminator X: Bring the noise"
        wrong_bytes = sum(key[i] != expected_key[i] for i in range(116))
        self.assertTrue(wrong_bytes < 10)

    def test_challenge8(self):
        correct_answer = 132
        with open("data/8.txt", "r") as file:
            likelyhoods = []
            for line in file:
                data = bytes.fromhex(line)
                likelyhoods.append(aes128_ecb_likelyhood(data))
        self.assertTrue(likelyhoods[correct_answer] > 0)
        self.assertEqual(sum(likelyhoods), likelyhoods[correct_answer])


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
        files_to_encrypt = ["challenge1.py", "challenge2.py", "utils.py"]
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
            self.assertEqual(decrypted[:16], target[:16].decode())


if __name__ == "__main__":
    unittest.main()
