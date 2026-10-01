import random
import unittest

from set2.challenge9 import add_pkcs7_padding
from set2.challenge10 import decrypt_aes_128_cbc, encrypt_aes_128_cbc
from set3.challenge18 import process_aes_128_ctr
from set4.challenge25 import break_editable_aes_128_ctr, edit_aes_128_ctr
from set4.challenge26 import do_bitflipping_attack
from set4.challenge27 import break_cbc_iv_equals_key
from set4.challenge28 import sha1, sha1_mac
from set4.challenge29 import sha1_mac_length_extension, verify_sha1_mac
from set4.challenge30 import md4, md4_mac, md4_mac_length_extension, verify_md4_mac
from set4.challenge31 import guess_hmac, hmac_sha1, slow_compare
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


class TestChallenge27(unittest.TestCase):
    def test_recovering_key_from_cbc_iv_equals_key(self):
        key = random.randbytes(16)
        plaintext = (
            b"nel mezzo del cammin di nostra vita mi ritrovai per una selva oscura"
        )
        ciphertext = encrypt_aes_128_cbc(key, key, add_pkcs7_padding(plaintext, 16))
        get_decryption_result = lambda ciphertext: decrypt_aes_128_cbc(
            key, key, ciphertext
        )
        self.assertEqual(
            break_cbc_iv_equals_key(ciphertext, get_decryption_result), plaintext
        )


class TestChallenge28(unittest.TestCase):
    def test_sha1_blank(self):
        self.assertEqual(sha1(b""), 0xDA39A3EE5E6B4B0D3255BFEF95601890AFD80709)

    def test_sha1_string(self):
        self.assertEqual(
            sha1(b"The quick brown fox jumps over the lazy dog"),
            0x2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12,
        )


class TestChallenge29(unittest.TestCase):
    def test_sha1_extension(self):
        key = random.randbytes(random.randint(1, 64))
        message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        extension = b";admin=true"
        mac = sha1_mac(key, message)
        verify = lambda msg, mac: verify_sha1_mac(msg, key, mac)
        extended_message, extended_mac = sha1_mac_length_extension(
            message, extension, mac, verify
        )
        self.assertTrue(extended_message.startswith(message))
        self.assertTrue(extended_message.endswith(extension))
        self.assertTrue(verify_sha1_mac(extended_message, key, extended_mac))


class TestChallenge30(unittest.TestCase):
    def test_md4_blank(self):
        self.assertEqual(md4(b""), 0x31D6CFE0D16AE931B73C59D7E0C089C0)

    def test_md4_string(self):
        self.assertEqual(
            md4(b"The quick brown fox jumps over the lazy dog"),
            0x1BEE69A46BA811185C194762ABAEAE90,
        )

    def test_md4_extension(self):
        key = random.randbytes(random.randint(1, 64))
        message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        extension = b";admin=true"
        mac = md4_mac(key, message)
        verify = lambda msg, mac: verify_md4_mac(msg, key, mac)
        extended_message, extended_mac = md4_mac_length_extension(
            message, extension, mac, verify
        )
        self.assertTrue(extended_message.startswith(message))
        self.assertTrue(extended_message.endswith(extension))
        self.assertTrue(verify_md4_mac(extended_message, key, extended_mac))


class TestChallenge31(unittest.TestCase):
    message = b"The quick brown fox jumps over the lazy dog"

    def test_hmac_sha1_short_key(self):
        self.assertEqual(
            hmac_sha1(b"key", self.message),
            0xDE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9,
        )

    def test_hmac_sha1_block_size_key(self):
        self.assertEqual(
            hmac_sha1(b"A" * 64, self.message),
            0x76A4A7EB10B722FA4EA89D5C3548E4CFC7DC5801,
        )

    def test_hmac_sha1_long_key(self):
        self.assertEqual(
            hmac_sha1(b"A" * 100, self.message),
            0x1307E001A9782FB0A8DE16DA90197642CDC0A73E,
        )

    def test_hmac_sha1_timing_leak(self):
        # We try to guess only the first 3 bytes of a random sha1 hash
        delay = 6
        bytes_to_guess = 3
        target = b"\x10\x20\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        check = lambda guess: slow_compare(target, guess, delay)
        guess = guess_hmac(check, bytes_to_guess, delay)
        self.assertEqual(guess, target)


if __name__ == "__main__":
    unittest.main()
