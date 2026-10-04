from random import randbytes

from set2.challenge9 import add_pkcs7_padding
from set2.challenge10 import decrypt_aes_128_cbc, encrypt_aes_128_cbc
from set2.challenge15 import strip_pkcs7_padding
from set4.challenge28 import sha1
from set5.challenge33 import diffie_hellman


def int_to_16byte_key(x: int) -> bytes:
    def int_to_bytes(x: int) -> bytes:
        byte_len = (x.bit_length() + 7) // 8
        return x.to_bytes(byte_len, "big")

    return int_to_bytes(sha1(int_to_bytes(x)))[:16]


class dh_party:
    def __init__(self, p: int, g: int):
        self.dh = diffie_hellman(p, g)
        self.a, self.A = self.dh.get_keys()
        self.key, self.s = b"", 0

    def get_public_key(self):
        return self.A

    def generate_session_key(self, B: int) -> int:
        self.s = self.dh.get_session_key(self.a, B)
        self.key = int_to_16byte_key(self.s)
        return self.s

    def encrypt(self, message: bytes) -> bytes:
        iv = randbytes(16)
        plaintext = add_pkcs7_padding(message, 16)
        return iv + encrypt_aes_128_cbc(iv, self.key, plaintext)

    def decrypt(self, message: bytes) -> bytes:
        iv, ciphertext = message[:16], message[16:]
        return strip_pkcs7_padding(decrypt_aes_128_cbc(iv, self.key, ciphertext), 16)


class dh_echo_bot(dh_party):
    def echo(self, message: bytes) -> bytes:
        plaintext = self.decrypt(message)
        return self.encrypt(plaintext)


def man_in_the_middle(
    alice: dh_party, bot: dh_echo_bot, p: int
) -> tuple[bytes, bytes, bytes]:
    def mitm_decrypt(message: bytes) -> bytes:
        iv, ciphertext = message[:16], message[16:]
        return strip_pkcs7_padding(decrypt_aes_128_cbc(iv, zero_key, ciphertext), 16)

    message = randbytes(300)
    zero_key = int_to_16byte_key(0)
    _, _ = alice.generate_session_key(p), bot.generate_session_key(p)
    alice_to_eve = alice.encrypt(message)
    alice_plaintext = mitm_decrypt(alice_to_eve)
    bot_to_eve = bot.echo(alice_to_eve)
    bot_plaintext = mitm_decrypt(bot_to_eve)
    return message, alice_plaintext, bot_plaintext
