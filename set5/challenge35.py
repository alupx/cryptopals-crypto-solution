from random import randbytes

from set2.challenge10 import decrypt_aes_128_cbc
from set2.challenge15 import strip_pkcs7_padding
from set5.challenge34 import dh_echo_bot, dh_party, int_to_16byte_key


def man_in_the_middle_inject_g(
    alice: dh_party, bot: dh_echo_bot, p: int, g: int
) -> tuple[bytes, bytes, bytes]:
    def mitm_decrypt(message: bytes) -> bytes:
        iv, ciphertext = message[:16], message[16:]
        return strip_pkcs7_padding(decrypt_aes_128_cbc(iv, key, ciphertext), 16)

    message = randbytes(300)
    A, B = alice.get_public_key(), bot.get_public_key()
    if g == 1:
        key = int_to_16byte_key(1)
    elif g == p - 1:
        key = int_to_16byte_key(p - 1 if A == B == p - 1 else 1)
    elif g == p:
        key = int_to_16byte_key(0)
    else:
        raise ValueError(f"unsupported g: {g}")
    _, _ = alice.generate_session_key(B), bot.generate_session_key(A)
    alice_to_eve = alice.encrypt(message)
    alice_plaintext = mitm_decrypt(alice_to_eve)
    bot_to_eve = bot.echo(alice_to_eve)
    bot_plaintext = mitm_decrypt(bot_to_eve)
    return message, alice_plaintext, bot_plaintext
