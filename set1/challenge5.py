from itertools import cycle


def encrypt_repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key for byte, key in zip(plaintext, cycle(key)))
