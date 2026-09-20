import random
from collections.abc import Callable

from set3.challenge18 import process_aes_128_ctr
from utils import read_base64_file


def edit_aes_128_ctr(
    nonce: int, key: bytes, ciphertext: bytes, offset: int, newtext: bytes
):
    assert offset <= len(ciphertext)
    plaintext = process_aes_128_ctr(nonce, key, ciphertext)
    plaintext = plaintext[:offset] + newtext + plaintext[offset:]
    return process_aes_128_ctr(nonce, key, plaintext)


def break_editable_aes_128_ctr(
    edit: Callable[[int, bytes, bytes], bytes], ciphertext: bytes
) -> bytes:
    ciphertext_len = len(ciphertext)
    zeroes = bytes(ciphertext_len)
    key = edit(0, zeroes, ciphertext)[:ciphertext_len]
    plaintext = bytes([c ^ k for c, k in zip(bytearray(ciphertext), bytearray(key))])
    return plaintext


if __name__ == "__main__":
    nonce = random.randint(0, 2**8 - 1)
    key = random.randbytes(16)
    plaintext = read_base64_file("data/25.txt")
    ciphertext = process_aes_128_ctr(nonce, key, plaintext)
    edit = lambda offset, newtext, ciphertext: edit_aes_128_ctr(
        nonce, key, ciphertext, offset, newtext
    )
    recovered_plaintext = break_editable_aes_128_ctr(edit, ciphertext)
    assert recovered_plaintext == plaintext
    print("k")
