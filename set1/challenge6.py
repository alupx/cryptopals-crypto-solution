import base64

from challenge3 import decrypt_english_single_byte_xor
from challenge5 import encrypt_repeating_key_xor
from utils import hamming_distance


def guess_key_length(
    cryptotext: bytes, min_len: int = 1, max_len: int | None = None
) -> list[int, int]:
    if max_len is None:
        max_len = len(cryptotext) // 2

    assert 0 < min_len < max_len <= len(cryptotext) // 2

    hamming_distances = []

    for l in range(min_len, max_len + 1):
        hamming_distances.append(
            (l, hamming_distance(cryptotext[:l], cryptotext[l : 2 * l]) / l)
        )

    hamming_distances.sort(key=lambda x: x[1])

    return hamming_distances


def decode(cryptotext: bytes, key_len: int) -> tuple[bytes, str]:
    key = []
    plaintext = [" "] * len(cryptotext)
    for i in range(key_len):
        interlaced = cryptotext[i::key_len]
        _, k, s = decrypt_english_single_byte_xor(interlaced)
        j = i
        for c in s:
            plaintext[j] = c
            j += key_len
        key.append(k)
    return bytes(key), "".join(plaintext)


b64text = ""
with open("6.txt", "r") as file:
    for line in file:
        b64text += line

cryptotext = base64.b64decode(b64text)
print(hamming_distance(b"this is a test", b"wokka wokka!!!"))
print(decode(cryptotext, 116))
