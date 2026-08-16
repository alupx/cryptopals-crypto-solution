from challenge3 import decrypt_english_single_byte_xor
from utils import hamming_distance


def guess_key_length(
    ciphertext: bytes, min_len: int = 1, max_len: int | None = None
) -> list[int, int]:
    if max_len is None:
        max_len = len(ciphertext) // 2

    assert 0 < min_len < max_len <= len(ciphertext) // 2

    hamming_distances = []

    for l in range(min_len, max_len + 1):
        hamming_distances.append(
            (l, hamming_distance(ciphertext[:l], ciphertext[l : 2 * l]) / l)
        )

    hamming_distances.sort(key=lambda x: x[1])

    return hamming_distances


def decrypt_english_multi_byte_xor(
    ciphertext: bytes, key_len: int
) -> tuple[bytes, str]:
    key = []
    plaintext = [" "] * len(ciphertext)
    for i in range(key_len):
        interlaced = ciphertext[i::key_len]
        _, k, s = decrypt_english_single_byte_xor(interlaced)
        j = i
        for c in s:
            plaintext[j] = c
            j += key_len
        key.append(k)
    return bytes(key), "".join(plaintext)
