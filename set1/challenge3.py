import sys

sys.path.append("..")
from utils import plaintext_score


def decrypt_english_single_byte_xor(ciphertext: bytes) -> tuple[int, int, str]:
    best_score = float("inf")
    best_plaintext = None
    best_key = None
    for key in range(256):
        plaintext_bytes = bytes([c ^ key for c in ciphertext])
        if not plaintext_bytes.isascii():
            continue
        else:
            plaintext = plaintext_bytes.decode()
        score = plaintext_score(plaintext)
        if score < best_score:
            best_key = key
            best_score = score
            best_plaintext = plaintext
    return (best_score, best_key, best_plaintext)
