import sys

sys.path.append("..")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_aes_128_cbs(iv: bytes, key: bytes, ciphertext: bytes) -> bytes:
    assert len(ciphertext) % 16 == 0
    assert len(iv) == 16
    assert len(key) == 16

    last_ciphertext_block = iv
    plaintext = b""

    for i in range(0, len(ciphertext), 16):
        current_ciphertext_block = ciphertext[i : i + 16]
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        plaintext_block = decryptor.update(current_ciphertext_block)
        plaintext += bytes(
            [a ^ b for a, b in zip(plaintext_block, last_ciphertext_block)]
        )
        last_ciphertext_block = current_ciphertext_block

    return plaintext
