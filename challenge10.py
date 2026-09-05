from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_aes_128_cbc(iv: bytes, key: bytes, plaintext: bytes) -> bytes:
    assert len(plaintext) % 16 == 0
    assert len(iv) == 16
    assert len(key) == 16

    last_ciphertext_block = iv
    ciphertext = b""

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    for i in range(0, len(plaintext), 16):
        current_plaintext_block = plaintext[i : i + 16]
        encryptor = cipher.encryptor()
        encryptor_input = bytes(
            [a ^ b for a, b in zip(current_plaintext_block, last_ciphertext_block)]
        )
        ciphertext_block = encryptor.update(encryptor_input)
        last_ciphertext_block = ciphertext_block
        ciphertext += ciphertext_block

    return ciphertext


def decrypt_aes_128_cbc(iv: bytes, key: bytes, ciphertext: bytes) -> bytes:
    assert len(ciphertext) % 16 == 0
    assert len(iv) == 16
    assert len(key) == 16

    last_ciphertext_block = iv
    plaintext = b""

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    for i in range(0, len(ciphertext), 16):
        current_ciphertext_block = ciphertext[i : i + 16]
        decryptor = cipher.decryptor()
        plaintext_block = decryptor.update(current_ciphertext_block)
        plaintext += bytes(
            [a ^ b for a, b in zip(plaintext_block, last_ciphertext_block)]
        )
        last_ciphertext_block = current_ciphertext_block

    return plaintext
