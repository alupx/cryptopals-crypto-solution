from collections.abc import Callable

from set2.challenge10 import decrypt_aes_128_cbc
from set2.challenge15 import strip_pkc7_padding


def padding_oracle(iv: bytes, key: bytes, data: bytes) -> bool:
    # Returns true if data if plaintext is correctly padded after CBC decryption
    plaintext = decrypt_aes_128_cbc(iv, key, data)
    try:
        _ = strip_pkc7_padding(plaintext, 16)
    except ValueError:
        return False
    return True


def padding_oracle_attack(
    iv: bytes, ciphertext: bytes, padding_oracle: Callable[[bytes, bytes], bool]
) -> bytes:
    # Decrypt first block (using IV)
    block = bytearray(16)
    for i in range(15, -1, -1):
        corrupted_iv = bytearray(iv)
        for j in range(i, 16):
            corrupted_iv[j] = (16 - i) ^ block[j]
        for c in range(256):
            corrupted_iv[i] = c
            if padding_oracle(bytes(corrupted_iv), ciphertext[:16]):
                if i > 0:
                    corrupted_iv[i - 1] ^= 1
                    if not padding_oracle(bytes(corrupted_iv), ciphertext[:16]):
                        corrupted_iv[i - 1] ^= 1
                        continue
                block[i] = (16 - i) ^ c
                break
    msg = bytes(block[i] ^ iv[i] for i in range(16))

    # Decrypt next blocks
    block_count = len(ciphertext) // 16
    for k in range(block_count - 1):
        block = bytearray(16)
        for i in range(15, -1, -1):
            corrupted_block = bytearray(ciphertext[(k) * 16 : (k + 1) * 16])
            for j in range(i, 16):
                corrupted_block[j] = (16 - i) ^ block[j]
            for c in range(256):
                corrupted_block[i] = c
                if padding_oracle(
                    iv, bytes(corrupted_block) + ciphertext[(k + 1) * 16 : (k + 2) * 16]
                ):
                    if i > 0:
                        corrupted_block[i - 1] ^= 1
                        if not padding_oracle(
                            iv,
                            bytes(corrupted_block)
                            + ciphertext[(k + 1) * 16 : (k + 2) * 16],
                        ):
                            corrupted_block[i - 1] ^= 1
                            continue
                    block[i] = (16 - i) ^ c
                    break
        msg += bytes(
            block[i] ^ bytearray(ciphertext[(k) * 16 : (k + 1) * 16])[i]
            for i in range(16)
        )

    return msg
