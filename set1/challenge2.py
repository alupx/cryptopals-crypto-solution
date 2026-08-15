def fixed_byte_xor(plaintext: bytes, key: bytes) -> bytes:
    assert len(plaintext) == len(key)
    return bytes([p ^ k for p, k in zip(plaintext, key)])
