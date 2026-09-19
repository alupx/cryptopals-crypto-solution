from challenge21 import MT19937


def process_MT19937_stream_cipher(key: int, data: bytes) -> bytes:
    KEY_MASK = 0xFFFF
    OUTPUT_MASK = 0xFF

    rng = MT19937(key & KEY_MASK)
    get_keystream = lambda: rng.rand() & OUTPUT_MASK

    output = b""
    for byte in data:
        output += bytes([byte ^ get_keystream()])
    return output


def bruteforce_MT19937_stream_cipher(ciphertext: bytes, target_suffix: bytes) -> bytes:
    """
    Bruteforce the ciphertext given that the seed is 16 bits long and given
    a known suffix in the plaintext
    """
    for seed in range(2**16):
        plaintext = process_MT19937_stream_cipher(seed, ciphertext)
        if plaintext.endswith(target_suffix):
            return plaintext
    return b""
