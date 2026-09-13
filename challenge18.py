from challenge10 import encrypt_aes_128_ecb


def get_keystream(nonce: int, counter: int, key: bytes):
    stream = nonce.to_bytes(8, byteorder="little") + counter.to_bytes(
        8, byteorder="little"
    )
    return encrypt_aes_128_ecb(key, stream)


def process_aes_128_ctr(nonce: int, key: bytes, data: bytes) -> bytes:
    assert len(key) == 16
    output = b""
    i = 0
    while i * 16 < len(data):
        chunk = bytearray(data[i * 16 : min(len(data), (i + 1) * 16)])
        keystream = bytearray(get_keystream(nonce, i, key)[: len(chunk)])
        output += bytes(k ^ c for k, c in zip(keystream, chunk))
        i += 1
    return output
