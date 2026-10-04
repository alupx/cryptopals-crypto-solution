def add_pkcs7_padding(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)
