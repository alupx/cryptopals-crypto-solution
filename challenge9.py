def add_pkcs7_padding(data: bytes, block_size: int) -> bytes:
    modulo = len(data) % block_size
    if modulo == 0:
        modulo = block_size
    pad_len = block_size - modulo
    return data + bytes([pad_len] * pad_len)
