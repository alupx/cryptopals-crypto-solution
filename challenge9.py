def add_pkcs7_padding(data: bytes, block_size: int) -> bytes:
    modulo = len(data) % block_size
    if modulo == 0:
        modulo = block_size
    pad_len = block_size - modulo
    return data + bytes([pad_len] * pad_len)


def strip_pkc7_padding(data: bytes, block_size: int) -> bytes:
    pad_len = data[-1]
    assert pad_len <= block_size
    return data[: (len(data) - pad_len)]
