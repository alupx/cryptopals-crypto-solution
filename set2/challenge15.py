def strip_pkcs7_padding(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Data length is not a positive multiple of the block size")
    pad_len = data[-1]
    if not 0 < pad_len <= block_size:
        raise ValueError("Invalid padding length")
    if any(x != pad_len for x in data[-pad_len:]):
        raise ValueError("Wrong padding")
    return data[:-pad_len]
