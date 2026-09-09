def strip_pkc7_padding(data: bytes, block_size: int) -> bytes:
    pad_len = data[-1]
    if pad_len > block_size:
        raise ValueError("Padding longer than a block")
    if any(x != pad_len for x in data[-pad_len:]):
        raise ValueError("Wrong padding")
    return data[: (len(data) - pad_len)]
