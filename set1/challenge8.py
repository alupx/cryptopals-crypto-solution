def aes128_ecb_likelyhood(data: bytes) -> float:
    assert len(data) % 16 == 0
    chunks_set = {data[i : i + 16] for i in range(0, len(data), 16)}
    chunks_count = len(data) // 16
    return (chunks_count - len(chunks_set)) / chunks_count
