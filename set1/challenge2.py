def fixed_byte_xor(plaintext: bytes, key: bytes) -> bytes:
    assert len(plaintext) == len(key)
    return bytes([p ^ k for p, k in zip(plaintext, key)])


plaintext = bytes.fromhex("1c0111001f010100061a024b53535009181c")
key = bytes.fromhex("686974207468652062756c6c277320657965")
expectedOutput = "746865206b696420646f6e277420706c6179"
assert fixed_byte_xor(plaintext, key).hex() == expectedOutput
print("Passed")
