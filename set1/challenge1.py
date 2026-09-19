base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def binary_to_base64(input: bytes) -> str:
    def encode_byte_triplet(triplet: bytes) -> str:
        value = triplet[0] << 16 | triplet[1] << 8 | triplet[2]
        return (
            base64_alphabet[(value & 0xFC0000) >> 18]
            + base64_alphabet[(value & 0x3F000) >> 12]
            + base64_alphabet[(value & 0xFC0) >> 6]
            + base64_alphabet[(value & 0x3F)]
        )

    base64_str = ""
    for i in range(0, len(input), 3):
        if i + 3 <= len(input):
            triplet = input[i : i + 3]
            pad = 0
        elif i + 2 <= len(input):
            triplet = input[i : i + 2] + b"\x00"
            pad = 1
        else:
            triplet = input[i : i + 1] + b"\x00\x00"
            pad = 2
        base64_str += encode_byte_triplet(triplet)
    if pad:
        base64_str = base64_str[:-pad]
        base64_str += "=" * pad
    return base64_str
