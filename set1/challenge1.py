base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def binary_to_base64(input: bytes) -> str:
    def encode_byte_triplet(triplet: bytes) -> str:
        value = triplet[0] << 16 | triplet[1] << 8 | triplet[2]
        return (
            base64Alphabet[(value & 0xFC0000) >> 18]
            + base64Alphabet[(value & 0x3F000) >> 12]
            + base64Alphabet[(value & 0xFC0) >> 6]
            + base64Alphabet[(value & 0x3F)]
        )

    base64Str = ""
    for i in range(0, len(input), 3):
        if i + 3 <= len(input):
            triplet = input[i : i + 3]
            toRemove = 0
        elif i + 2 <= len(input):
            triplet = input[i : i + 2] + b"\x00"
            toRemove = 1
        else:
            triplet = input[i : i + 1] + b"\x00\x00"
            toRemove = 2
        base64Str += encode_byte_triplet(triplet)
    if toRemove:
        base64Str = base64Str[:-toRemove]
        base64Str += "=" * toRemove
    return base64Str


testInput = bytes.fromhex(
    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
)
testOutput = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
assert binary_to_base64(testInput) == testOutput

testInput = bytes.fromhex("42424242")
testOutput = "QkJCQg=="
assert binary_to_base64(testInput) == testOutput

testInput = bytes.fromhex("4242")
testOutput = "QkI="
assert binary_to_base64(testInput) == testOutput

print("Passed")
