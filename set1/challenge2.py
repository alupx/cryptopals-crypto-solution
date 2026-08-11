from utils import validateHexString

def fixedXorHex(hex1: str, hex2: str) -> str:
    assert len(hex1) == len(hex2)
    assert validateHexString(hex1)
    assert validateHexString(hex2)

    result = ""
    for i in range(0, len(hex1), 2):
        byte1 = int(hex1[i:i+2], 16)
        byte2 = int(hex2[i:i+2], 16)
        result += f"{(byte1^byte2):x}"
    return result


hex1 = "1c0111001f010100061a024b53535009181c"
hex2 = "686974207468652062756c6c277320657965"
expectedOutput = "746865206b696420646f6e277420706c6179"
assert(fixedXorHex(hex1, hex2) == expectedOutput);
