hexCharacters = "0123456789abcdef"

def validateHexString(s: str) -> bool:
    if len(s) % 2: return False;
    return all(c in hexCharacters for c in s)

englishCharacters = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "1234567890"
        " .,'?!@"
        )

def plaintextScore(s: str) -> float:
    return sum(c in englishCharacters for c in s) / len(s)

def hexToASCII(hexString: str) -> str:
    assert validateHexString(hexString)
    
    ASCIIString = ""
    for i in range(0, len(hexString), 2):
        ASCIIString += chr(int(hexString[i:i+2], 16))
    return ASCIIString
