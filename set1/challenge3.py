from utils import hexToASCII, plaintextScore

def decryptEnglishSingleByteXOR(encryptedHexStr: str) -> str:
    bestScore = 0.0
    bestPlaintext = ""

    for key in range(256):
        decryptedHexStr = ""
        for i in range(0, len(encryptedHexStr), 2):
            decryptedHexStr += f"{(int(encryptedHexStr[i:i+2], 16)^key):02x}"
        score = plaintextScore(hexToASCII(decryptedHexStr))
        if score > bestScore:
            bestScore = score
            bestPlaintext = hexToASCII(decryptedHexStr)
    return (bestScore, bestPlaintext)

print(decryptEnglishSingleByteXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
