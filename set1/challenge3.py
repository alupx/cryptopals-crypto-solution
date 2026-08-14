from utils import plaintext_score


def decrypt_english_single_byte_xor(cryptotext: bytes) -> tuple[int, int, str]:
    bestScore = float('inf')
    bestPlaintext = None
    bestKey = None
    for key in range(256):
        plaintextBytes = bytes([c ^ key for c in cryptotext])
        if not plaintextBytes.isascii():
            continue
        else:
            plaintext = plaintextBytes.decode()
        score = plaintext_score(plaintext)
        if score < bestScore:
            bestKey = key
            bestScore = score
            bestPlaintext = plaintext
    return (bestScore, bestKey, bestPlaintext)


if __name__ == "__main__":
    testInput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    testOutput = "Cooking MC's like a pound of bacon"
    _, _, plaintext = decrypt_english_single_byte_xor(bytes.fromhex(testInput))
    assert plaintext == testOutput
    print("Passed")
