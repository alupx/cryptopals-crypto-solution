from utils import plaintext_score


def decrypt_english_single_byte_xor(cryptotext: bytes) -> str:
    bestScore = 0.0
    bestPlaintext = ""
    for key in range(256):
        plaintextBytes = bytes([c ^ key for c in cryptotext])
        if not plaintextBytes.isascii():
            continue
        else:
            plaintext = plaintextBytes.decode()
        score = plaintext_score(plaintext)
        if score > bestScore:
            bestScore = score
            bestPlaintext = plaintext
    return (bestScore, bestPlaintext)


if __name__ == "__main__":
    testInput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    testOutput = "Cooking MC's like a pound of bacon"
    _, plaintext = decrypt_english_single_byte_xor(bytes.fromhex(testInput))
    assert plaintext == testOutput
    print("Passed")
