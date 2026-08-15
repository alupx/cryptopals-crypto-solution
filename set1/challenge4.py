from challenge3 import decrypt_english_single_byte_xor


def find_and_decrypt_single_byte_xor_in_file(filename: str) -> str:
    bestScore = float('inf')
    with open(filename, "r") as file:
        for line in file:
            score, _, plaintext = decrypt_english_single_byte_xor(
                bytes.fromhex(line.strip())
            )
            if score < bestScore:
                bestText = plaintext
                bestScore = score
    return bestText


inputFile = "data/4.txt"
testOutput = "Now that the party is jumping\n"
assert find_and_decrypt_single_byte_xor_in_file(inputFile) == testOutput
print("Passed")
