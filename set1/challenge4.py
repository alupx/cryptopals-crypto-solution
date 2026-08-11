from challenge3 import decryptEnglishSingleByteXOR

bestScore = 0
with open("4.txt", 'r') as file:
    for line in file:
        score, plaintext = decryptEnglishSingleByteXOR(line.strip())
        if score > bestScore:
            bestText = plaintext
            bestScore = score
            print(score, plaintext)
