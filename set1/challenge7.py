import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

with open("data/7.txt", "r") as file:
    ctb64 = ""
    for line in file:
        ctb64 += line
ct = base64.b64decode(ctb64)

key = b"YELLOW SUBMARINE"

cipher = Cipher(algorithms.AES(key), modes.ECB())
decryptor = cipher.decryptor()
print(decryptor.update(ct) + decryptor.finalize())
