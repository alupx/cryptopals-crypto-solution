from random import randbytes

from challenge9 import add_pkcs7_padding
from challenge10 import encrypt_aes_128_ecb
from challenge11 import ecb_detector
from utils import read_base64_file


def ecb_encryption_oracle(key, data):
    unknown_string = read_base64_file("data/12.txt")
    padded_plaintext = add_pkcs7_padding(data + unknown_string, 16)
    return encrypt_aes_128_ecb(key, padded_plaintext)


def decrypt_unknown_string():
    key = randbytes(16)

    buffer = b""

    min_ciphertext = ecb_encryption_oracle(key, buffer)
    min_ciphertext_len = len(min_ciphertext)

    buffer_len = 0
    while True:
        buffer_len += 1
        buffer += b"a"
        ciphertext_len = len(ecb_encryption_oracle(key, buffer))
        if ciphertext_len > min_ciphertext_len:
            break
    block_size = ciphertext_len - min_ciphertext_len

    ciphertext = ecb_encryption_oracle(key, b"a" * block_size * 2)
    is_ecb = ecb_detector(ciphertext)

    msg = b""
    for idx in range(min_ciphertext_len):
        count_of_previous_blocks = idx // block_size
        block_start = count_of_previous_blocks * block_size
        block_end = (count_of_previous_blocks + 1) * block_size
        buffer = b"a" * (block_size - idx % block_size - 1)
        target = ecb_encryption_oracle(key, buffer)[block_start:block_end]
        next_plaintext_byte = None
        for x in range(256):
            c = bytes([x])
            test_buffer = buffer + msg + c
            test_ciphertext = ecb_encryption_oracle(key, test_buffer)[
                block_start:block_end
            ]
            if target == test_ciphertext:
                next_plaintext_byte = c
                break
        if next_plaintext_byte:
            msg += next_plaintext_byte
            continue
        else:
            break
    if msg[-1] == 1:
        # delete first decoded padding
        msg = msg[:-1]

    return block_size, is_ecb, msg
