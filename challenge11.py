from random import randbytes, randint

from challenge8 import aes128_ecb_likelyhood
from challenge9 import add_pkcs7_padding
from challenge10 import encrypt_aes_128_cbc, encrypt_aes_128_ecb


def ecb_cbc_encryption_oracle(data: bytes):
    prepend_len, append_len = randint(5, 10), randint(5, 10)
    prepend_data, append_data = randbytes(prepend_len), randbytes(append_len)

    key = randbytes(16)
    data = prepend_data + data + append_data
    data = add_pkcs7_padding(data, 16)

    mode = randint(0, 1)

    if mode:
        # CBC
        iv = randbytes(16)
        ciphertext = encrypt_aes_128_cbc(iv, key, data)
    else:
        # ECB
        ciphertext = encrypt_aes_128_ecb(key, data)

    return mode, ciphertext


def ecb_detector(ciphertext: bytes) -> bool:
    return aes128_ecb_likelyhood(ciphertext) > 0
