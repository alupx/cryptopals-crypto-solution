from .challenge9 import add_pkcs7_padding
from .challenge10 import encrypt_aes_128_cbc


def generate_ciphertext(key: bytes, iv: bytes, data: str) -> bytes:
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    data = data.replace(";", "").replace("=", "")
    plaintext = add_pkcs7_padding(bytes(prefix + data + suffix, "utf-8"), 16)
    return encrypt_aes_128_cbc(key, iv, plaintext)


def do_bitflipping_attack(key, iv):
    user_data = "a" * 16 + "9admin9true"
    ciphertext = generate_ciphertext(key, iv, user_data)
    array = bytearray(ciphertext)
    array[32] ^= 2
    array[38] ^= 4
    ciphertext = bytes(array)
    return ciphertext
