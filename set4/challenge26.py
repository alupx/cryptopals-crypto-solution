from set3.challenge18 import process_aes_128_ctr


def generate_ciphertext(nonce: int, key: bytes, data: str) -> bytes:
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    data = data.replace(";", "").replace("=", "")
    plaintext = bytes(prefix + data + suffix, "utf-8")
    return process_aes_128_ctr(nonce, key, plaintext)


def do_bitflipping_attack(nonce: int, key: bytes):
    user_data = "foo9admin9true"
    ciphertext = generate_ciphertext(nonce, key, user_data)
    array = bytearray(ciphertext)
    array[35] ^= 2
    array[41] ^= 4
    ciphertext = bytes(array)
    return ciphertext
