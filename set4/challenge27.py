from collections.abc import Callable

from set2.challenge10 import decrypt_aes_128_cbc
from set2.challenge15 import strip_pkc7_padding


def break_cbc_iv_equals_key(
    ciphertext: bytes, get_decryption_result: Callable[[bytes], bytes]
) -> bytes:
    forged_ciphertext = ciphertext[:16] + bytes(16) + ciphertext[:16]
    corrupted_decryption = get_decryption_result(forged_ciphertext)
    recovered_key = bytes(
        [a ^ b for a, b in zip(corrupted_decryption[:16], corrupted_decryption[32:])]
    )
    recovered_plaintext = decrypt_aes_128_cbc(recovered_key, recovered_key, ciphertext)
    return strip_pkc7_padding(recovered_plaintext, 16)
