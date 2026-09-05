from collections.abc import Callable

from challenge9 import add_pkcs7_padding, strip_pkc7_padding
from challenge10 import decrypt_aes_128_ecb, encrypt_aes_128_ecb


def encode_profile(email: str, uid: int, role: str) -> str:
    return f"email={email}&uid={uid}&role={role}"


def decode_profile(profile: str) -> tuple[str, int, str]:
    a, b, c = profile.split("&")
    email = a[6:]
    uid = int(b[4:])
    role = c[5:]
    return (email, uid, role)


def profile_for(email: str):
    return encode_profile(email, 10, "user")


def provide_encrypted_profile(key: bytes, email: str):
    profile_string = profile_for(email)
    plaintext = add_pkcs7_padding(bytes(profile_string, "utf-8"), 16)
    return encrypt_aes_128_ecb(key, plaintext)


def decrypt_profile(key: bytes, ciphertext: bytes):
    plaintext = strip_pkc7_padding(decrypt_aes_128_ecb(key, ciphertext), 16)
    return plaintext


def aes_ecb_cut_and_paste_generate_admin(
    encrypted_profile_getter: Callable[[str], bytes],
) -> bytes:
    # "email=bre@k.aes.ecb&uid=10&role=" is 32 bytes long
    first = encrypted_profile_getter("bre@k.aes.ecb")
    forged = b"x" * (16 - len("email=")) + add_pkcs7_padding(b"admin", 16)
    second = encrypted_profile_getter(forged.decode("latin-1"))
    return first[:32] + second[16:32]


#    print(decrypt_profile(key, first[:32] + second[16:32]))
