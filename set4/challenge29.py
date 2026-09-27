from collections.abc import Callable

from utils import mask32

from .challenge28 import sha1, sha1_mac


def get_sha1_final_state(digest: int) -> list[int]:
    state = []
    for i in range(5):
        state.append(mask32(digest >> ((4 - i) * 32)))
    return state


def get_sha1_padding(message_len: int) -> bytes:
    padding = b"\x80"
    while (message_len + len(padding) + 8) % 64 > 0:
        padding += b"\x00"
    padding += (message_len * 8).to_bytes(8, "big")
    return padding


def verify_sha1_mac(message: bytes, secret: bytes, mac: int) -> bool:
    return sha1_mac(secret, message) == mac


def sha1_mac_length_extension(
    message: bytes,
    extension: bytes,
    mac: int,
    verify: Callable[[bytes, int], bool],
    max_key_len: int = 64,
) -> tuple[bytes, int]:
    state = get_sha1_final_state(mac)
    message_len = len(message)
    extension_len = len(extension)
    for key_len in range(max_key_len + 1):
        glue_padding = get_sha1_padding(key_len + message_len)
        final_padding = get_sha1_padding(
            key_len + message_len + len(glue_padding) + extension_len
        )
        extended_mac = sha1(extension + final_padding, state)
        extended_message = message + glue_padding + extension
        if verify(extended_message, extended_mac):
            return (extended_message, extended_mac)
    return (b"", -1)
