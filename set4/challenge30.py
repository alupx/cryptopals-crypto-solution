import struct
from collections.abc import Callable

from utils import mask32


def md4(message: bytes, state: list[int] | None = None) -> int:
    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    def rotate_left(x: int, n: int) -> int:
        return mask32((x << n) | (x >> (32 - n)))

    if state:
        assert len(state) == 4
    else:
        state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        message += get_md4_padding(len(message))
    chunks = [message[i * 64 : (i + 1) * 64] for i in range(len(message) // 64)]
    for chunk in chunks:
        words, regs = list(struct.unpack("<16I", chunk)), state.copy()

        shifts = [3, 7, 11, 19]
        for n in range(16):
            a, b, c, d = [x % 4 for x in range(-n, -n + 4)]
            word_index, shift = n, shifts[n % 4]
            value = regs[a] + F(regs[b], regs[c], regs[d]) + words[word_index]
            regs[a] = rotate_left(mask32(value), shift)

        shifts = [3, 5, 9, 13]
        for n in range(16):
            a, b, c, d = [x % 4 for x in range(-n, -n + 4)]
            word_index, shift = n % 4 * 4 + n // 4, shifts[n % 4]
            value = (
                regs[a] + G(regs[b], regs[c], regs[d]) + words[word_index] + 0x5A827999
            )
            regs[a] = rotate_left(mask32(value), shift)

        shifts = [3, 9, 11, 15]
        word_order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for n in range(16):
            a, b, c, d = [x % 4 for x in range(-n, -n + 4)]
            word_index, shift = word_order[n], shifts[n % 4]
            value = (
                regs[a] + H(regs[b], regs[c], regs[d]) + words[word_index] + 0x6ED9EBA1
            )
            regs[a] = rotate_left(mask32(value), shift)
        state = [mask32(s + r) for s, r in zip(state, regs)]
    return int.from_bytes(struct.pack("<4I", *state), "big")


def md4_mac(key: bytes, message: bytes) -> int:
    return md4(key + message)


def get_md4_final_state(digest: int) -> list[int]:
    return list(struct.unpack("<4I", digest.to_bytes(16, "big")))


def get_md4_padding(message_len: int) -> bytes:
    padding = b"\x80"
    while (message_len + len(padding) + 8) % 64 > 0:
        padding += b"\x00"
    padding += (message_len * 8).to_bytes(8, "little")
    return padding


def verify_md4_mac(message: bytes, secret: bytes, mac: int) -> bool:
    return md4_mac(secret, message) == mac


def md4_mac_length_extension(
    message: bytes,
    extension: bytes,
    mac: int,
    verify: Callable[[bytes, int], bool],
    max_key_len: int = 64,
) -> tuple[bytes, int]:
    state = get_md4_final_state(mac)
    message_len = len(message)
    extension_len = len(extension)
    for key_len in range(max_key_len + 1):
        glue_padding = get_md4_padding(key_len + message_len)
        final_padding = get_md4_padding(
            key_len + message_len + len(glue_padding) + extension_len
        )
        extended_mac = md4(extension + final_padding, state)
        extended_message = message + glue_padding + extension
        if verify(extended_message, extended_mac):
            return (extended_message, extended_mac)
    return (b"", -1)
