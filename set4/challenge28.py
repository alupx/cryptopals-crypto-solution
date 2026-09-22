def rotateLeft(x: int, n: int) -> int:
    return mask32((x << n) | (x >> (32 - n)))


def mask32(x: int) -> int:
    return x & 0xFFFFFFFF


def SHA1(message: bytes) -> int:
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    message_len = len(message) * 8
    message += b"\x80"
    while (len(message) + 8) % 64 > 0:
        message += b"\x00"
    message += message_len.to_bytes(8, "big")
    chunks = [message[i * 64 : (i + 1) * 64] for i in range(len(message) // 64)]
    for chunk in chunks:
        a, b, c, d, e = h0, h1, h2, h3, h4
        words = [int.from_bytes(chunk[i * 4 : (i + 1) * 4], "big") for i in range(16)]
        for _ in range(64):
            words.append(rotateLeft(words[-3] ^ words[-8] ^ words[-14] ^ words[-16], 1))
        for i in range(80):
            if i < 20:
                f = mask32((b & c) | (~b & d))
                k = 0x5A827999
            elif i < 40:
                f = mask32(b ^ c ^ d)
                k = 0x6ED9EBA1
            elif i < 60:
                f = mask32((b & c) | (b & d) | (c & d))
                k = 0x8F1BBCDC
            else:
                f = mask32(b ^ c ^ d)
                k = 0xCA62C1D6
            temp = mask32(rotateLeft(a, 5) + f + e + k + words[i])
            e, d, c, b, a = mask32(d), mask32(c), rotateLeft(b, 30), mask32(a), temp
        h0, h1, h2, h3, h4 = (
            mask32(h0 + a),
            mask32(h1 + b),
            mask32(h2 + c),
            mask32(h3 + d),
            mask32(h4 + e),
        )
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh


def SHA1MAC(key: bytes, message: bytes):
    return SHA1(key + message)
