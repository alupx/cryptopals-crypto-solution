from hashlib import sha256
from secrets import randbelow, randbits
from typing import final


def to_bytes(x: int | str) -> bytes:
    if isinstance(x, str):
        return x.encode()
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


def sha256_int(a: int | str, b: int | str = "") -> int:
    return int.from_bytes(sha256(to_bytes(a) + to_bytes(b)).digest(), "big")


def hmac_sha256(key: int, message: int) -> bytes:
    key_bytes = to_bytes(key)
    if len(key_bytes) > 64:
        key_bytes = sha256(key_bytes).digest()
    key_bytes = key_bytes + bytes([0]) * (64 - len(key_bytes))
    message_bytes = to_bytes(message)
    o_key_pad = bytes([0x5C ^ k for k in key_bytes])
    i_key_pad = bytes([0x36 ^ k for k in key_bytes])
    return sha256(o_key_pad + sha256(i_key_pad + message_bytes).digest()).digest()


class Srp:
    N: int
    g: int
    k: int
    salt: int
    priv: int
    pub: int
    u: int
    S: int
    K: int


@final
class SrpServer(Srp):
    v: int

    def __init__(self, N: int, g: int, k: int, password: str):
        self.salt = randbits(2048)
        x = sha256_int(self.salt, password)
        self.v = pow(g, x, N)
        self.priv = randbelow(N - 1) + 1
        self.pub = (k * self.v + pow(g, self.priv, N)) % N
        self.N = N
        self.k = k
        self.g = g

    def check_validation_hmac(self, client_pub: int, validation: bytes) -> bool:
        self.u = sha256_int(client_pub, self.pub)
        self.S = pow(client_pub * pow(self.v, self.u, self.N), self.priv, self.N)
        self.K = sha256_int(self.S)
        # Not constant-time: a real implementation should use hmac.compare_digest
        return validation == hmac_sha256(self.K, self.salt)


@final
class SrpClient(Srp):
    password: str

    def __init__(self, N: int, g: int, k: int, password: str, salt: int):
        self.password = password
        self.salt = salt
        self.priv = randbelow(N - 1) + 1
        self.pub = pow(g, self.priv, N)
        self.N = N
        self.k = k
        self.g = g

    def get_validation_hmac(self, server_pub: int) -> bytes:
        x = sha256_int(self.salt, self.password)
        self.u = sha256_int(self.pub, server_pub)
        base = server_pub - self.k * pow(self.g, x, self.N)
        self.S = pow(base, self.priv + self.u * x, self.N)
        self.K = sha256_int(self.S)
        return hmac_sha256(self.K, self.salt)
