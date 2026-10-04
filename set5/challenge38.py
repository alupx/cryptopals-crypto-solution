from secrets import randbelow, randbits
from typing import final

from set5.challenge36 import Srp, hmac_sha256, sha256_int


@final
class SrpServerSimplified(Srp):
    v: int
    u: int

    def __init__(self, N: int, g: int, k: int, password: str):
        self.salt = randbits(2048)
        self.u = randbits(128)
        x = sha256_int(self.salt, password)
        self.v = pow(g, x, N)
        self.priv = randbelow(N - 1) + 1
        self.pub = pow(g, self.priv, N)
        self.N, self.K, self.g = N, k, g

    def check_validation_hmac(self, client_pub: int, validation: bytes) -> bool:
        self.S = pow(client_pub * pow(self.v, self.u, self.N), self.priv, self.N)
        self.K = sha256_int(self.S)
        # A real implementation should have a constant time comparison
        return validation == hmac_sha256(self.K, self.salt)


@final
class SrpClientSimplified(Srp):
    password: str

    def __init__(self, N: int, g: int, k: int, password: str, salt: int):
        self.password = password
        self.salt = salt
        self.priv = randbelow(N - 1) + 1
        self.pub = pow(g, self.priv, N)
        self.N, self.K, self.g = N, k, g

    def get_validation_hmac(self, server_pub: int, server_u: int) -> bytes:
        x = sha256_int(self.salt, self.password)
        self.S = pow(server_pub, self.priv + server_u * x, self.N)
        self.K = sha256_int(self.S)
        return hmac_sha256(self.K, self.salt)


def check_password(
    password: str, server: SrpServerSimplified, client_pub: int, target_hmac: bytes
) -> bool:
    x = sha256_int(server.salt, password)
    v = pow(server.g, x, server.N)
    S = pow(client_pub * pow(v, server.u, server.N), server.priv, server.N)
    K = sha256_int(S)
    h = hmac_sha256(K, server.salt)
    return h == target_hmac


def do_dictionary_attack_simplified_srp(
    password_dict: list[str],
    server: SrpServerSimplified,
    client_pub: int,
    target_hmac: bytes,
) -> str:
    # Here the attack assumes that we have access to server, which is not really
    # the case. But this is conceptually equivalent to being the MITM.
    for password in password_dict:
        if check_password(password, server, client_pub, target_hmac):
            return password
    return ""
