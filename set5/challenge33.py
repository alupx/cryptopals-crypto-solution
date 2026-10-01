from random import randint
from typing import final


@final
class diffie_hellman:
    def __init__(self, p: int, g: int):
        assert p.bit_length() <= 4096
        self.p = p
        self.g = g

    def _modexp(self, b: int, e: int, m: int) -> int:
        ans = 1
        curr = b % m
        for i in range(4096):
            if e & 1 == 1:
                ans = (ans * curr) % m
            curr = (curr * curr) % m
            e >>= 1
            if e == 0:
                break
        return ans

    def get_keys(self) -> tuple[int, int]:
        a = randint(1, self.p - 1)
        A = self._modexp(self.g, a, self.p)
        return a, A

    def get_session_key(self, a: int, B: int) -> int:
        return self._modexp(B, a, self.p)
