from collections.abc import Callable
from math import prod

from set5.challenge39 import invmod, rsa_keygen, rsa_process


def get_ciphertext(data: int, k: int) -> tuple[int, int]:
    _, public_key = rsa_keygen(k)
    return (public_key[1], rsa_process(data, public_key))


def sunzi_theorem(cs: list[int], ns: list[int]) -> int:
    assert len(cs) == len(ns)
    ms = prod(ns)
    mss = [ms // n for n in ns]
    acc = sum(c * m * invmod(m, n) for c, m, n in zip(cs, mss, ns))
    return acc % ms


def integer_root(x: int, n: int) -> int:
    if x <= 1 or n == 1:
        return x

    right = 2
    while right**n < x:
        right *= 2
    left = right // 2

    while left < right:
        middle = (left + right + 1) // 2
        y = middle**n
        if y < x:
            left = middle
        elif y > x:
            right = middle - 1
        else:
            return middle
    return left


def rsa_broadcast_attack(getter: Callable[[], tuple[int, int]], e: int) -> int:
    """
    `e` is the RSA public exponent. In this attack we assume to be able to
    call the server repeatedly to fetch different ciphertext/modulus pairs.
    The attack requires `e` calls to the server to succeed.
    """
    cs = []
    ns = []
    for _ in range(e):
        n, c = getter()
        cs.append(c)
        ns.append(n)
    return integer_root(sunzi_theorem(cs, ns), e)
