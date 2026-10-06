from typing import overload

from sympy import randprime

from set5.challenge36 import to_bytes


def invmod(a: int, m: int) -> int:
    # Returns x such that (a * x) % m = 1
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    x = old_s
    while x < 0:
        x += m
    return x


def rsa_keygen(e: int) -> tuple[tuple[int, int], tuple[int, int]]:
    et = 0
    while et % e == 0:
        p, q = randprime(2**1023, 2**1024), randprime(2**1023, 2**1024)
        et = (p - 1) * (q - 1)
    n = p * q
    d = invmod(e, et)
    return (d, n), (e, n)


@overload
def rsa_process(data: int, key: tuple[int, int]) -> int: ...
@overload
def rsa_process(data: bytes, key: tuple[int, int]) -> bytes: ...
def rsa_process(data: int | bytes, key: tuple[int, int]) -> int | bytes:
    is_bytes = isinstance(data, bytes)
    if is_bytes:
        data_int = int("0x" + data.hex(), 16)
    else:
        data_int = data
    if data_int >= key[1]:
        raise ValueError("Data to process should be smaller than n")
    processed_int = pow(data_int, key[0], key[1])
    if is_bytes:
        return to_bytes(processed_int)
    else:
        return processed_int
