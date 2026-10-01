from collections.abc import Callable
from time import perf_counter, sleep

from set4.challenge28 import sha1


def hmac_sha1(key: bytes, message: bytes) -> int:
    if len(key) > 64:
        key = sha1(key).to_bytes(20, "big")
    key = key + bytes([0]) * (64 - len(key))

    o_key_pad = bytes([0x5C ^ k for k in key])
    i_key_pad = bytes([0x36 ^ k for k in key])

    return sha1(o_key_pad + sha1(i_key_pad + message).to_bytes(20, "big"))


def slow_compare(a: bytes, b: bytes, delay_ms: int) -> bool:
    for aa, bb in zip(a, b):
        sleep(delay_ms / 1000)
        if aa != bb:
            return False
    return True


def get_delay(f: Callable[[], bool]) -> tuple[bool, int]:
    tic = perf_counter()
    result = f()
    toc = perf_counter()
    return result, round((toc - tic) * 1000)


def guess_hmac(check: Callable[[bytes], bool], n: int, delay: int) -> bytes:
    guess = bytearray(20)
    for i in range(n):
        while True:
            result, execution_time = get_delay(lambda: check(bytes(guess)))
            if result:
                return bytes(guess)
            if execution_time >= (i + 1) * delay + delay // 2:
                break
            guess[i] += 1
    return bytes(guess)
