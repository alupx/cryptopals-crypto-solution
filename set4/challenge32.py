from collections.abc import Callable
from statistics import median
from time import perf_counter


def get_delay_fast(f: Callable[[], bool]) -> tuple[bool, float]:
    times = []
    for _ in range(10):
        tic = perf_counter()
        result = f()
        toc = perf_counter()
        times.append(toc - tic)
    return result, median(times)


def guess_hmac_fast(check: Callable[[bytes], bool], n: int) -> bytes:
    guess = bytearray(20)
    for i in range(n):
        best_guess = 0
        best_time = float(0)
        while True:
            result, execution_time = get_delay_fast(lambda: check(bytes(guess)))
            if result:
                return bytes(guess)
            if execution_time > best_time:
                best_time = execution_time
                best_guess = guess[i]
            if guess[i] == 255:
                guess[i] = best_guess
                break
            guess[i] += 1
    return bytes(guess)
