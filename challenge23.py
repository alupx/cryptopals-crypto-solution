from collections.abc import Callable

from challenge21 import MT19937

# All inverse functions here assume 32 bits


def get_bit(x: int, n: int) -> int:
    """Return bit n (0 = least significant) of x."""
    return 1 if (x & (1 << n) > 0) else 0


def invert_xor_rshift_and(y: int, n: int, a: int) -> int:
    """Invert y = x ^ ((x >> n) & a) and return x."""
    assert n > 0
    mask = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
    x = y & mask
    for i in range(31 - n, -1, -1):
        x |= (get_bit(y, i) ^ (get_bit(x, i + n) & get_bit(a, i))) << i
    return x


def invert_xor_lshift_and(y: int, n: int, a: int) -> int:
    """Invert y = x ^ ((x << n) & a) and return x."""
    assert n > 0
    mask = 0xFFFFFFFF >> (32 - n)
    x = y & mask
    for i in range(n, 32):
        x |= (get_bit(y, i) ^ (get_bit(x, i - n) & get_bit(a, i))) << i
    return x


def untemper_MT19937(z: int) -> int:
    y = invert_xor_rshift_and(z, MT19937.l, 0xFFFFFFFF)
    y = invert_xor_lshift_and(y, MT19937.t, MT19937.c)
    y = invert_xor_lshift_and(y, MT19937.s, MT19937.b)
    y = invert_xor_rshift_and(y, MT19937.u, MT19937.d)
    return y


def xor_rshift_and(x: int, n: int, a: int) -> int:
    return x ^ ((x >> n) & a)


def xor_lshift_and(x: int, n: int, a: int) -> int:
    return x ^ ((x << n) & a)


def clone_MT19937_from_output(rand: Callable[[], int]) -> MT19937:
    state = [untemper_MT19937(rand()) for _ in range(MT19937.n)]
    return MT19937.from_state(state)
