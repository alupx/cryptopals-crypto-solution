from collections import deque


class MT19937:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253
    umask = 0x80000000
    lmask = 0x7FFFFFFF

    def __init__(self, seed):
        assert (seed >> self.w) == 0
        initial_x = [seed]
        for i in range(1, self.n):
            seed = self.f * (seed ^ (seed >> (self.w - 2))) + i
            seed &= 0xFFFFFFFF
            initial_x.append(seed)
        self.x = deque(initial_x)

    @classmethod
    def from_state(cls, state: list[int]) -> "MT19937":
        """Build an instance directly from a state vector (skips seeding)."""
        assert len(state) == cls.n
        obj = cls.__new__(cls)
        obj.x = deque(state)
        return obj

    def rand(self):
        x = (self.x[0] & self.umask) | (self.x[1] & self.lmask)
        xA = x >> 1
        if x & 1:
            xA ^= self.a
        new_x = (self.x[self.m] ^ xA) & 0xFFFFFFFF

        self.x.append(new_x)
        self.x.popleft()

        y = new_x ^ ((new_x >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y &= 0xFFFFFFFF
        z = y ^ (y >> self.l)
        return z
