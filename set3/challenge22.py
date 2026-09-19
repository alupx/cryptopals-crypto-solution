from random import randint
from time import sleep, time

from .challenge21 import MT19937


def bruteforce_MT19937(target: int, start_time: int) -> int:
    seed = start_time
    while True:
        MT = MT19937(seed)
        if MT.rand() == target:
            return seed
        seed -= 1


def get_time_seed_32() -> int:
    return int(time() * 1000) & 0xFFFFFFFF


if __name__ == "__main__":
    # Run as `python -m set3.challenge22` from the repo root (relative import needs a package context).
    print("Waiting for a random number of seconds...")
    sleep(randint(1, 10))
    seed = get_time_seed_32()
    sleep(randint(1, 10))

    print("Bruteforcing the seed...")
    first_output = MT19937(seed).rand()
    cracked = bruteforce_MT19937(first_output, get_time_seed_32())
    assert seed == cracked
    print(f"Seed: {seed}")
