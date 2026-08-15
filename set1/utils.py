from collections import defaultdict

letter_frequency_english = {
    "a": 0.082,
    "b": 0.015,
    "c": 0.028,
    "d": 0.043,
    "e": 0.127,
    "f": 0.023,
    "g": 0.020,
    "h": 0.061,
    "i": 0.067,
    "j": 0.002,
    "k": 0.008,
    "l": 0.040,
    "m": 0.024,
    "n": 0.067,
    "o": 0.075,
    "p": 0.019,
    "q": 0.001,
    "r": 0.059,
    "s": 0.063,
    "t": 0.091,
    "u": 0.028,
    "v": 0.010,
    "w": 0.024,
    "x": 0.002,
    "y": 0.020,
    "z": 0.001,
}


def plaintext_score(s: str) -> float:
    s_letter_frequency = defaultdict(float)
    letters_count = 0
    score = 0
    for c in s:
        if c.lower() in letter_frequency_english:
            s_letter_frequency[c.lower()] += 1
            letters_count += 1
        elif 32 <= ord(c) <= 126 or ord(c) == 10:
            score += 20 / len(s)
        else:
            return float("inf")
    for c in s_letter_frequency:
        s_letter_frequency[c] /= letters_count

    for c, f in letter_frequency_english.items():
        score += abs(s_letter_frequency[c] - f)
    return score


def hamming_distance(a: bytes, b: bytes) -> int:
    assert len(a) == len(b)
    distance = 0
    for ca, cb in zip(a, b):
        distance += (ca ^ cb).bit_count()
    return distance
