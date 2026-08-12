englishCharacters = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 .,'?!@"
)


def plaintext_score(s: str) -> float:
    return sum(c in englishCharacters for c in s) / len(s)
