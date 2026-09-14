from utils import plaintext_score


def break_fixed_nonce(ciphertexts: list[bytes]):
    max_len = max(len(ct) for ct in ciphertexts)
    plaintexts = [""] * len(ciphertexts)
    for i in range(max_len):
        best_score, best_key = float("inf"), 0
        for key in range(256):
            characters = []
            for ct in ciphertexts:
                if i < len(ct):
                    characters.append(bytes([ct[i] ^ key]))
            if not all(ch.isascii() for ch in characters):
                continue
            score = plaintext_score(
                "".join(ch.decode() for ch in characters),
                blacklist=["/", "%", "+"],
                numeric=False,
            )
            if score < best_score:
                best_score = score
                best_key = key
        for j in range(len(ciphertexts)):
            if len(ciphertexts[j]) > i:
                plaintexts[j] += chr(ciphertexts[j][i] ^ best_key)
    return plaintexts
