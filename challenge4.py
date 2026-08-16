from challenge3 import decrypt_english_single_byte_xor


def find_and_decrypt_single_byte_xor_in_file(filename: str) -> str:
    best_score = float("inf")
    with open(filename, "r") as file:
        for line in file:
            score, _, plaintext = decrypt_english_single_byte_xor(
                bytes.fromhex(line.strip())
            )
            if score < best_score:
                best_text = plaintext
                best_score = score
    return best_text
