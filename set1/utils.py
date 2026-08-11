hexCharacters = "0123456789abcdef"

def validateHexString(s: str) -> bool:
    if len(s) % 2: return False;
    return all(c in hexCharacters for c in s)

