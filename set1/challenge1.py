base64Alphabet = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/"
)

def hexToBase64(hex: str) -> str:
    base64Str = ""
   
    for i in range(0, len(hex), 6):
        # First byte
        firstByte = int(hex[i:i+2], 16)
        firstB64 = firstByte >> 2
        base64Str += base64Alphabet[firstB64]
       
        # Second byte
        secondB64 = ((firstByte & 0b00000011) << 4)
        if i+4 <= len(hex):
            secondByte = int(hex[i+2:i+4], 16)
            secondB64 |= (secondByte  >> 4)
            base64Str += base64Alphabet[secondB64]
        else:
            base64Str += base64Alphabet[secondB64]
            base64Str += "=="
            break
        
        # Third byte
        thirdB64 = ((secondByte & 0b00001111) << 2)
        if i+6 <= len(hex):
            thirdByte = int(hex[i+4:i+6], 16)
            thirdB64 |= (thirdByte  >> 6)
            fourthB64 = thirdByte & 0b00111111
            base64Str += base64Alphabet[thirdB64]
            base64Str += base64Alphabet[fourthB64]
        else:
            base64Str += base64Alphabet[thirdB64]
            base64Str += "="

    return base64Str

testInput = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
testOutput = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
assert hexToBase64(testInput) == testOutput

