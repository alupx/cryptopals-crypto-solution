import base64
import unittest

from challenge1 import binary_to_base64
from challenge2 import fixed_byte_xor
from challenge3 import decrypt_english_single_byte_xor
from challenge4 import find_and_decrypt_single_byte_xor_in_file
from challenge5 import encrypt_repeating_key_xor
from challenge6 import decrypt_english_multi_byte_xor, guess_key_length
from challenge8 import aes128_ecb_likelyhood
from utils import hamming_distance


class TestUtils(unittest.TestCase):
    def test_hamming_distance(self):
        self.assertEqual(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37)


class TestChallenges(unittest.TestCase):
    def setUp(self):
        b64data = ""
        with open("data/6.txt", "r") as file:
            for line in file:
                b64data += line.strip()
        self.challenge6_cryptotext = base64.b64decode(b64data)

    def test_challenge1(self):
        self.assertEqual(
            binary_to_base64(
                bytes.fromhex(
                    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
                )
            ),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        )

        self.assertEqual(
            binary_to_base64(bytes.fromhex("4242")),
            "QkI=",
        )

        self.assertEqual(
            binary_to_base64(bytes.fromhex("42424242")),
            "QkJCQg==",
        )

    def test_challenge2(self):
        plaintext = bytes.fromhex("1c0111001f010100061a024b53535009181c")
        key = bytes.fromhex("686974207468652062756c6c277320657965")
        expected_output = "746865206b696420646f6e277420706c6179"
        self.assertEqual(fixed_byte_xor(plaintext, key).hex(), expected_output)

    def test_challenge3(self):
        testInput = (
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )
        test_output = "Cooking MC's like a pound of bacon"
        _, _, plaintext = decrypt_english_single_byte_xor(bytes.fromhex(testInput))
        self.assertEqual(plaintext, test_output)

    def test_challenge4(self):
        input_file = "data/4.txt"
        test_output = "Now that the party is jumping\n"
        self.assertEqual(
            find_and_decrypt_single_byte_xor_in_file(input_file), test_output
        )

    def test_challenge5(self):
        plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key = b"ICE"
        cryptotext = encrypt_repeating_key_xor(plaintext, key)
        expected_cryptotext = (
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
            "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        )
        self.assertEqual(cryptotext.hex(), expected_cryptotext)

    def test_challenge6_key_len(self):
        guesses = guess_key_length(self.challenge6_cryptotext)
        # test that the correct answer is among first 5 guesses
        most_likely_keylens = [key_len for key_len, _ in guesses[:6]]
        self.assertIn(116, most_likely_keylens)

    def test_challenge6_key(self):
        key, _ = decrypt_english_multi_byte_xor(self.challenge6_cryptotext, 116)
        expected_key = b"Terminator X: Bring the noiseTerminator X: Bring the noiseTerminator X: Bring the noiseTerminator X: Bring the noise"
        wrong_bytes = sum(key[i] != expected_key[i] for i in range(116))
        self.assertTrue(wrong_bytes < 10)

    def test_challenge8(self):
        correct_answer = 132
        with open("data/8.txt", "r") as file:
            likelyhoods = []
            for line in file:
                data = bytes.fromhex(line)
                likelyhoods.append(aes128_ecb_likelyhood(data))
        self.assertTrue(likelyhoods[correct_answer] > 0)
        self.assertEqual(sum(likelyhoods), likelyhoods[correct_answer])


if __name__ == "__main__":
    unittest.main()
