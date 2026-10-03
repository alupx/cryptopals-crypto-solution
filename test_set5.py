import unittest
from random import randbytes

from set5.challenge33 import diffie_hellman
from set5.challenge34 import dh_echo_bot, dh_party, man_in_the_middle
from set5.challenge35 import man_in_the_middle_inject_g
from set5.challenge36 import SrpClient, SrpServer


def _hex(s: str) -> int:
    return int(s.replace(" ", ""), 16)


# RFC 7919 groups, all with generator g = 2.
FFDHE2048 = _hex(
    "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
    "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
    "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
    "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
    "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
    "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
    "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
    "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
    "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
    "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
    "886B4238 61285C97 FFFFFFFF FFFFFFFF"
)

FFDHE3072 = _hex(
    "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
    "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
    "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
    "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
    "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
    "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
    "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
    "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
    "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
    "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
    "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
    "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
    "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
    "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
    "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
    "3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF"
)

FFDHE4096 = _hex(
    "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
    "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
    "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
    "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
    "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
    "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
    "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
    "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
    "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
    "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
    "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
    "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
    "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
    "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
    "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
    "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
    "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
    "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
    "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
    "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
    "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E655F6A"
    "FFFFFFFF FFFFFFFF"
)


class TestChallenge33(unittest.TestCase):
    def _check_exchange(self, p: int, g: int):
        DH = diffie_hellman(p, g)
        a, A = DH.get_keys()
        b, B = DH.get_keys()
        self.assertEqual(A, pow(g, a, p))
        self.assertEqual(B, pow(g, b, p))
        self.assertEqual(DH.get_session_key(a, B), DH.get_session_key(b, A))

    def test_diffie_hellman_ffdhe2048(self):
        self._check_exchange(FFDHE2048, 2)

    def test_diffie_hellman_ffdhe3072(self):
        self._check_exchange(FFDHE3072, 2)

    def test_diffie_hellman_ffdhe4096(self):
        self._check_exchange(FFDHE4096, 2)


class TestChallenge34(unittest.TestCase):
    def test_echo(self):
        p, g = FFDHE2048, 2
        alice, bot = dh_party(p, g), dh_echo_bot(p, g)
        A, B = alice.get_public_key(), bot.get_public_key()
        _ = alice.generate_session_key(B)
        _ = bot.generate_session_key(A)
        message = randbytes(300)
        alice_to_bot = alice.encrypt(message)
        bot_to_alice = bot.echo(alice_to_bot)
        self.assertEqual(alice.decrypt(bot_to_alice), message)

    def test_man_in_the_middle(self):
        p, g = FFDHE2048, 2
        alice, bot = dh_party(p, g), dh_echo_bot(p, g)
        message, a, b = man_in_the_middle(alice, bot, p)
        self.assertEqual(a, message)
        self.assertEqual(b, message)


class TestChallenge35(unittest.TestCase):
    def _check_g_injection(self, p: int, g: int):
        alice, bot = dh_party(p, g), dh_echo_bot(p, g)
        message, a, b = man_in_the_middle_inject_g(alice, bot, p, g)
        self.assertEqual(a, message)
        self.assertEqual(b, message)

    def test_man_in_the_middle_g_1(self):
        for p in [FFDHE2048, FFDHE3072, FFDHE4096]:
            self._check_g_injection(p, 1)

    def test_man_in_the_middle_g_p(self):
        for p in [FFDHE2048, FFDHE3072, FFDHE4096]:
            self._check_g_injection(p, p)

    def test_man_in_the_middle_g_p_minus_1(self):
        for p in [FFDHE2048, FFDHE3072, FFDHE4096]:
            self._check_g_injection(p, p - 1)


class TestChallenge36(unittest.TestCase):
    def _check_client_server(
        self, N: int, server_password: str, client_password: str
    ) -> bool:
        g = 2
        k = 3
        s = SrpServer(N, g, k, server_password)
        salt = s.salt
        c = SrpClient(N, g, k, client_password, salt)
        A, B = c.pub, s.pub
        h = c.get_validation_hmac(B)
        return s.check_validation_hmac(A, h)

    def test_client_server_handshake(self):
        password = "y3lloWsUbm@r1nE!"
        for N in [FFDHE2048, FFDHE3072, FFDHE4096]:
            self.assertTrue(self._check_client_server(N, password, password))

    def test_client_server_wrong_password(self):
        for N in [FFDHE2048, FFDHE3072, FFDHE4096]:
            self.assertFalse(
                self._check_client_server(N, "y3lloWsUbm@r1nE!", "y3lloWsUbm@r1nE?")
            )


if __name__ == "__main__":
    unittest.main()
