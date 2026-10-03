from set5.challenge36 import SrpServer, hmac_sha256, sha256_int


def break_srp_with_zero_key(s: SrpServer):
    salt = s.salt
    K = sha256_int(0)
    h = hmac_sha256(K, salt)
    return h
