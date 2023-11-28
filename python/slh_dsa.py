"""
SLH_DSA context class
"""
import hashlib
import hmac
from utils import cdiv, toByte

ALLOWED_PSETS = [
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-256f"]

SHA256_DIGEST_LEN = 32
SHA512_DIGEST_LEN = 64

def sha256(m: bytes) -> bytes:
    """SHA256 wrapper function"""
    h = hashlib.sha256()
    h.update(m)
    return h.digest()

def sha512(m: bytes) -> bytes:
    """SHA256 wrapper function"""
    h = hashlib.sha512()
    h.update(m)
    return h.digest()

def mgf1_sha256(seed: bytes, mlen: int) -> bytes:
    """MGF1 mask generation function with SHA256.
       See NIST SP 800-56B rev 2 section 7.2.2.2."""
    hash_len = SHA256_DIGEST_LEN
    t = b""
    for c in range(0, cdiv(mlen, hash_len)):
        t += sha256(seed + toByte(c, 4))
    return t[:mlen]

def mgf1_sha512(seed: bytes, mlen: int) -> bytes:
    """MGF1 mask generation function with SHA256.
       See NIST SP 800-56B rev 2 section 7.2.2.2."""
    hash_len = SHA512_DIGEST_LEN
    t = b""
    for c in range(0, cdiv(mlen, hash_len)):
        t += sha512(seed + toByte(c, 4))
    return t[:mlen]

def hmac_sha256(k: bytes, msg: bytes) -> bytes:
    """HMAC-SHA-256 wrapper function"""
    return hmac.digest(k, msg, hashlib.sha256)

def hmac_sha512(k: bytes, msg: bytes) -> bytes:
    """HMAC-SHA-512 wrapper function"""
    return hmac.digest(k, msg, hashlib.sha512)

class SLHDSA:
    """Context class for SLH-DSA"""
    def __init__(self, pset: str):
        assert pset in ALLOWED_PSETS

        if pset == "SLH-DSA-SHA2-128s" or pset == "SLH-DSA-SHAKE-128s":
            self.n = 16
            self.h = 63
            self.d = 7
            self.hp = 9
            self.a = 12
            self.k = 14
            self.lg_w = 4
            self.m = 30
            self.sec_lvl = 1
            self.pk_bytes = 32
            self.sig_bytes = 7856
        if pset == "SLH-DSA-SHA2-128f" or pset == "SLH-DSA-SHAKE-128f":
            self.n = 16
            self.h = 66
            self.d = 22
            self.hp = 3
            self.a = 6
            self.k = 33
            self.lg_w = 4
            self.m = 34
            self.sec_lvl = 1
            self.pk_bytes = 32
            self.sig_bytes = 17088
        if pset == "SLH-DSA-SHA2-192s" or pset == "SLH-DSA-SHAKE-192s":
            self.n = 24
            self.h = 63
            self.d = 7
            self.hp = 9
            self.a = 14
            self.k = 17
            self.lg_w = 4
            self.m = 39
            self.sec_lvl = 3
            self.pk_bytes = 48
            self.sig_bytes = 16224
        if pset == "SLH-DSA-SHA2-192f" or pset == "SLH-DSA-SHAKE-192f":
            self.n = 24
            self.h = 66
            self.d = 22
            self.hp = 3
            self.a = 8
            self.k = 33
            self.lg_w = 4
            self.m = 42
            self.sec_lvl = 3
            self.pk_bytes = 48
            self.sig_bytes = 35664
        if pset == "SLH-DSA-SHA2-256s" or pset == "SLH-DSA-SHAKE-256s":
            self.n = 32
            self.h = 64
            self.d = 8
            self.hp = 8
            self.a = 14
            self.k = 22
            self.lg_w = 4
            self.m = 47
            self.sec_lvl = 5
            self.pk_bytes = 64
            self.sig_bytes = 29792
        if pset == "SLH-DSA-SHA2-256f" or pset == "SLH-DSA-SHAKE-256f":
            self.n = 32
            self.h = 68
            self.d = 17
            self.hp = 4
            self.a = 9
            self.k = 35
            self.lg_w = 4
            self.m = 49
            self.sec_lvl = 5
            self.pk_bytes = 64
            self.sig_bytes = 49856

        if "SHAKE" in pset:
            self.shake = True
        else:
            self.shake = False
            if "-128" in pset:
                self.seccat = 1
            elif "-192" in pset:
                self.seccat = 3
            else:
                self.seccat = 5

        # Setting WOTS+ constants, assuming lg_w == 4
        self.wotsp_w = 16
        self.wotsp_len1 = 2*self.n
        self.wotsp_len2 = 3
        self.wotsp_len = 2*self.n + 3

    def h_msg(self, R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes) -> bytes:
        """Compute the H_{msg} function"""
        if self.shake:
            h = hashlib.shake_256()
            h.update(R + pk_seed + pk_root + M)
            return h.digest(self.m)
        else:
            if self.seccat == 1:
                return mgf1_sha256(R + pk_seed + sha256(R + pk_seed + pk_root + M), self.m)
            else:
                return mgf1_sha512(R + pk_seed + sha512(R + pk_seed + pk_root + M), self.m)

    def prf(self, pk_seed: bytes, sk_seed: bytes, adrs: bytes) -> bytes:
        """Compute the PRF function"""
        if self.shake:
            h = hashlib.shake_256()
            h.update(pk_seed + adrs + sk_seed)
            return h.digest(self.n)
        else:
            adrsc = adrs[3:4] + adrs[8:16] + adrs[19:20] + adrs[20:32]
            if self.seccat == 1:
                return sha256(pk_seed + toByte(0,64-self.n) + adrsc + sk_seed)[:self.n]
            else:
                return sha256(pk_seed + toByte(0,64-self.n) + adrsc + sk_seed)[:self.n]

    def prf_msg(self, sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
        """Compute the PRF_{msg} function"""
        if self.shake:
            h = hashlib.shake_256()
            h.update(sk_prf + opt_rand + M)
            return h.digest(self.n)
        else:
            if self.seccat == 1:
                return hmac_sha256(sk_prf, opt_rand + M)[:self.n]
            else:
                return hmac_sha512(sk_prf, opt_rand + M)[:self.n]

    def f(self, pk_seed: bytes, adrs: bytes, M1: bytes) -> bytes:
        """Compute the F function"""
        if self.shake:
            h = hashlib.shake_256()
            h.update(pk_seed + adrs + M1)
            return h.digest(self.n)
        else:
            adrsc = adrs[3:4] + adrs[8:16] + adrs[19:20] + adrs[20:32]
            if self.seccat == 1:
                return sha256(pk_seed + toByte(0,64-self.n) + adrsc + M1)[:self.n]
            else:
                return sha256(pk_seed + toByte(0,64-self.n) + adrsc + M1)[:self.n]

    def hf(self, pk_seed: bytes, adrs: bytes, M2: bytes) -> bytes:
        """Compute the H function"""
        if self.shake:
            h = hashlib.shake_256()
            h.update(pk_seed + adrs + M2)
            return h.digest(self.n)
        else:
            adrsc = adrs[3:4] + adrs[8:16] + adrs[19:20] + adrs[20:32]
            if self.seccat == 1:
                return sha256(pk_seed + toByte(0,64-self.n) + adrsc + M2)[:self.n]
            else:
                return sha512(pk_seed + toByte(0,128-self.n) + adrsc + M2)[:self.n]

    def t(self, ell: int, pk_seed: bytes, adrs: bytes, M_ell: bytes) -> bytes:
        """Compute the T_{\\ell} function"""
        assert len(M_ell) == self.n*ell
        if self.shake:
            h = hashlib.shake_256()
            h.update(pk_seed + adrs + M_ell)
            return h.digest(self.n)
        else:
            adrsc = adrs[3:4] + adrs[8:16] + adrs[19:20] + adrs[20:32]
            if self.seccat == 1:
                return sha256(pk_seed + toByte(0,64-self.n) + adrsc + M_ell)[:self.n]
            else:
                return sha512(pk_seed + toByte(0,128-self.n) + adrsc + M_ell)[:self.n]

