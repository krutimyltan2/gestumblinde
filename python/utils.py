"""
Utilities from Section 4.4: "Arrays, Byte Strings, and Integers"
and some additional ones.
"""

import sys

def cdiv(n, k):
    """Compute ceil(n/k)"""
    return (n + k - 1)//k

def toInt(X: bytes, n: int) -> int:
    """Convert a byte string to an integer"""
    assert len(X) == n
    return int.from_bytes(X, byteorder="big")

def toByte(x: int, n: int) -> bytes:
    """Convert an integer to a byte string"""
    assert n >= 0
    x %= (2**(8*n))
    return x.to_bytes(length=n, byteorder="big")

def base_2b(X: bytes, b: int, out_len: int) -> list[int]:
    """Compute the base 2^b representation of X"""
    assert b > 0
    assert out_len >= 0
    n = len(X)
    assert n >= cdiv(out_len*b, 8)
    in_ = 0
    bits = 0
    total = 0

    baseb = []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + X[in_]
            in_ += 1
            bits += 8
        bits -= b
        baseb.append((total >> bits) % (2**b))
    assert len(baseb) == out_len
    return baseb
