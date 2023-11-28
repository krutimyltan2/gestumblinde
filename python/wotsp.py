"""
From Section 5.
"""

from address import Address, AddressType
from slh_dsa import SLHDSA
from utils import cdiv, base_2b, toByte

def wotsp_chain(X: bytes, i: int, s: int, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Chaining function used in WOTS+"""
    assert len(X) == ctx.n
    if (i + s) >= ctx.wotsp_w:
        return b"" # NULL

    tmp = X

    for j in range(i, i + s):
        adrs.set_hash_address(j)
        tmp = ctx.f(pk_seed, bytes(adrs.data), tmp)
    return tmp

def wotsp_pkgen(sk_seed: bytes, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Generate a WOTS+ public key"""
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(AddressType.WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    tmp = bytes()
    for i in range(ctx.wotsp_len):
        sk_adrs.set_chain_address(i)
        sk = ctx.prf(pk_seed, sk_seed, sk_adrs.data)
        adrs.set_chain_address(i)
        tmp += wotsp_chain(sk, 0, ctx.wotsp_w - 1, pk_seed, adrs, ctx)
    wotspk_adrs = adrs.copy()
    wotspk_adrs.set_type_and_clear(AddressType.WOTS_PK)
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = ctx.t(ctx.wotsp_len, pk_seed, bytes(wotspk_adrs.data), tmp)
    return pk

def wotsp_sign(M: bytes, sk_seed: bytes, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Generate a WOTS+ signature on an n-byte message"""
    csum = 0
    msg = base_2b(M, ctx.lg_w, ctx.wotsp_len1)

    for i in range(ctx.wotsp_len1):
        csum += ctx.wotsp_w - 1 - msg[i]

    csum <<= ((8 - ((ctx.wotsp_len2 * ctx.lg_w) % 8)) % 8)
    msg += base_2b(toByte(csum, cdiv(ctx.wotsp_len2 * ctx.lg_w, 8)),
                   ctx.lg_w, ctx.wotsp_len2)

    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(AddressType.WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    sig = b""
    for i in range(ctx.wotsp_len):
        sk_adrs.set_chain_address(i)
        sk = ctx.prf(pk_seed, sk_seed, bytes(sk_adrs.data))
        adrs.set_chain_address(i)
        sig += wotsp_chain(sk, 0, msg[i], pk_seed, adrs, ctx)
    return sig

def wotsp_pk_from_sig(sig: bytes, M: bytes, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Computes a WOTS+ public key from a message and its signature"""
    csum = 0
    msg = base_2b(M, ctx.lg_w, ctx.wotsp_len1)

    for i in range(ctx.wotsp_len1):
        csum += ctx.wotsp_w - 1 - msg[i]

    csum <<= ((8 - ((ctx.wotsp_len2 * ctx.lg_w) % 8)) % 8)
    msg += base_2b(toByte(csum, cdiv(ctx.wotsp_len2 * ctx.lg_w, 8)),
                   ctx.lg_w, ctx.wotsp_len2)
    tmp = bytes()
    for i in range(ctx.wotsp_len):
        adrs.set_chain_address(i)
        next_chain = wotsp_chain(sig[ctx.n * i: ctx.n * (i + 1)], msg[i], ctx.wotsp_w-1-msg[i], pk_seed, adrs, ctx)
        assert next_chain != None
        tmp += next_chain
    wotspk_adrs = adrs.copy()
    wotspk_adrs.set_type_and_clear(AddressType.WOTS_PK)
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk_sig = ctx.t(ctx.wotsp_len, pk_seed, bytes(wotspk_adrs.data), tmp)
    return pk_sig
