# From Section 6

from address import Address, AddressType
from slh_dsa import SLHDSA
from utils import toByte
from wotsp import wotsp_pkgen, wotsp_sign, wotsp_pk_from_sig

def xmss_node(sk_seed: bytes, i: int, z: int, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Compute the root of a Merkle subtree of WOTS+ public keys"""
    assert i >= 0
    assert z >= 0

    if z > ctx.hp or i >= 2**(ctx.hp - z):
        return b"" # NULL

    if z == 0:
        adrs.set_type_and_clear(AddressType.WOTS_HASH)
        adrs.set_key_pair_address(toByte(i, 4))
        node = wotsp_pkgen(sk_seed, pk_seed, adrs, ctx)
    else:
        lnode = xmss_node(sk_seed, 2*i    , z-1, pk_seed, adrs, ctx)
        rnode = xmss_node(sk_seed, 2*i + 1, z-1, pk_seed, adrs, ctx)
        adrs.set_type_and_clear(AddressType.TREE)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)
        node = ctx.hf(pk_seed, bytes(adrs.data), lnode + rnode)
    return node

def xmss_sign(M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Generate an XMSS signature"""
    assert len(M) == ctx.n
    assert idx >= 0
    assert idx < (2**ctx.hp)

    auth = bytes()
    for j in range(ctx.hp):
        k = (idx//(2**j)) ^ 0b01
        auth += xmss_node(sk_seed, k, j, pk_seed, adrs, ctx)

    adrs.set_type_and_clear(AddressType.WOTS_HASH)
    adrs.set_key_pair_address(toByte(idx, 4))
    sig = wotsp_sign(M, sk_seed, pk_seed, adrs, ctx)
    sig_xmss = sig + auth
    return sig_xmss

def xmss_pk_from_sig(idx: int, sig_xmss: bytes, M: bytes, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Compute an XMSS public key from an XMSS signature"""
    assert idx >= 0
    assert len(M) == ctx.n
    assert len(sig_xmss) == (ctx.wotsp_len + ctx.hp) * ctx.n

    adrs.set_type_and_clear(AddressType.WOTS_HASH)
    adrs.set_key_pair_address(toByte(idx, 4))
    sig = sig_xmss[:ctx.wotsp_len * ctx.n]  # sig <- sig_xmss.getWOTSSig()
    auth = sig_xmss[ctx.wotsp_len * ctx.n:] # auth <- sig_xmss.getXMSSAUTH()
    node = [wotsp_pk_from_sig(sig, M, pk_seed, adrs, ctx), None]

    adrs.set_type_and_clear(AddressType.TREE)
    adrs.set_tree_index(idx)
    for k in range(ctx.hp):
        adrs.set_tree_height(k + 1)
        if (idx//(2**k)) % 2 == 0:
            adrs.set_tree_index(adrs.get_tree_index()//2)
            node[1] = ctx.hf(pk_seed, bytes(adrs.data), node[0] + auth[k*ctx.n : (k+1)*ctx.n])
        else:
            adrs.set_tree_index((adrs.get_tree_index()-1)//2)
            node[1] = ctx.hf(pk_seed, bytes(adrs.data), auth[k*ctx.n : (k+1)*ctx.n] + node[0])
        node[0] = node[1]
    return node[0]
