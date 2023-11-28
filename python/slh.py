"""
From Section 9.
Top level functions of SLH-DSA.
"""

from secrets import token_bytes
from address import Address, AddressType
from slh_dsa import SLHDSA
from utils import cdiv, toByte, toInt
from xmss import xmss_node
from fors import fors_sign, fors_pk_from_sig
from ht import ht_sign, ht_verify

def slh_keygen(ctx: SLHDSA):
    """Generate an SLH-DSA key pair"""
    sk_seed = token_bytes(ctx.n)
    sk_prf = token_bytes(ctx.n)
    pk_seed = token_bytes(ctx.n)

    adrs = Address(toByte(0, 32)) # adrs <- toByte(0,32)
    adrs.set_layer_address(ctx.d - 1)
    pk_root = xmss_node(sk_seed, 0, ctx.hp, pk_seed, adrs, ctx)

    return ((sk_seed, sk_prf, pk_seed, pk_root), (pk_seed, pk_root))

def slh_sign(M: bytes, sk: tuple[bytes, bytes, bytes, bytes], ctx: SLHDSA, randomize = False) -> bytes:
    """Generate an SLH-DSA signature"""
    assert len(sk) == 4
    sk_seed, sk_prf, pk_seed, pk_root = sk

    adrs = Address(toByte(0, 32)) # adrs <- toByte(0,32)

    opt_rand = pk_seed
    if randomize:
        opt_rand = token_bytes(ctx.n)
    r = ctx.prf_msg(sk_prf, opt_rand, M)
    sig = r

    digest = ctx.h_msg(r, pk_seed, pk_root, M)
    md = digest[0 : cdiv(ctx.k*ctx.a, 8)]
    tmp_idx_tree = digest[cdiv(ctx.k*ctx.a,8) : cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8)]
    tmp_idx_leaf = digest[cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8) : cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8)+cdiv(ctx.h,8*ctx.d)]
    idx_tree = toInt(tmp_idx_tree, cdiv(ctx.h-ctx.h//ctx.d,8)) % 2**(ctx.h-ctx.h//ctx.d)
    idx_leaf = toInt(tmp_idx_leaf, cdiv(ctx.h,8*ctx.d)) % 2**(ctx.h//ctx.d)

    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(AddressType.FORS_TREE)
    adrs.set_key_pair_address(toByte(idx_leaf, 4))
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs, ctx)
    sig += sig_fors

    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs, ctx)

    sig_ht = ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, ctx)
    sig += sig_ht

    return sig

def slh_verify(M: bytes, sig: bytes, pk: tuple[bytes, bytes], ctx: SLHDSA) -> bool:
    """Verify an SLH-DSA signature"""

    if len(sig) != (1 + ctx.k * (1 + ctx.a) + ctx.h + ctx.d * ctx.wotsp_len) * ctx.n:
        return False

    pk_seed, pk_root = pk

    adrs = Address(toByte(0, 32)) # adrs <- toByte(0,32)
    r = sig[0:ctx.n] # r <- sig.getR()
    sig_fors = sig[ctx.n : (1+ctx.k*(1+ctx.a))*ctx.n] # sig <- sig.getSIG_FORS()
    sig_ht = sig[(1+ctx.k*(1+ctx.a))*ctx.n : (1+ctx.k*(1+ctx.a)+ctx.h+ctx.d*ctx.wotsp_len)*ctx.n] # sig <- sig.getSIG_HT()
    
    digest = ctx.h_msg(r, pk_seed, pk_root, M)
    md = digest[0 : cdiv(ctx.k*ctx.a, 8)]
    tmp_idx_tree = digest[cdiv(ctx.k*ctx.a,8) : cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8)]
    tmp_idx_leaf = digest[cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8) : cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8)+cdiv(ctx.h,8*ctx.d)]
    idx_tree = toInt(tmp_idx_tree, cdiv(ctx.h-ctx.h//ctx.d,8)) % 2**(ctx.h-ctx.h//ctx.d)
    idx_leaf = toInt(tmp_idx_leaf, cdiv(ctx.h,8*ctx.d)) % 2**(ctx.h//ctx.d)

    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(AddressType.FORS_TREE)
    adrs.set_key_pair_address(toByte(idx_leaf, 4))

    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs, ctx)

    return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root, ctx)

