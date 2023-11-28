"""
From Section 7.
Hypertree section.
"""

from address import Address
from slh_dsa import SLHDSA
from xmss import xmss_sign, xmss_pk_from_sig
from utils import toByte

def ht_sign(M: bytes, sk_seed: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, ctx: SLHDSA) -> bytes:
    """Generate a hypertree signature"""
    assert idx_leaf >= 0
    assert idx_tree >= 0

    adrs = Address(toByte(0,32)) # adrs <- toByte(0, 32)

    adrs.set_tree_address(idx_tree)
    sig_tmp = xmss_sign(M, sk_seed, idx_leaf, pk_seed, adrs, ctx)
    sig_ht = bytes(sig_tmp)
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, M, pk_seed, adrs, ctx)
    for j in range(1, ctx.d):
        idx_leaf = idx_tree % (2**ctx.hp)
        idx_tree = idx_tree >> ctx.hp
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs, ctx)
        sig_ht += sig_tmp
        if j < ctx.d - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, pk_seed, adrs, ctx)
    return sig_ht

def ht_verify(M: bytes, sig_ht: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, pk_root: bytes, ctx: SLHDSA) -> bool:
    """Verify a hypertree signature"""
    assert idx_leaf >= 0
    assert idx_tree >= 0

    adrs = Address(toByte(0,32)) # adrs <- toByte(0, 32)

    adrs.set_tree_address(idx_tree)
    sig_tmp = sig_ht[:(ctx.hp+ctx.wotsp_len)*ctx.n]  # sig_tmp <- sig_ht.getXMSSSignature(0)
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, M, pk_seed, adrs, ctx)
    for j in range(1, ctx.d):
        idx_leaf = idx_tree % (2**ctx.hp)
        idx_tree = idx_tree >> ctx.hp
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        # sig_tmp <- sig_ht.getXMSSSignature(j)
        sig_tmp = sig_ht[j*(ctx.hp+ctx.wotsp_len)*ctx.n : (j+1)*(ctx.hp+ctx.wotsp_len)*ctx.n]
        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, pk_seed, adrs, ctx)
    if node == pk_root:
        return True
    else:
        return False