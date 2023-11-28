"""
From Section 8.
"""

from address import Address, AddressType
from slh_dsa import SLHDSA
from utils import base_2b, cdiv

def fors_skgen(sk_seed: bytes, pk_seed: bytes, adrs: Address, idx: int, ctx: SLHDSA) -> bytes:
    """Generate a FORS private-key value"""
    assert idx >= 0

    skadrs = adrs.copy()
    skadrs.set_type_and_clear(AddressType.FORS_PRF)
    skadrs.set_key_pair_address(adrs.get_key_pair_address())
    skadrs.set_tree_index(idx)

    return ctx.prf(pk_seed, sk_seed, bytes(skadrs.data))

def fors_node(sk_seed: bytes, i: int, z: int, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Compute the root of a Merkle subtree of FORS public values"""
    assert i >= 0
    assert z >= 0

    if z > ctx.a or i >= ctx.k * 2**(ctx.a - z):
        return b"" # NULL

    if z == 0:
        sk = fors_skgen(sk_seed, pk_seed, adrs, i, ctx)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i)
        node = ctx.f(pk_seed, bytes(adrs.data), sk)
    else:
        lnode = fors_node(sk_seed, 2*i  , z-1, pk_seed, adrs, ctx)
        rnode = fors_node(sk_seed, 2*i+1, z-1, pk_seed, adrs, ctx)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)
        node = ctx.hf(pk_seed, bytes(adrs.data), lnode + rnode)

    return node

def fors_sign(md: bytes, sk_seed: bytes, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Generate a FORS signature"""
    assert len(md) == cdiv(ctx.k * ctx.a, 8)

    sig_fors = bytes() # initialize sig_fors as a zero-length byte string
    indices = base_2b(md, ctx.a, ctx.k)
    for i in range(ctx.k):
        sig_fors += fors_skgen(sk_seed, pk_seed, adrs, i * 2**ctx.a + indices[i], ctx)

        auth = bytes()
        for j in range(ctx.a):
            s = indices[i]//(2**j) ^ 0b01
            auth += fors_node(sk_seed, i*2**(ctx.a-j) + s, j, pk_seed, adrs, ctx)
        sig_fors += auth
    return sig_fors

def fors_pk_from_sig(sig_fors: bytes, md: bytes, pk_seed: bytes, adrs: Address, ctx: SLHDSA) -> bytes:
    """Compute a FORS public key from a FORS signature"""
    assert len(sig_fors) == ctx.k * (ctx.a + 1) * ctx.n
    assert len(md) == cdiv(ctx.k * ctx.a, 8)

    indices = base_2b(md, ctx.a, ctx.k)
    node =[b"" ,b""]
    root = bytes()
    for i in range(ctx.k):
        sk = sig_fors[i*(ctx.a+1)*ctx.n : (i*(ctx.a+1)+1)*ctx.n] # sk <- sig_fors.getSK(i)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * 2**ctx.a + indices[i])
        node[0] = ctx.f(pk_seed, bytes(adrs.data), sk)

        auth = sig_fors[(i*(ctx.a+1)+1)*ctx.n : (i+1)*(ctx.a+ctx.n)*ctx.n] # auth <- sig_fors.getAUTH(i)
        for j in range(ctx.a):
            adrs.set_tree_height(j+1)
            if (indices[i]//(2**j)) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index()//2)
                node[1] = ctx.hf(pk_seed, bytes(adrs.data), node[0] + auth[j*ctx.n:(j+1)*ctx.n])
            else:
                adrs.set_tree_index((adrs.get_tree_index()-1)//2)
                node[1] = ctx.hf(pk_seed, bytes(adrs.data), auth[j*ctx.n:(j+1)*ctx.n] + node[0])
            node[0] = node[1]
        root += node[0]
    forspkadrs = adrs.copy()
    forspkadrs.set_type_and_clear(AddressType.FORS_ROOTS)
    forspkadrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = ctx.t(ctx.k, pk_seed, bytes(forspkadrs.data), root)
    return pk
