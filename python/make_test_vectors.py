"""
Program for making test vectors, and dumping them
in JSON.
"""

from slh_dsa import SLHDSA
from address import Address, AddressType
from wotsp import wotsp_pkgen, wotsp_sign, wotsp_pk_from_sig
from xmss import xmss_node, xmss_sign, xmss_pk_from_sig
from fors import fors_skgen, fors_node, fors_sign, fors_pk_from_sig
from slh import slh_keygen, slh_sign, slh_verify
from ht import ht_sign, ht_verify
from utils import toByte, cdiv
import json
from secrets import token_bytes

def create_test_vectors(t):
    """Create a dict of test vectors for parameter choice t"""
    print(f"[+] Creating test vectors for parameter choice \"{t}\"...")
    tv = dict()
    ctx = SLHDSA(t)

    # WOTS+
    pfx = t+" WOTS+ "
    tv[pfx+"SK_SEED"] = b"gestumblindegaat" + token_bytes(ctx.n-16)
    tv[pfx+"PK_SEED"] = b"densomfraagarfar" + token_bytes(ctx.n-16)
    tv[pfx+"ADDRESS"] = [
      0x72, 0x67, 0x69, 0x53, 0x69, 0x6d, 0x61, 0x6c,
      0x74, 0x65, 0x68, 0x20, 0x6e, 0x6f, 0x6b, 0x20,
      0x00, 0x00, 0x00, 0x00, 0x72, 0x65, 0x00, 0x0c,
      0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x20]
    adrs = Address()
    adrs.data = bytearray(tv[pfx+"ADDRESS"])
    tv[pfx+"PUBLIC_KEY"] = wotsp_pkgen(tv[pfx+"SK_SEED"],
                                       tv[pfx+"PK_SEED"],
                                       adrs, ctx)
    tv[pfx+"MSG"]     = b"meddelandetaerde" + token_bytes(ctx.n-16)
    tv[pfx+"SIGNATURE"] = wotsp_sign(tv[pfx+"MSG"],
                                     tv[pfx+"SK_SEED"],
                                     tv[pfx+"PK_SEED"],
                                     adrs, ctx)
    # XMSS
    pfx = t+" XMSS "
    tv[pfx+"SK_SEED"] = b"gestumblindegaat" + token_bytes(ctx.n-16)
    tv[pfx+"PK_SEED"] = b"densomfraagarfar" + token_bytes(ctx.n-16)
    tv[pfx+"ADDRESS"] = [
      0x72, 0x67, 0x69, 0x53, 0x69, 0x6d, 0x61, 0x6c,
      0x74, 0x65, 0x68, 0x20, 0x6e, 0x6f, 0x6b, 0x20,
      0x00, 0x00, 0x00, 0x00, 0x72, 0x65, 0x00, 0x0c,
      0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x20]
    adrs = Address()
    adrs.data = bytearray(tv[pfx+"ADDRESS"])
    tv[pfx+"NODEI"]  = 0
    tv[pfx+"NODEZ"]  = 0
    tv[pfx+"NODE"] = xmss_node(tv[pfx+"SK_SEED"],
                               tv[pfx+"NODEI"],
                               tv[pfx+"NODEZ"],
                               tv[pfx+"PK_SEED"],
                               adrs, ctx)
    tv[pfx+"MSG"]       = b"meddelandetaerde" + token_bytes(ctx.n-16)
    tv[pfx+"SIGNIDX"]   = 0
    tv[pfx+"SIGNATURE"] = xmss_sign(tv[pfx+"MSG"],
                                    tv[pfx+"SK_SEED"],
                                    tv[pfx+"SIGNIDX"],
                                    tv[pfx+"PK_SEED"],
                                    adrs, ctx)

    # HT
    pfx = t+" HT "
    tv[pfx+"SK_SEED"]   = b"gestumblindegaat" + token_bytes(ctx.n-16)
    tv[pfx+"PK_SEED"]   = b"densomfraagarfar" + token_bytes(ctx.n-16)
    tv[pfx+"MSG"]       = b"meddelandetaerde" + token_bytes(ctx.n-16)
    tv[pfx+"IDX_TREE"]  = 2
    tv[pfx+"IDX_LEAF"]  = 6
    tv[pfx+"SIGNATURE"] = ht_sign(tv[pfx+"MSG"],
                                  tv[pfx+"SK_SEED"],
                                  tv[pfx+"PK_SEED"],
                                  tv[pfx+"IDX_TREE"],
                                  tv[pfx+"IDX_LEAF"],
                                  ctx)
    # FORS
    pfx = t+" FORS "
    tv[pfx+"SK_SEED"]   = b"gestumblindegaat" + token_bytes(ctx.n-16)
    tv[pfx+"PK_SEED"]   = b"densomfraagarfar" + token_bytes(ctx.n-16)
    tv[pfx+"ADDRESS"]   = [
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    tv[pfx+"IDX"] = 1
    adrs = Address()
    adrs.data = bytearray(tv[pfx+"ADDRESS"])
    tv[pfx+"SK"] = fors_skgen(tv[pfx+"SK_SEED"],
                              tv[pfx+"PK_SEED"],
                              adrs,
                              tv[pfx+"IDX"],
                              ctx)
    tv[pfx+"NODEI"] = 1
    tv[pfx+"NODEZ"] = 5
    tv[pfx+"NODE"] = fors_node(tv[pfx+"SK_SEED"],
                               tv[pfx+"NODEI"],
                               tv[pfx+"NODEZ"],
                               tv[pfx+"PK_SEED"],
                               adrs, ctx)
    tv[pfx+"MD"] = bytes(list(range(cdiv(ctx.k * ctx.a, 8))))
    tv[pfx+"SIGNATURE"] = fors_sign(tv[pfx+"MD"],
                                    tv[pfx+"SK_SEED"],
                                    tv[pfx+"PK_SEED"],
                                    adrs, ctx)
    tv[pfx+"PK_FROM_SIG"] = fors_pk_from_sig(tv[pfx+"SIGNATURE"],
                                             tv[pfx+"MD"],
                                             tv[pfx+"PK_SEED"],
                                             adrs, ctx)

    # SLH
    pfx = t+" SLH "
    sk_seed = b"gestumblindegaat" + token_bytes(ctx.n-16)
    sk_prf  = b"aanaerinteloestf" + token_bytes(ctx.n-16)
    pk_seed = b"oerennagonkommer" + token_bytes(ctx.n-16)

    # Generate pk_root from sk_seed, pk_seed
    adrs = Address(toByte(0, 32)) # adrs <- toByte(0,32)
    adrs.set_layer_address(ctx.d - 1)
    pk_root = xmss_node(sk_seed, 0, ctx.hp, pk_seed, adrs, ctx)

    tv[pfx+"SK"]   = (sk_seed, sk_prf, pk_seed, pk_root)
    tv[pfx+"PK"]   = (pk_seed, pk_root)
    tv[pfx+"MSG"]  =  b"helloworldorsomesuchmeaninglesst"
    tv[pfx+"SIGNATURE"] = slh_sign(tv[pfx+"MSG"],
                                   tv[pfx+"SK"],
                                   ctx)

    return tv

def write_tv_to_file(filename, tv):
    """Write the test vectors in dict tv to JSON file"""
    print(f"[+] Writing test vector to file {filename}...")
    # convert bytes to lists of ints
    converted = dict()
    for k in tv.keys():
        if type(tv[k]) == bytes:
            converted[k] = list(tv[k])
        elif type(tv[k]) == tuple:
            converted[k] = tuple([list(x) for x in tv[k]])
        else:
            converted[k] = tv[k]
    json_object = json.dumps(converted, indent=2)
    with open(filename, "w") as outfile:
        outfile.write(json_object)

if __name__ == "__main__":
#    tv = create_test_vectors("SLH-DSA-SHAKE-128s")
#    write_tv_to_file("/tmp/slh-dsa-shake-128s-test-vectors.json", tv)
#    tv = create_test_vectors("SLH-DSA-SHAKE-128f")
#    write_tv_to_file("/tmp/slh-dsa-shake-128f-test-vectors.json", tv)
#    tv = create_test_vectors("SLH-DSA-SHAKE-192s")
#    write_tv_to_file("/tmp/slh-dsa-shake-192s-test-vectors.json", tv)
#    tv = create_test_vectors("SLH-DSA-SHAKE-192f")
#    write_tv_to_file("/tmp/slh-dsa-shake-192f-test-vectors.json", tv)
#    tv = create_test_vectors("SLH-DSA-SHAKE-256s")
#    write_tv_to_file("/tmp/slh-dsa-shake-256s-test-vectors.json", tv)
#    tv = create_test_vectors("SLH-DSA-SHAKE-256f")
#    write_tv_to_file("/tmp/slh-dsa-shake-256f-test-vectors.json", tv)
    tv = create_test_vectors("SLH-DSA-SHA2-128s")
    write_tv_to_file("/tmp/slh-dsa-sha2-128s-test-vectors.json", tv)
    tv = create_test_vectors("SLH-DSA-SHA2-128f")
    write_tv_to_file("/tmp/slh-dsa-sha2-128f-test-vectors.json", tv)
    tv = create_test_vectors("SLH-DSA-SHA2-192s")
    write_tv_to_file("/tmp/slh-dsa-sha2-192s-test-vectors.json", tv)
    tv = create_test_vectors("SLH-DSA-SHA2-192f")
    write_tv_to_file("/tmp/slh-dsa-sha2-192f-test-vectors.json", tv)
    tv = create_test_vectors("SLH-DSA-SHA2-256s")
    write_tv_to_file("/tmp/slh-dsa-sha2-256s-test-vectors.json", tv)
    tv = create_test_vectors("SLH-DSA-SHA2-256f")
    write_tv_to_file("/tmp/slh-dsa-sha2-256f-test-vectors.json", tv)
