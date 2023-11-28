"""
Timing stuff.
"""

import json
import time
from slh_dsa import SLHDSA
from address import Address, AddressType
from wotsp import wotsp_pkgen, wotsp_sign, wotsp_pk_from_sig
from xmss import xmss_node, xmss_sign, xmss_pk_from_sig
from fors import fors_skgen, fors_node, fors_sign, fors_pk_from_sig
from slh import slh_keygen, slh_sign, slh_verify
from ht import ht_sign, ht_verify
from utils import toByte, cdiv

def read_json_test_vectors(filename):
    """Read test vector from JSON file"""
    with open(filename, "r") as infile:
        json_object = infile.read()
    r = json.loads(json_object)
    # convert to bytes/tuples of bytes
    converted = dict()
    for k in r.keys():
        if type(r[k]) == list:
            if len(r[k]) in [2,4] and (("SLH SK" in k) or ("SLH PK" in k)):
                converted[k] = tuple([bytes(x) for x in r[k]])
            else:
                converted[k] = bytes(r[k])
        else:
            converted[k] = r[k]
    return converted

def time_sign(file, name):
    """Time signature generation"""
    print(f"[+] Timing signing using {name} parameter set...")
    tv = read_json_test_vectors(file)
    ctx = SLHDSA(name)
    pfx = name + " SLH "
    sk           = tv[pfx+"SK"]
    sig_ref      = tv[pfx+"SIGNATURE"]
    msg          = tv[pfx+"MSG"]

    tb = time.time()
    sig = slh_sign(msg, sk, ctx)
    ta = time.time()

    return ta-tb

def time_verify(file, name):
    """Time signature verification"""
    print(f"[+] Timing signature verification using {name} parameter set...")
    tv = read_json_test_vectors(file)
    ctx = SLHDSA(name)
    pfx = name + " SLH "
    pk           = tv[pfx+"PK"]
    sig          = tv[pfx+"SIGNATURE"]
    msg          = tv[pfx+"MSG"]

    tb = time.time()
    slh_verify(msg, sig, pk, ctx)
    ta = time.time()

    return ta-tb

if __name__ == "__main__":
    files = {
            "SLH-DSA-SHAKE-128s": "../slh-dsa-shake-128s-test-vectors.json",
            "SLH-DSA-SHAKE-128f": "../slh-dsa-shake-128f-test-vectors.json",
            "SLH-DSA-SHAKE-192s": "../slh-dsa-shake-192s-test-vectors.json",
            "SLH-DSA-SHAKE-192f": "../slh-dsa-shake-192f-test-vectors.json",
            "SLH-DSA-SHAKE-256s": "../slh-dsa-shake-256s-test-vectors.json",
            "SLH-DSA-SHAKE-256f": "../slh-dsa-shake-256f-test-vectors.json",
            "SLH-DSA-SHA2-128s": "../slh-dsa-sha2-128s-test-vectors.json",
            "SLH-DSA-SHA2-128f": "../slh-dsa-sha2-128f-test-vectors.json",
            "SLH-DSA-SHA2-192s": "../slh-dsa-sha2-192s-test-vectors.json",
            "SLH-DSA-SHA2-192f": "../slh-dsa-sha2-192f-test-vectors.json",
            "SLH-DSA-SHA2-256s": "../slh-dsa-sha2-256s-test-vectors.json",
            "SLH-DSA-SHA2-256f": "../slh-dsa-sha2-256f-test-vectors.json"
            }

    # timing 
    tsig = dict()
    tver = dict()
    for k in files.keys():
        tsig[k] = time_sign(files[k], k)
        tver[k] = time_verify(files[k], k)
    
    # printing
    print("\n\nSignature times:")
    for k in tsig.keys():
        print(f"  {k}: {tsig[k]} seconds")

    print("Verify times:")
    for k in tver.keys():
        print(f"  {k}: {tver[k]} seconds")
