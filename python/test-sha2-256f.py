"""
Unit tests
"""

import unittest
import json
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

class TestSHA2_256F_Address(unittest.TestCase):
    """Unit tests for Address class"""

    def test_init(self):
        """Test Address initialisation"""
        a = Address()
        self.assertEqual(len(a.data), 32)
        for i in range(len(a.data)):
            self.assertEqual(a.data[i], 0)
        
class TestSHA2_256F_WotsPlus(unittest.TestCase):
    """Unit tests for WOTS+ stuff"""

    def test_pkgen(self):
        """Testing WOTS+ public key generation"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f WOTS+ "
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        pk_cmp       = tv[pfx+"PUBLIC_KEY"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)
        pk = wotsp_pkgen(sk_seed, pk_seed, adrs, ctx)
        self.assertEqual(len(pk), ctx.n)
        self.assertEqual(pk, pk_cmp)

    def test_sign(self):
        """Testing signature."""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f WOTS+ "
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        msg          = tv[pfx+"MSG"]
        sig_ref      = tv[pfx+"SIGNATURE"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)
        sig = wotsp_sign(msg, sk_seed, pk_seed, adrs, ctx)
        self.assertEqual(sig, sig_ref)

    def test_verify(self):
        """Testing verification of own signatures"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f WOTS+ "
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        pk           = tv[pfx+"PUBLIC_KEY"]
        msg          = tv[pfx+"MSG"]
        sig          = tv[pfx+"SIGNATURE"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)
        # verify the signature; good (msg, sig)
        pk_from_sig = wotsp_pk_from_sig(sig, msg, pk_seed, adrs, ctx)
        self.assertEqual(pk, pk_from_sig)
        # fail verify with bitflipped sig
        sigp = bytearray(sig) # copy signature
        sigp[3] ^= 0x10 # flip a bit
        pk_from_sigp = wotsp_pk_from_sig(bytes(sigp), msg, pk_seed, adrs, ctx)
        self.assertNotEqual(pk, pk_from_sigp)
        # fail verify with bitflipped msg
        msgp = bytearray(msg) # copy message
        msgp[6] ^= 0x04 # flip a bit
        pk_from_sigm = wotsp_pk_from_sig(sig, bytes(msgp), pk_seed, adrs, ctx)
        self.assertNotEqual(pk, pk_from_sigm)

class TestSHA2_256F_XMSS(unittest.TestCase):
    """Unit tests for XMSS stuff"""

    def test_node(self):
        """Testing XMSS node function"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f XMSS "
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        node_ref     = tv[pfx+"NODE"]
        i            = tv[pfx+"NODEI"]
        z            = tv[pfx+"NODEZ"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)
        node = xmss_node(sk_seed, i, z, pk_seed, adrs, ctx)
        self.assertEqual(node, node_ref)

    def test_sign(self):
        """Testing XMSS signing"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f XMSS "
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        msg          = tv[pfx+"MSG"]
        idx          = tv[pfx+"SIGNIDX"]
        sig_ref      = tv[pfx+"SIGNATURE"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)
        sig = xmss_sign(msg, sk_seed, idx, pk_seed, adrs, ctx)
        self.assertEqual(sig, sig_ref)

    def test_verify(self):
        """Self-testing XMSS signature verification"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f XMSS "
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        msg          = tv[pfx+"MSG"]
        idx          = tv[pfx+"SIGNIDX"]
        sig          = tv[pfx+"SIGNATURE"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)
        # public key is node at level h'
        pk = xmss_node(sk_seed, 0, ctx.hp, pk_seed, adrs, ctx)
        # verify the signature; good (idx, msg, sig)
        pk_from_sig = xmss_pk_from_sig(idx, sig, msg, pk_seed, adrs, ctx)
        self.assertEqual(pk, pk_from_sig)
        # fail verify with bitflipped sig
        sigp = bytearray(sig) # copy signature
        sigp[3] ^= 0x10 # flip a bit
        pk_from_sigp = xmss_pk_from_sig(idx, bytes(sigp), msg, pk_seed, adrs, ctx)
        self.assertNotEqual(pk, pk_from_sigp)
        # fail verify with bitflipped msg
        msgp = bytearray(msg) # copy message
        msgp[6] ^= 0x04 # flip a bit
        pk_from_sigm = xmss_pk_from_sig(idx, sig, bytes(msgp), pk_seed, adrs, ctx)
        self.assertNotEqual(pk, pk_from_sigm)
        # fail verify with wrong idx
        idxp = 2
        pk_from_sigi = xmss_pk_from_sig(idxp, sig, msg, pk_seed, adrs, ctx)
        self.assertNotEqual(pk, pk_from_sigi)

        # testing with address of pk_root (as in ht_verify)
        adrs = Address(toByte(0, 32)) # adrs <- toByte(0,32)
        adrs.set_layer_address(ctx.d - 1)
        pk_root = xmss_node(sk_seed, 0, ctx.hp, pk_seed, adrs, ctx)
        sig2 = xmss_sign(msg, sk_seed, idx, pk_seed, adrs, ctx)
        pk_from_sig = xmss_pk_from_sig(idx, sig2, msg, pk_seed, adrs, ctx)
        self.assertEqual(pk_from_sig, pk_root)

class TestSHA2_256F_HT(unittest.TestCase):
    """Unit test for hypertree stuff"""

    def test_sign(self):
        """Hypertree signature test"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f HT "
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        msg          = tv[pfx+"MSG"]
        sig_ref      = tv[pfx+"SIGNATURE"]
        idx_tree     = tv[pfx+"IDX_TREE"]
        idx_leaf     = tv[pfx+"IDX_LEAF"]

        sig = ht_sign(msg, sk_seed, pk_seed, idx_tree, idx_leaf, ctx)

        self.assertEqual(sig, sig_ref)

    def test_verify(self):
        """Self-testing hypertree signature verification"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f HT "
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        msg          = tv[pfx+"MSG"]
        sig          = tv[pfx+"SIGNATURE"]
        idx_tree     = tv[pfx+"IDX_TREE"]
        idx_leaf     = tv[pfx+"IDX_LEAF"]

        # Calculate PK.root as in slh_keygen()
        adrs = Address(toByte(0, 32)) # adrs <- toByte(0,32)
        adrs.set_layer_address(ctx.d - 1)
        pk_root = xmss_node(sk_seed, 0, ctx.hp, pk_seed, adrs, ctx)

        self.assertTrue(ht_verify(msg, sig, pk_seed, idx_tree, idx_leaf, pk_root, ctx))

class TestSHA2_256F_FORS(unittest.TestCase):
    """Unit test for FORS stuff"""

    def test_skgen(self):
        """Testing FORS secret key generation function"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f FORS "
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        fors_sk      = tv[pfx+"SK"]
        idx          = tv[pfx+"IDX"]
        adrs_bytes   = tv[pfx+"ADDRESS"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)

        sk = fors_skgen(sk_seed, pk_seed, adrs, idx, ctx)

        self.assertTrue(sk, fors_sk)

    def test_node(self):
        """Testing FORS node function"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f FORS "
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        adrs_bytes   = tv[pfx+"ADDRESS"]
        i            = tv[pfx+"NODEI"]
        z            = tv[pfx+"NODEZ"]
        node_ref     = tv[pfx+"NODE"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)

        node = fors_node(sk_seed, i, z, pk_seed, adrs, ctx)

        self.assertEqual(node, node_ref)

    def test_sign(self):
        """Testing FORS sign function"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f FORS "
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sig_ref      = tv[pfx+"SIGNATURE"]
        md           = tv[pfx+"MD"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)

        sig = fors_sign(md, sk_seed, pk_seed, adrs, ctx)

        self.assertEqual(sig, sig_ref)

    def test_pk_from_sig(self):
        """Self-testing FORS verification (pk from sig)"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f FORS "
        sk_seed      = tv[pfx+"SK_SEED"]
        pk_seed      = tv[pfx+"PK_SEED"]
        adrs_bytes   = tv[pfx+"ADDRESS"]
        sig          = tv[pfx+"SIGNATURE"]
        node         = tv[pfx+"NODE"]
        md           = tv[pfx+"MD"]
        adrs = Address()
        adrs.data = bytearray(adrs_bytes)

        pk = fors_pk_from_sig(sig, md, pk_seed, adrs, ctx)

        # generate the pk from roots from sk_seed
        roots = b""
        for j in range(ctx.k):
            node = fors_node(sk_seed, j, ctx.a, pk_seed, adrs, ctx)
            roots += node
        forspkadrs = adrs.copy()
        forspkadrs.set_type_and_clear(AddressType.FORS_ROOTS)
        forspkadrs.set_key_pair_address(adrs.get_key_pair_address())
        pk_ref = ctx.t(ctx.k, pk_seed, bytes(forspkadrs.data), roots)

        self.assertEqual(pk, pk_ref)

class TestSHA2_256F_SLH(unittest.TestCase):
    """Unit test for top-level SLH-DSA function"""

    def test_keygen(self):
        """Sanity checks of SLH-DSA keygen"""
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        key = slh_keygen(ctx)
        self.assertEqual(type(key), tuple)
        self.assertEqual(len(key),    2)
        self.assertEqual(type(key[0]), tuple)
        self.assertEqual(len(key[0]), 4)
        self.assertEqual(type(key[1]), tuple)
        self.assertEqual(len(key[1]), 2)
        self.assertEqual(len(key[0][0]), ctx.n) 
        self.assertEqual(len(key[0][1]), ctx.n) 
        self.assertEqual(len(key[0][2]), ctx.n) 
        self.assertEqual(len(key[0][3]), ctx.n) 
        self.assertEqual(len(key[1][0]), ctx.n) 
        self.assertEqual(len(key[1][1]), ctx.n) 

    def test_sign(self):
        """Test signature generation"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f SLH "
        sk           = tv[pfx+"SK"]
        sig_ref      = tv[pfx+"SIGNATURE"]
        msg          = tv[pfx+"MSG"]

        sig = slh_sign(msg, sk, ctx)
        
        # sanity
        self.assertEqual(len(sig), ctx.sig_bytes)
        self.assertEqual(len(sig), len(sig_ref))

        self.assertEqual(sig, sig_ref)

    def test_verify(self):
        """Self-testing signature verification"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-test-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f SLH "
        pk           = tv[pfx+"PK"]
        sig          = tv[pfx+"SIGNATURE"]
        msg          = tv[pfx+"MSG"]

        # verify original (msg,sig) pair
        self.assertTrue(slh_verify(msg, sig, pk, ctx))

        # flip a bit and the verification should fail
        msg2 = bytes([msg[0] ^ 0x10]) + msg[1:]
        self.assertFalse(slh_verify(msg2, sig, pk, ctx))

class TestSHA2_256F_SLHREF(unittest.TestCase):
    """Unit test for SLH-DSA wrp hacked SPHINCS+ ref impl"""

    def test_sign(self):
        """Test signature generation"""
        tv = read_json_test_vectors("../slh-dsa-sha2-256f-ref-vectors.json")
        ctx = SLHDSA("SLH-DSA-SHA2-256f")
        pfx = "SLH-DSA-SHA2-256f SLH "
        sk           = tv[pfx+"SK"]
        sig_ref      = tv[pfx+"SIGNATURE"]
        msg          = tv[pfx+"MSG"]

        sig = slh_sign(msg, sk, ctx)
        
        # sanity
        self.assertEqual(len(sig), ctx.sig_bytes)
        self.assertEqual(len(sig), len(sig_ref))

        self.assertEqual(sig, sig_ref)

if __name__ == "__main__":
    unittest.main()
