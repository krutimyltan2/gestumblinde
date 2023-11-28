# gestumblinde

Gestumblinde, Sphincs+ or SLH-DSA

**Warning!** Experimental stuff here.

This repository contains implementations (one in Python and one in C) of
stateless hash-based signatures per
[[FIPS.205]](https://csrc.nist.gov/pubs/fips/205/ipd). The
implementations are based on the mentioned FIPS draft and, partly, on
the SPHINCS+ submission
[[SPHINCSpv3.1]](https://sphincs.org/resources.html).

## References

[[FIPS.205]](https://csrc.nist.gov/pubs/fips/205/ipd)
  NIST - "FIPS 205 (Draft) - Stateless Hash-Based Digital Signature
  Standard", 2023.
[[SPHINCSpv3.1]](https://sphincs.org/resources.html)
Aumasson et al. - "SPHINCS+: Submission to the NIST post-quantum
  project, v.3.1", 2022.

## Test Vectors

There are a number of JSON files with test vectors.

The files that have a name on the form

    [parameter-choice]-test-vectors.json

contains test vectors for the individual algorithms that are in FIPS
205 and are generated using the Python implementation in the `python`
folder in this repository. The Python script `make_test_vectors.py` can
be used for the purpose of generating test vectors.

Since it seems meaningless to compare with test vectors that have been
generated with the same implementation as the one being tested I also
wanted to use the reference implementation of SPHINCS+. The main issues
with this are:

* There is no obvious way to extract the results of each individual
  "algorithm" from the specification (because the reference
  implementation is not separated in this way). This means that there
  are no test vectors for these.
* The reference implementation of SPHINCS+ does _not_ conform to the
  draft FIPS 205. I have therefore "hacked" the reference
  implementation of SPHINCS+ to make it (as I understand it) work as it
  would if it was written according to FIPS 205. For more details see
  `tvectors/sphincs/README.md`.

The test vectors for these are put into files named

    [parameter-choice]-ref-vectors.json

Finally, the easiest way to understand the internal naming and structure
in the JSON representation of the test vectors is to look at the code in
the unit tests written for the Python implementation, eg.
`python/test-sha2-128f.py`.

## Build instruction for the C impl

To build the pre-selected command line tools `keygen`, `sign` and
`verif` you can do the following:

```console
$ cd src
$ make
```

This assumes BSD make, you might need to run `bmake` instead if your
default make program is, for example, GNU Make.

### Example usage

This example assumes that you have build the command line tools for the
parameter set `SLH-DSA-SHAKE-128s`.

First we generate a keypair, putting the public key in `/tmp/pk.bin`
and the secret key in `/tmp/sk.bin`:

```console
$ ./build/keygen_shake_128s /tmp/pk.bin /tmp/sk.bin
```

Let us now sign the message "gestumblinde is cool" with the secret key
as follows, and put the signature in `/tmp/cool.sig`:

```console
$ echo -n "gestumblinde is cool" | ./build/sign_shake_128s /tmp/sk.bin > /tmp/cool.sig
```

We can now try to verify the message, using the signature and the
public key with:

```console
$ echo -n "gestumblinde is cool" | ./build/verif_shake_128s /tmp/pk.bin /tmp/cool.sig
TRUE
```

whereas changing up message or signature should give false

```console
$ echo -n "gestumblinde is not cool" | ./build/verif_shake_128s /tmp/pk.bin /tmp/cool.sig
FALSE
```

## Timing results on an old, bad computador

Computed using `python/bench.py`.

    +--------------------+-------+-------+
    | PARAMETER SET      | sign  | veri  |
    +--------------------+-------+-------+
    | SLH-DSA-SHAKE-128s | 32.28 |  0.03 |
    | SLH-DSA-SHAKE-128f |  1.57 |  0.09 |
    | SLH-DSA-SHAKE-192s | 68.41 |  0.05 |
    | SLH-DSA-SHAKE-192f |  2.86 |  0.14 |
    | SLH-DSA-SHAKE-256s | 66.24 |  0.08 |
    | SLH-DSA-SHAKE-256f |  5.90 |  0.14 |
    | SLH-DSA-SHA2-128s  | 50.25 |  0.05 |
    | SLH-DSA-SHA2-128f  |  2.41 |  0.15 |
    | SLH-DSA-SHA2-192s  | 97.00 |  0.07 |
    | SLH-DSA-SHA2-192f  |  4.26 |  0.20 |
    | SLH-DSA-SHA2-256s  | 91.17 |  0.11 |
    | SLH-DSA-SHA2-256f  |  8.79 |  0.21 |
    +--------------------+-------+-------+

Computed using `./benchmark.sh` (the C implementation):

    +--------------------+-------+------+
    | PARAMETER SET      | sign  | veri |
    +--------------------+-------+------+
    | SLH-DSA-SHAKE-128s |  1.90 | 0.00 |
    | SLH-DSA-SHAKE-128f |  0.08 | 0.00 |
    | SLH-DSA-SHAKE-192s |  3.27 | 0.00 |
    | SLH-DSA-SHAKE-192f |  0.15 | 0.01 |
    | SLH-DSA-SHAKE-256s |  3.00 | 0.00 |
    | SLH-DSA-SHAKE-256f |  0.31 | 0.01 |
    | SLH-DSA-SHA2-128s  |  1.90 | 0.00 |
    | SLH-DSA-SHA2-128f  |  0.10 | 0.00 |
    | SLH-DSA-SHA2-192s  |  3.18 | 0.00 |
    | SLH-DSA-SHA2-192f  |  0.15 | 0.01 |
    | SLH-DSA-SHA2-256s  |  2.78 | 0.00 |
    | SLH-DSA-SHA2-256f  |  0.27 | 0.01 |
    +--------------------+-------+------+
