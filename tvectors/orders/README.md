# Differences in bit order in bytes

This illustrates three different ways to interpret a sequence of bytes
as a sequence of bits. The three ways are

* Using the method from FIPS.205 (the natural way), using big-endian-bit
  order.
* Using the method from SPHINCS+ where the least significant bits comes
  first (wierd).
* The way it was implemented in the SPHINCS+ reference implementation
  prior to commit `74b618d4b1311a9946170fbcb85d9bca06033460`. This is
  just wrong?
