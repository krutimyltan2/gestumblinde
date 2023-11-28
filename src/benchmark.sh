#!/bin/sh
echo    "+--------------------+-------+------+"
echo    "| PARAMETER SET      | sign  | veri |"
echo    "+--------------------+-------+------+"
echo -n "| SLH-DSA-SHAKE-128s |  "
./build/benchmark_shake_128s | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHAKE-128f |  "
./build/benchmark_shake_128f | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHAKE-192s |  "
./build/benchmark_shake_192s | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHAKE-192f |  "
./build/benchmark_shake_192f | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHAKE-256s |  "
./build/benchmark_shake_256s | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHAKE-256f |  "
./build/benchmark_shake_256f | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHA2-128s  |  "
./build/benchmark_sha2_128s | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHA2-128f  |  "
./build/benchmark_sha2_128f | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHA2-192s  |  "
./build/benchmark_sha2_192s | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHA2-192f  |  "
./build/benchmark_sha2_192f | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHA2-256s  |  "
./build/benchmark_sha2_256s | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo -n "| SLH-DSA-SHA2-256f  |  "
./build/benchmark_sha2_256f | sed 's/^  // ; s/ / | / ; s/$/ |/'
echo    "+--------------------+-------+------+"
