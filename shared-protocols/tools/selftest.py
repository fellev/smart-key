#!/usr/bin/env python3
"""Sanity checks for the reference implementation (RFC 5869 / RFC 7748 vectors)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import skp_crypto as skp  # noqa: E402

H = bytes.fromhex
failures = []


def check(name, got, expect):
    if got != expect:
        failures.append(f"{name}: got {got.hex()} expected {expect.hex()}")
    else:
        print("ok  ", name)


# RFC 5869 test case 1
check("hkdf-rfc5869-1",
      skp.hkdf_sha256(b"\x0b" * 22, H("000102030405060708090a0b0c"),
                      H("f0f1f2f3f4f5f6f7f8f9"), 42),
      H("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))

# RFC 7748 section 6.1 (X25519 Diffie-Hellman)
a_priv = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
b_priv = H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
a_pub = H("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
b_pub = H("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
shared = H("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

check("x25519-pub-a", skp.x25519_public(a_priv), a_pub)
check("x25519-pub-b", skp.x25519_public(b_priv), b_pub)
check("x25519-shared-ab", skp.x25519(a_priv, b_pub), shared)
check("x25519-shared-ba", skp.x25519(b_priv, a_pub), shared)

# HMAC-SHA256 RFC 4231 test case 2
check("hmac-rfc4231-2", skp.hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
      H("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))

if failures:
    print("\nFAILURES:")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("\nall reference vectors pass")
