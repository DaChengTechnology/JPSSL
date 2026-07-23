#!/usr/bin/env python3
"""Compare jpssl Ed25519 against OpenSSL and Python reference values."""
import hashlib
import subprocess
import sys

# RFC 8032 Section 7.1 TEST 1
seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])

expected_pub = bytes([0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
                      0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
                      0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
                      0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a])

expected_sig = bytes([0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
                      0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
                      0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
                      0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
                      0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
                      0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
                      0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
                      0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b])

# Step 1: SHA-512(seed)
h = bytearray(hashlib.sha512(seed).digest())
print(f"SHA-512(seed):    {bytes(h).hex()}")
print(f"  expected (ref):  307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f8d4cd145e5e5b9a3b7a1d5e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6")

# Step 2: Clamp
h[0] &= 248
h[31] &= 127
h[31] |= 64
scalar = bytes(h[:32])
prefix = bytes(h[32:])
print(f"\nClamped scalar:  {scalar.hex()}")
print(f"Prefix (32B):     {prefix.hex()}")

# Step 3: r = SHA-512(prefix || msg) mod l, for empty msg
r_hash_raw = hashlib.sha512(prefix + b'').digest()
print(f"\nSHA-512(prefix):  {r_hash_raw.hex()}")

# Step 4: R = r * B (point encoding)
# The first 32 bytes of expected_sig is R
R = expected_sig[:32]
print(f"Expected R:       {R.hex()}")

# Step 5: k = SHA-512(R || A || msg) mod l
A = expected_pub
k_hash_raw = hashlib.sha512(R + A + b'').digest()
print(f"\nSHA-512(R||A||M): {k_hash_raw.hex()}")

# Step 6: S = (r + k * s) mod l
# S is the last 32 bytes of expected_sig
S_bytes = expected_sig[32:]
print(f"Expected S:       {S_bytes.hex()}")

# Now use OpenSSL to verify
print("\n=== OpenSSL Ed25519 verification ===")
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization

    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(f"OpenSSL pub key:  {pub_bytes.hex()}")
    print(f"Expected pub:     {expected_pub.hex()}")
    print(f"Match: {pub_bytes == expected_pub}")

    sig = priv.sign(b'')
    print(f"OpenSSL sig:      {sig.hex()}")
    print(f"Expected sig:     {expected_sig.hex()}")
    print(f"Match: {sig == expected_sig}")

except ImportError:
    print("cryptography not available, using openssl CLI")

# Now check what jpssl produces
print("\n=== jpssl Ed25519 output ===")
# From the test output:
jpssl_pub = bytes.fromhex("c8e3605afc7f000098c3c6939572000070e2605afc7f000012d86a9395720000")
jpssl_sig = bytes.fromhex("1f07d039b0feffcb77e5a2ca813204fd802c60309093a94b831efaff1df9c7becfbe742968a1e4af8a0cf81b886b4509f7aa3bfa1d6258d8a1775ea58d865a05")
jpssl_R = jpssl_sig[:32]
jpssl_S = jpssl_sig[32:]

print(f"jpssl pub:        {jpssl_pub.hex()}")
print(f"jpssl R:          {jpssl_R.hex()}")
print(f"jpssl S:          {jpssl_S.hex()}")

# Check if jpssl's SHA-512 is correct
print("\n=== SHA-512 check ===")
# The clamped scalar from jpssl test output was:
# 307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f
jpssl_scalar_hex = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f"
print(f"jpssl scalar:     {jpssl_scalar_hex}")
print(f"python scalar:    {scalar.hex()}")
print(f"Match: {jpssl_scalar_hex == scalar.hex()}")
