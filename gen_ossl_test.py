#!/usr/bin/env python3
"""Generate Ed25519 keypair and signature via OpenSSL, output as C arrays for jpssl"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os

# Generate a fresh key
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
pub_bytes = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

messages = [
    b"",
    b"Hello, world!",
    b"The quick brown fox jumps over the lazy dog",
    b"A" * 256,
]

print("#include <cstdint>")
print()

# Pub key
print("// OpenSSL-generated public key")
print("static const uint8_t ossl_pub[32] = {", end="")
for i, b in enumerate(pub_bytes):
    if i % 16 == 0: print()
    print(f"0x{b:02x},", end="")
print("\n};\n")

for idx, msg in enumerate(messages):
    sig = priv.sign(msg)
    print(f"// Message {idx}: {repr(msg)}")
    print(f"static const uint8_t ossl_msg{idx}[{len(msg)}] = {{", end="")
    for i, b in enumerate(msg):
        if i % 16 == 0: print()
        print(f"0x{b:02x},", end="")
    print("\n};\n")
    
    print(f"static const uint8_t ossl_sig{idx}[64] = {{", end="")
    for i, b in enumerate(sig):
        if i % 16 == 0: print()
        print(f"0x{b:02x},", end="")
    print("\n};\n")

print("// Test loop (add to main):")
for idx, msg in enumerate(messages):
    print(f'    ok = ed25519_verify(ossl_pub, ossl_msg{idx}, {len(msg)}, ossl_sig{idx});')
    print(f'    printf("OpenSSL sig {idx} ({repr(msg)[:30]}...): %s\\n", ok ? "PASS" : "FAIL");')
