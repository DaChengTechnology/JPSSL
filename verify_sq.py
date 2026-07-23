#!/usr/bin/env python3
"""Verify fe_sq output for By^2."""
p = 2**255 - 19

# By = 4/5 mod p
By = 4 * pow(5, -1, p) % p
print(f"By = {By}")
By_bytes = By.to_bytes(32, 'little')
print(f"By bytes: {By_bytes.hex()}")

# By^2 mod p
By2 = pow(By, 2, p)
print(f"By^2 = {By2}")
By2_bytes = By2.to_bytes(32, 'little')
print(f"By^2 bytes: {By2_bytes.hex()}")

# jpssl output for By^2:
# e051b81e85eb51b81e85eb51b81e85eb51b81e85eb51b81e85eb51b81e85eb51
jpssl_By2 = bytes.fromhex("e051b81e85eb51b81e85eb51b81e85eb51b81e85eb51b81e85eb51b81e85eb51")
print(f"jpssl By^2 bytes: {jpssl_By2.hex()}")
print(f"Match: {jpssl_By2 == By2_bytes}")

# Also check: what number does jpssl's output represent?
jpssl_val = int.from_bytes(jpssl_By2, 'little')
print(f"jpssl By^2 as int: {jpssl_val}")
print(f"correct By^2 as int: {By2}")
print(f"diff: {(jpssl_val - By2) % p}")

# Check if the SHA-512 difference matters
import hashlib
seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])

h = hashlib.sha512(seed).digest()
print(f"\nPython SHA-512(seed): {h.hex()}")

# jpssl SHA-512(seed):
# 357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f
jpssl_h = bytes.fromhex("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f")
print(f"jpssl SHA-512(seed): {jpssl_h.hex()}")
print(f"Match: {h == jpssl_h}")

# Find the differing bytes
for i in range(64):
    if h[i] != jpssl_h[i]:
        print(f"  Diff at byte {i}: python={h[i]:02x}, jpssl={jpssl_h[i]:02x}")
