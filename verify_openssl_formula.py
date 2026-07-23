#!/usr/bin/env python3
"""Verify L64, S64 constants and sc_reduce correctness"""
l = 2**252 + 27742317777372353535851937790883648493

# L64 from jpssl: {0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0x0000000000000000, 0x1000000000000000}
L64 = [0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0x0000000000000000, 0x1000000000000000]
L_computed = L64[0] + (L64[1] << 64) + (L64[2] << 128) + (L64[3] << 192)
print(f"L from L64: {L_computed}")
print(f"L (2^252+...): {l}")
print(f"Match: {L_computed == l}")

# S64 is used for Barrett reduction: S = floor(2^512 / l)
S64 = [0xd6ec31748d98951d, 0xc6ef5bf4737dcf70, 0xfffffffffffffffe, 0x0fffffffffffffff]
S_computed = S64[0] + (S64[1] << 64) + (S64[2] << 128) + (S64[3] << 192)
S_expected = (2**512) // l
print(f"\nS from S64: {S_computed}")
print(f"S = floor(2^512/l): {S_expected}")
print(f"S64 match: {S_computed == S_expected}")

# Now test: sc_reduce on known SHA-512 values
import hashlib

# Test with RFC verification: SHA-512(R||A)
R_bytes = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
A_bytes = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
sha_out = hashlib.sha512(R_bytes + A_bytes).digest()

print(f"\nSHA-512(R||A) = {sha_out.hex()}")

# Simulate sc_reduce
# Step 1: interpret as 8 uint64_t little-endian
def load_le64(b, offset):
    return int.from_bytes(b[offset:offset+8], 'little')

t = [load_le64(sha_out, 0), load_le64(sha_out, 8), load_le64(sha_out, 16), load_le64(sha_out, 24),
     load_le64(sha_out, 32), load_le64(sha_out, 40), load_le64(sha_out, 48), load_le64(sha_out, 56)]

print(f"t (loaded as LE64): {[hex(x) for x in t]}")

# Step 2: Barrett reduction loop
for _ in range(200):
    if t[4] | t[5] | t[6] | t[7] == 0:
        break
    hi = [t[4], t[5], t[6], t[7]]
    t[4] = t[5] = t[6] = t[7] = 0
    for pos in range(4):
        if hi[pos] == 0:
            continue
        p = [0, 0, 0, 0, 0]
        carry = 0
        for j in range(4):
            carry += hi[pos] * S64[j] + p[j]
            p[j] = carry & 0xFFFFFFFFFFFFFFFF
            carry >>= 64
        p[4] = carry & 0xFFFFFFFFFFFFFFFF
        carry = 0
        for j in range(5):
            carry += t[j + pos] + p[j]
            t[j + pos] = carry & 0xFFFFFFFFFFFFFFFF
            carry >>= 64
        j = 5 + pos
        while carry and j < 8:
            carry += t[j]
            t[j] = carry & 0xFFFFFFFFFFFFFFFF
            carry >>= 64
            j += 1

# Step 3: Conditional subtract L
for _ in range(10):
    cmp = 0
    for j in range(3, -1, -1):
        if t[j] > L64[j]:
            cmp = 1
            break
        if t[j] < L64[j]:
            cmp = -1
            break
    if cmp < 0:
        break
    borrow = 0
    for j in range(4):
        r = t[j] - L64[j] - borrow
        t[j] = r & 0xFFFFFFFFFFFFFFFF
        borrow = 1 if (r >> 64) else 0

# Step 4: Store result
def store_le64(b, offset, vals):
    for i, v in enumerate(vals):
        b[offset + 8*i:offset + 8*i + 8] = v.to_bytes(8, 'little')

result = bytearray(32)
store_le64(result, 0, t[:4])

print(f"sc_reduce result: {result.hex()}")

# Expected from Python: 
k_int = int.from_bytes(sha_out, 'little') % l
k_expected = k_int.to_bytes(32, 'little')
print(f"Expected k:       {k_expected.hex()}")

print(f"Match: {result.hex() == k_expected.hex()}")

# Also test with SHA-512(seed) for signature
seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])
h_seed = hashlib.sha512(seed).digest()
h_clamped = bytearray(h_seed)
h_clamped[0] &= 248
h_clamped[31] &= 127
h_clamped[31] |= 64
print(f"\nClamped scalar (Python): {h_clamped[:32].hex()}")

# Now simulate the full signing process with our sc_reduce
prefix = bytes(h_seed[32:])
r_hash = hashlib.sha512(prefix).digest()
print(f"SHA-512(prefix): {r_hash.hex()}")

# Our sc_reduce on r_hash
t_sig = [load_le64(r_hash, 0), load_le64(r_hash, 8), load_le64(r_hash, 16), load_le64(r_hash, 24),
         load_le64(r_hash, 32), load_le64(r_hash, 40), load_le64(r_hash, 48), load_le64(r_hash, 56)]

for _ in range(200):
    if t_sig[4] | t_sig[5] | t_sig[6] | t_sig[7] == 0:
        break
    # ... same reduction ...

# This is getting complex. Let me just compare raw int values.
sha_int = int.from_bytes(sha_out, 'little')
print(f"\nSHA-512(R||A) as LE int: {hex(sha_int)[:40]}...")
print(f"mod L: {hex(sha_int % l)}")
print(f"Expected k (little-endian hex): {k_expected.hex()}")
