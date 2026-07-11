#!/usr/bin/env python3
"""Verify X25519 ladder steps using Python's integer arithmetic in GF(2^255-19)"""
p = 2**255 - 19

def mont_ladder_step(x1, x2, z2, x3, z3, a24=121665):
    """One step of Montgomery ladder, all values in GF(p)"""
    A  = (x2 + z2) % p
    B  = (x2 - z2) % p
    C  = (x3 + z3) % p
    D  = (x3 - z3) % p
    DA = (D * A) % p
    CB = (C * B) % p
    x3_new = ((DA + CB) ** 2) % p
    z3_new = (x1 * ((DA - CB) ** 2)) % p
    x2_new = (A * A * B * B) % p
    t = (A*A - B*B) % p
    z2_new = (t * (A*A + a24 * t)) % p
    return x2_new, z2_new, x3_new, z3_new

# First round
x1 = 9
x2, z2 = 1, 0
x3, z3 = 9, 1

x2, z2, x3, z3 = mont_ladder_step(x1, x2, z2, x3, z3)
print(f"Round 1:")
print(f"  x2={x2}, z2={z2}, x3={x3}, z3={z3}")

# Verify: x3 = 324, z3 = 36
assert x3 == 324, f"Expected 324, got {x3}"
assert z3 == 36, f"Expected 36, got {z3}"
assert x2 == 1 and z2 == 0, f"Expected (1,0), got ({x2},{z2})"
print("  PASS: matches expected small values")

# Second round after swap (simulating bit=1 triggers cswap)
# After first round with swap=1: old x3,z3 ↔ old x2,z2
x2_s, z2_s = 324, 36   # was x3,z3
x3_s, z3_s = 1, 0      # was x2,z2

x2, z2, x3, z3 = mont_ladder_step(x1, x2_s, z2_s, x3_s, z3_s)
print(f"Round 2 (after cswap):")
print(f"  x2={x2}, z2={z2}, x3={x3}, z3={z3}")
# Expected: x3 = (360+288)^2 = 648^2 = 419904
#         z3 = 9 * (360-288)^2 = 9 * 5184 = 46656
#         x2 = 360^2 * 288^2 = 129600 * 82944 = 10748505600  等等...
# But mod p, but these are < p so no reduction

# Manual:
A = 324 + 36  # 360
B = 324 - 36  # 288
print(f"  A=360, B=288")
assert x3 == 419904, f"Expected x3=419904, got {x3}"
assert z3 == 46656, f"Expected z3=46656, got {z3}"
print(f"  x2={x2}, z2={z2}")
print("  PASS")

# Now run full X25519 with RFC test vector
def x25519(scalar_bytes, point_bytes):
    """RFC 7748 X25519"""
    u = int.from_bytes(point_bytes, 'little')
    
    # Clamp
    e = bytearray(scalar_bytes)
    e[0] &= 248
    e[31] &= 127
    e[31] |= 64
    k = int.from_bytes(e, 'little')
    
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        
        A  = (x2 + z2) % p
        AA = (A * A) % p
        B  = (x2 - z2) % p
        BB = (B * B) % p
        E  = (AA - BB) % p
        C  = (x3 + z3) % p
        D  = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = ((DA + CB) ** 2) % p
        z3 = (x1 * ((DA - CB) ** 2)) % p
        x2 = (AA * BB) % p
        z2 = (E * (AA + 121665 * E)) % p
    
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    
    # Result = x2 * z2^(p-2) mod p
    result = (x2 * pow(z2, p - 2, p)) % p
    return result.to_bytes(32, 'little')

# RFC 7748 Test Vector 1
alice_priv = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
expected_pub = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
# Basepoint = 9
basepoint = (9).to_bytes(32, 'little')

pub = x25519(alice_priv, basepoint)
print(f"\nFull X25519 test:")
print(f"  Result:   {pub.hex()}")
print(f"  Expected: {expected_pub.hex()}")
print(f"  MATCH: {pub == expected_pub}")

# Also test shared secret
bob_priv = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
bob_pub_expected = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
shared_expected = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')

bob_pub = x25519(bob_priv, basepoint)
print(f"  Bob pub:   {bob_pub.hex()}")
print(f"  Expected:  {bob_pub_expected.hex()}")
print(f"  MATCH: {bob_pub == bob_pub_expected}")

shared_alice = x25519(alice_priv, bob_pub_expected)
print(f"  Alice shared: {shared_alice.hex()}")
print(f"  Expected:     {shared_expected.hex()}")
print(f"  MATCH: {shared_alice == shared_expected}")
