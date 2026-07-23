#!/usr/bin/env python3
"""Use Python's ecdsa-like operations to verify Ed25519 point operations."""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

# Correct Bx
By = 4 * pow(5, -1, p) % p
y2 = pow(By, 2, p)
x2 = (y2 - 1) * pow(1 + d * y2, -1, p) % p
r = pow(x2, (p+3)//8, p)
if pow(r, 2, p) != x2:
    sqrt_m1 = pow(2, (p-1)//4, p)
    r = r * sqrt_m1 % p
if r & 1:
    r = p - r
Bx = r

# Check B on curve: -x^2 + y^2 = 1 + d*x^2*y^2
lhs = (pow(By, 2, p) - pow(Bx, 2, p)) % p
rhs = (1 + d * pow(Bx, 2, p) * pow(By, 2, p)) % p
print(f"B on curve: {lhs == rhs}")

# Hmm, let me check: maybe the curve equation is x^2 + y^2 = 1 + d*x^2*y^2 
# (untwisted Edwards, a=+1) with d being the NEGATIVE of what we have
# Ed25519 uses the twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2
# where d = -121665/121666

# Let me try the OTHER sign of d
d_alt = (121665 * pow(121666, -1, p)) % p
lhs_alt = (pow(By, 2, p) - pow(Bx, 2, p)) % p
rhs_alt = (1 + d_alt * pow(Bx, 2, p) * pow(By, 2, p)) % p
print(f"With d_alt: {lhs_alt == rhs_alt}")

# Also try: x^2 + y^2 = 1 + d*x^2*y^2 (untwisted)
lhs_unt = (pow(Bx, 2, p) + pow(By, 2, p)) % p
rhs_unt = (1 + d * pow(Bx, 2, p) * pow(By, 2, p)) % p
print(f"Untwisted with d: {lhs_unt == rhs_unt}")

lhs_unt2 = (pow(Bx, 2, p) + pow(By, 2, p)) % p
rhs_unt2 = (1 + d_alt * pow(Bx, 2, p) * pow(By, 2, p)) % p
print(f"Untwisted with d_alt: {lhs_unt2 == rhs_unt2}")

# Let's also try: maybe Bx is wrong. Let me get Bx from the RFC 8032 decimal value.
Bx_rfc = 15112221349535891490771889845789546913814871384922459474716389586016139295636

# Check RFC Bx on curve
lhs_rfc = (pow(By, 2, p) - pow(Bx_rfc, 2, p)) % p
rhs_rfc = (1 + d * pow(Bx_rfc, 2, p) * pow(By, 2, p)) % p
print(f"\nRFC Bx on twisted curve with d: {lhs_rfc == rhs_rfc}")

lhs_rfc2 = (pow(Bx_rfc, 2, p) + pow(By, 2, p)) % p
rhs_rfc2 = (1 + d * pow(Bx_rfc, 2, p) * pow(By, 2, p)) % p
print(f"RFC Bx on untwisted curve with d: {lhs_rfc2 == rhs_rfc2}")

lhs_rfc3 = (pow(By, 2, p) - pow(Bx_rfc, 2, p)) % p
rhs_rfc3 = (1 + d_alt * pow(Bx_rfc, 2, p) * pow(By, 2, p)) % p
print(f"RFC Bx on twisted curve with d_alt: {lhs_rfc3 == rhs_rfc3}")

lhs_rfc4 = (pow(Bx_rfc, 2, p) + pow(By, 2, p)) % p
rhs_rfc4 = (1 + d_alt * pow(Bx_rfc, 2, p) * pow(By, 2, p)) % p
print(f"RFC Bx on untwisted curve with d_alt: {lhs_rfc4 == rhs_rfc4}")

# Wait - the RFC 8032 decimal value might be wrong in my Python code.
# Let me re-read the RFC 8032 spec carefully.
# RFC 8032 Section 5.1:
# The basepoint is the same as in RFC 7748 Section 4.1 (Curve25519).
# But Ed25519 uses the twisted Edwards form, not Montgomery.
# 
# RFC 8032 says:
# Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
# By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
# 
# Wait, let me check: is Bx_rfc perhaps the x on the MONTGOMERY curve?
# The Montgomery curve is By^2 = Bx^3 + 486662*Bx^2 + Bx
# Let me check if Bx_rfc satisfies the Montgomery curve equation with x = Bx_rfc
mont_lhs = pow(By, 2, p)
mont_rhs = (pow(Bx_rfc, 3, p) + 486662 * pow(Bx_rfc, 2, p) + Bx_rfc) % p
print(f"\nMontgomery check with Bx_rfc: {mont_lhs == mont_rhs}")

# Hmm, what about with the computed Bx?
mont_lhs2 = pow(By, 2, p)
mont_rhs2 = (pow(Bx, 3, p) + 486662 * pow(Bx, 2, p) + Bx) % p
print(f"Montgomery check with computed Bx: {mont_lhs2 == mont_rhs2}")

# Let me just use the Python cryptography library to get the actual basepoint
# by deriving pub = 1 * B (i.e., scalar = 1)
# But Ed25519 clamps the scalar, so we can't use scalar=1 directly.
# However, we can use the RFC test vector to verify our point operations.

# Actually, let me use a proper Python Ed25519 implementation
# to compute 2B and compare.

# Simple affine point addition on twisted Edwards curve -x^2+y^2=1+d*x^2*y^2
def point_add_affine(P, Q, p, d):
    """Add two points on -x^2 + y^2 = 1 + d*x^2*y^2"""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    # For twisted Edwards with a=-1:
    # x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    # y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
    # Note: for a=-1, the formula is:
    # x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    # y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
    # With a=-1: y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
    t = d * x1 * x2 % p * y1 % p * y2 % p
    x3 = (x1 * y2 + x2 * y1) % p * pow(1 + t, -1, p) % p
    y3 = (y1 * y2 + x1 * x2) % p * pow(1 - t, -1, p) % p
    return (x3, y3)

def point_double_affine(P, p, d):
    return point_add_affine(P, P, p, d)

# Test with B = (Bx_computed, By)
B = (Bx, By)
B2 = point_double_affine(B, p, d)
print(f"\n=== 2B via affine doubling ===")
print(f"x = {B2[0]}")
print(f"y = {B2[1]}")

# Check 2B on curve
lhs_2b = (pow(B2[1], 2, p) - pow(B2[0], 2, p)) % p
rhs_2b = (1 + d * pow(B2[0], 2, p) * pow(B2[1], 2, p)) % p
print(f"2B on curve: {lhs_2b == rhs_2b}")

# Also try with Bx_rfc
B_rfc = (Bx_rfc, By)
B2_rfc = point_double_affine(B_rfc, p, d)
print(f"\n=== 2B (RFC Bx) via affine doubling ===")
print(f"x = {B2_rfc[0]}")
print(f"y = {B2_rfc[1]}")

lhs_2b_rfc = (pow(B2_rfc[1], 2, p) - pow(B2_rfc[0], 2, p)) % p
rhs_2b_rfc = (1 + d * pow(B2_rfc[0], 2, p) * pow(B2_rfc[1], 2, p)) % p
print(f"2B on curve: {lhs_2b_rfc == rhs_2b_rfc}")

# Actually, let me try the RFC Bx with POSITIVE d (untwisted)
d_pos = (121665 * pow(121666, -1, p)) % p
def point_double_untwisted(P, p, d):
    """Double on x^2 + y^2 = 1 + d*x^2*y^2"""
    x1, y1 = P
    t = d * x1 * x1 % p * y1 * y1 % p
    x3 = (2 * x1 * y1) % p * pow(1 + t, -1, p) % p
    y3 = (y1 * y1 - x1 * x1) % p * pow(1 - t, -1, p) % p
    return (x3, y3)

B2_unt = point_double_untwisted(B_rfc, p, d_pos)
print(f"\n=== 2B (RFC Bx, untwisted) ===")
print(f"x = {B2_unt[0]}")
print(f"y = {B2_unt[1]}")
lhs_2b_unt = (pow(B2_unt[0], 2, p) + pow(B2_unt[1], 2, p)) % p
rhs_2b_unt = (1 + d_pos * pow(B2_unt[0], 2, p) * pow(B2_unt[1], 2, p)) % p
print(f"2B on untwisted curve: {lhs_2b_unt == rhs_2b_unt}")

# Actually, the key question is: does the jpssl code produce the correct public key?
# Let me just verify by computing pub = scalar * B using Python
# with the SAME Bx that jpssl uses.
import hashlib

seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])

h = bytearray(hashlib.sha512(seed).digest())
h[0] &= 248
h[31] &= 127
h[31] |= 64
scalar = int.from_bytes(h[:32], 'little')

print(f"\n=== Scalar mult with computed Bx ===")
print(f"scalar = {scalar}")

def scalar_mult_affine(k, P, p, d):
    """Double-and-add scalar multiplication on twisted Edwards curve."""
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = point_add_affine(R, Q, p, d)
        Q = point_add_affine(Q, Q, p, d)
        k >>= 1
    return R

# Compute pub = scalar * B with computed Bx
pub_point = scalar_mult_affine(scalar, B, p, d)
print(f"pub point: x={pub_point[0]}")
print(f"           y={pub_point[1]}")
pub_bytes = pub_point[1].to_bytes(32, 'little')
if pub_point[0] & 1:
    pub_bytes = bytearray(pub_bytes)
    pub_bytes[31] |= 0x80
print(f"pub bytes: {pub_bytes.hex()}")
print(f"expected:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

# Also try with RFC Bx
pub_rfc = scalar_mult_affine(scalar, B_rfc, p, d)
print(f"\nWith RFC Bx:")
print(f"pub point: x={pub_rfc[0]}")
print(f"           y={pub_rfc[1]}")
pub_rfc_bytes = pub_rfc[1].to_bytes(32, 'little')
if pub_rfc[0] & 1:
    pub_rfc_bytes = bytearray(pub_rfc_bytes)
    pub_rfc_bytes[31] |= 0x80
print(f"pub bytes: {pub_rfc_bytes.hex()}")
