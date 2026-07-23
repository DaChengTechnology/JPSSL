#!/usr/bin/env python3
"""Verify Ed25519 doubling formula by implementing both standard and jpssl"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

# Basepoint from RFC
Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960

# Convert to 10-limb radix 2^25.5 representation
def to_limbs(x):
    b = x.to_bytes(32, 'little')
    h0 = b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24)
    h1 = (b[4] | (b[5]<<8) | (b[6]<<16)) << 6
    h2 = (b[7] | (b[8]<<8) | (b[9]<<16)) << 5
    h3 = (b[10] | (b[11]<<8) | (b[12]<<16)) << 3
    h4 = (b[13] | (b[14]<<8) | (b[15]<<16)) << 2
    h5 = b[16] | (b[17]<<8) | (b[18]<<16) | (b[19]<<24)
    h6 = (b[20] | (b[21]<<8) | (b[22]<<16)) << 7
    h7 = (b[23] | (b[24]<<8) | (b[25]<<16)) << 5
    h8 = (b[26] | (b[27]<<8) | (b[28]<<16)) << 4
    h9 = ((b[29] | (b[30]<<8) | (b[31]<<16)) & 0x7fffff) << 2
    # two-pass carry
    for _ in range(2):
        c = h0 >> 26; h1 += c; h0 -= c << 26
        c = h1 >> 25; h2 += c; h1 -= c << 25
        c = h2 >> 26; h3 += c; h2 -= c << 26
        c = h3 >> 25; h4 += c; h3 -= c << 25
        c = h4 >> 26; h5 += c; h4 -= c << 26
        c = h5 >> 25; h6 += c; h5 -= c << 25
        c = h6 >> 26; h7 += c; h6 -= c << 26
        c = h7 >> 25; h8 += c; h7 -= c << 25
        c = h8 >> 26; h9 += c; h8 -= c << 26
        c = h9 >> 25; h0 += c * 19; h9 -= c << 25
    return [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9]

def from_limbs(limbs):
    """Convert limbs back to integer"""
    h = limbs[:]
    # freeze
    q = (19 * h[9] + (1 << 24)) >> 25
    q = (h[0] + q) >> 26
    q = (h[1] + q) >> 25
    q = (h[2] + q) >> 26
    q = (h[3] + q) >> 25
    q = (h[4] + q) >> 26
    q = (h[5] + q) >> 25
    q = (h[6] + q) >> 26
    q = (h[7] + q) >> 25
    q = (h[8] + q) >> 26
    q = (h[9] + q) >> 25
    h[0] += 19 * q
    # carry
    c = h[0] >> 26; h[1] += c; h[0] &= 0x3ffffff
    c = h[1] >> 25; h[2] += c; h[1] &= 0x1ffffff
    c = h[2] >> 26; h[3] += c; h[2] &= 0x3ffffff
    c = h[3] >> 25; h[4] += c; h[3] &= 0x1ffffff
    c = h[4] >> 26; h[5] += c; h[4] &= 0x3ffffff
    c = h[5] >> 25; h[6] += c; h[5] &= 0x1ffffff
    c = h[6] >> 26; h[7] += c; h[6] &= 0x3ffffff
    c = h[7] >> 25; h[8] += c; h[7] &= 0x1ffffff
    c = h[8] >> 26; h[9] += c; h[8] &= 0x3ffffff
    h[9] &= 0x1ffffff
    # pack
    result = h[0] | (h[1] & 0x3f) << 26
    result |= h[1] >> 6 | (h[2] & 0x1f) << 19
    result |= h[2] >> 5 | (h[3] & 0x7) << 16
    result |= h[3] >> 3 | (h[4] & 0x3) << 14
    result |= h[4] >> 2 << 12
    return result

# Simple Python big-integer fe operations
def fe_add(a, b): return (a + b) % p
def fe_sub(a, b): return (a - b) % p  
def fe_mul(a, b): return (a * b) % p
def fe_sq(a): return (a * a) % p
def fe_neg(a): return (-a) % p

# d2 constant
d2_int = (2 * d) % p

# ============================================================
# Simulate jpssl's ge_p2_dbl exactly
# ============================================================
def jpssl_ge_p2_dbl_affine(x, y, z):
    """
    Simulate jpssl's ge_p2_dbl on affine coordinates via projective with Z=1
    p2 has (X, Y, Z) where T = X*Y/Z implicitly
    """
    A = fe_sq(x)     # r->X
    B = fe_sq(y)     # r->Z
    C = fe_add(fe_sq(z), fe_sq(z))  # r->T = 2*Z^2
    t0 = fe_sq(fe_add(x, y))  # (X+Y)^2
    H = fe_add(B, A)     # r->Y = A+B (jpssl calls this Y)
    G = fe_sub(B, A)     # r->Z = B-A (jpssl calls this Z)
    E = fe_sub(t0, H)    # r->X = (X+Y)^2 - (A+B) = 2XY
    F_neg = fe_sub(C, G)  # r->T = C - (B-A) = -F (NOT F!)
    
    # p1p1: {X=E, Y=H, Z=G, T=-F}
    # p1p1_to_p3: X3=E*(-F), Y3=H*G, Z3=G*(-F), T3=E*H
    X3 = fe_mul(E, F_neg)   # E * (-F) 
    Y3 = fe_mul(H, G)       # H * G
    Z3 = fe_mul(G, F_neg)   # G * (-F)
    T3 = fe_mul(E, H)       # E * H
    
    return X3, Y3, Z3, T3

# ============================================================
# Standard doubling (from libsodium/ed25519_ref10)
# ============================================================
def standard_ge_p2_dbl_affine(x, y, z):
    """
    Standard p2 doubling formula (from RFC 8032 / ed25519_ref10)
    """
    A = fe_sq(x)
    B = fe_sq(y)
    C = fe_add(fe_sq(z), fe_sq(z))   # 2*Z^2
    D = fe_neg(A)                     # -A  (since a = -1)
    E = fe_sub(fe_sub(fe_sq(fe_add(x, y)), A), B)  # (X+Y)^2 - A - B = 2XY
    G = fe_add(D, B)                  # B - A
    F = fe_sub(G, C)                  # B - A - 2*Z^2
    H = fe_sub(D, B)                  # -A - B
    
    X3 = fe_mul(E, F)
    Y3 = fe_mul(G, H)
    Z3 = fe_mul(F, G)
    T3 = fe_mul(E, H)
    
    return X3, Y3, Z3, T3

# Test with basepoint (Z=1)
x, y, z = Bx, By, 1

print("=== 2*B comparison ===")
Xj, Yj, Zj, Tj = jpssl_ge_p2_dbl_affine(x, y, z)
Xs, Ys, Zs, Ts = standard_ge_p2_dbl_affine(x, y, z)

# Convert to affine
inv_zj = pow(Zj, -1, p)
inv_zs = pow(Zs, -1, p)

xj_aff = (Xj * inv_zj) % p
yj_aff = (Yj * inv_zj) % p
xs_aff = (Xs * inv_zs) % p
ys_aff = (Ys * inv_zs) % p

print(f"jpssl 2B: x={xj_aff}, y={yj_aff}")
print(f"std   2B: x={xs_aff}, y={ys_aff}")
print(f"jpssl == std: {xj_aff == xs_aff and yj_aff == ys_aff}")

# Encode y only (like Ed25519)
if xj_aff & 1:
    yj_bytes = bytearray(yj_aff.to_bytes(32, 'little'))
    yj_bytes[31] |= 0x80
else:
    yj_bytes = yj_aff.to_bytes(32, 'little')
print(f"jpssl 2B encoded: {yj_bytes.hex()}")

if xs_aff & 1:
    ys_bytes = bytearray(ys_aff.to_bytes(32, 'little'))
    ys_bytes[31] |= 0x80
else:
    ys_bytes = ys_aff.to_bytes(32, 'little')
print(f"std   2B encoded: {ys_bytes.hex()}")

print(f"\nExpected from test output (jpssl C): c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022")
print(f"Expected from Python ref:             6f6ded8bb2ecda5ff43fba8216ab4628841516838bdf662bba0ddb7232a4913b")

# Debug: check intermediate values
print(f"\n=== Intermediate values ===")
A = fe_sq(x)
B = fe_sq(y)
C = fe_add(fe_sq(z), fe_sq(z))
t0 = fe_sq(fe_add(x, y))
E = fe_sub(fe_sub(t0, A), B)  # 2XY
H_jpssl = fe_add(B, A)       # A+B
G = fe_sub(B, A)              # B-A
F = fe_sub(G, C)              # B-A-2Z^2
F_neg_jpssl = fe_sub(C, G)    # 2Z^2 - (B-A) = -F

H_std = fe_sub(fe_neg(A), B)  # -A - B = -(A+B)

print(f"A = X^2 = {A}")
print(f"B = Y^2 = {B}")
print(f"C = 2Z^2 = {C}")
print(f"(X+Y)^2 = {t0}")
print(f"E = 2XY = {E}")
print(f"G = B-A = {G}")
print(f"F = B-A-2Z^2 = {F}")
print(f"jpssl F_neg = C-G = {F_neg_jpssl}")
print(f"F + F_neg_jpssl mod p = {(F + F_neg_jpssl) % p}")  # should be 0

print(f"\nH_jpssl = A+B = {H_jpssl}")
print(f"H_std = -A-B = {H_std}")
print(f"H_jpssl + H_std mod p = {(H_jpssl + H_std) % p}")

# Now compute both p1p1_to_p3 results
X3_jpssl = (E * F_neg_jpssl) % p
Y3_jpssl = (H_jpssl * G) % p
Z3_jpssl = (G * F_neg_jpssl) % p

X3_std = (E * F) % p
Y3_std = (G * H_std) % p
Z3_std = (F * G) % p

print(f"\n=== p1p1_to_p3 results ===")
print(f"jpssl: X3={X3_jpssl}, Y3={Y3_jpssl}, Z3={Z3_jpssl}")
print(f"std:   X3={X3_std}, Y3={Y3_std}, Z3={Z3_std}")
print(f"ratio X3: {X3_jpssl * pow(X3_std, -1, p) % p}")
print(f"ratio Y3: {Y3_jpssl * pow(Y3_std, -1, p) % p}")
print(f"ratio Z3: {Z3_jpssl * pow(Z3_std, -1, p) % p}")

# Since X3_jpssl = -X3_std, Y3_jpssl = -Y3_std, Z3_jpssl = -Z3_std
# Then the affine point should be the same: (-X)/(-Z) = X/Z, (-Y)/(-Z) = Y/Z
# This should work! Let me verify with 2B specifically...
print(f"\nX3_jpssl / Z3_jpssl = {X3_jpssl * pow(Z3_jpssl, -1, p) % p}")
print(f"X3_std / Z3_std = {X3_std * pow(Z3_std, -1, p) % p}")
print(f"Match: {X3_jpssl * pow(Z3_jpssl, -1, p) % p == X3_std * pow(Z3_std, -1, p) % p}")
