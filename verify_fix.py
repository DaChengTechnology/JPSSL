#!/usr/bin/env python3
"""Python reference: compute k*A step by step and compare with jpssl"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

# A from RFC 8032 Test 1
A_enc = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
A_y_int = int.from_bytes(A_enc, 'little')
sign_bit = (A_y_int >> 255) & 1
A_y = A_y_int & ((1 << 255) - 1)

# Recover A_x
A_y2 = pow(A_y, 2, p)
num = (A_y2 - 1) % p
den = (1 + d * A_y2) % p
A_x2 = num * pow(den, -1, p) % p
A_x = pow(A_x2, (p+3)//8, p)
if pow(A_x, 2, p) != A_x2:
    sqrt_m1 = pow(2, (p-1)//4, p)
    A_x = A_x * sqrt_m1 % p
if (A_x & 1) != sign_bit:
    A_x = p - A_x

print(f"A_x = {A_x}")
print(f"A_y = {A_y}")
print(f"A on curve: {(-pow(A_x,2,p)+pow(A_y,2,p))%p == (1+d*pow(A_x,2,p)*pow(A_y,2,p))%p}")

# k from RFC test
k = bytes.fromhex("0454522e167e3e8a132cec316125d8f86cdf00c6e70405293d19964c8eeabc86")
k_int = int.from_bytes(k, 'little')
print(f"\nk = {k_int}")
print(f"k bits 255-248: {bin(k_int)[2:].zfill(256)[0:8]}")

# Affine point operations
def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    t = d * x1 * x2 % p * y1 % p * y2 % p
    x3 = (x1 * y2 + x2 * y1) % p * pow(1 + t, -1, p) % p
    y3 = (y1 * y2 + x1 * x2) % p * pow(1 - t, -1, p) % p
    return (x3, y3)

def point_double(P):
    return point_add(P, P)

def scalar_mult_affine(k_val, P):
    R = None
    Q = P
    while k_val:
        if k_val & 1:
            R = point_add(R, Q)
        Q = point_double(Q)
        k_val >>= 1
    return R

# Compute k*A
kA_py = scalar_mult_affine(k_int, (A_x, A_y))
print(f"\nk*A (Python): x={kA_py[0]}, y={kA_py[1]}")
y_enc = kA_py[1].to_bytes(32, 'little')
if kA_py[0] & 1:
    y_enc = bytearray(y_enc)
    y_enc[31] |= 0x80
    y_enc = bytes(y_enc)
print(f"k*A encoded (Python): {y_enc.hex()}")
print(f"Expected from earlier gen: 9d890a59a69e9fc6e2901b2f8467fc5cdf215e9965e91e4fc4b5ba332adece0d")
print(f"jpssl k*A:                 a0d8279f86fe92e92c9df07dbc68da5d97d07c588e50684e5b0d6dd4d34a113a")

# Compare with expected from RFC (S*B - k*A should be R)
S = bytes.fromhex("0b107a8e4341516524be5b59f0f55bd26bb4f91c70391ec6ac3ba3901582b85f")
S_int = int.from_bytes(S, 'little')
By = 4 * pow(5, -1, p) % p
Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
B = (Bx, By)
SB = scalar_mult_affine(S_int, B)
print(f"\nS*B (Python): x={SB[0]}, y={SB[1]}")
SB_y_enc = SB[1].to_bytes(32, 'little')
if SB[0] & 1:
    SB_y_enc = bytearray(SB_y_enc)
    SB_y_enc[31] |= 0x80
    SB_y_enc = bytes(SB_y_enc)
print(f"S*B encoded: {SB_y_enc.hex()}")

# neg_kA
neg_kA = ((p - kA_py[0]) % p, kA_py[1])
R_calc = point_add(SB, neg_kA)
print(f"\nS*B - k*A: x={R_calc[0]}, y={R_calc[1]}")
R_calc_y = R_calc[1].to_bytes(32, 'little')
if R_calc[0] & 1:
    R_calc_y = bytearray(R_calc_y)
    R_calc_y[31] |= 0x80
    R_calc_y = bytes(R_calc_y)
print(f"S*B - k*A encoded: {R_calc_y.hex()}")
print(f"Expected R:        e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
print(f"Match: {R_calc_y.hex() == 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'}")
