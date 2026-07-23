#!/usr/bin/env python3
"""Correct Python reference: compute k*A and S*B with correct k"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
l = 2**252 + 27742317777372353535851937790883648493
import hashlib

# Correct k from SHA-512(R||A) mod l 
R = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
A_enc = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
k_hash = hashlib.sha512(R + A_enc).digest()
k_int = int.from_bytes(k_hash, 'little') % l
k_bytes = k_int.to_bytes(32, 'little')
print(f"k = {k_bytes.hex()}")

# S from signature
sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
S_bytes = sig[32:]
S_int = int.from_bytes(S_bytes, 'little')
print(f"S = {S_bytes.hex()}")

# Recover A_x from A_y
A_y_int = int.from_bytes(A_enc, 'little')
sign_bit = (A_y_int >> 255) & 1
A_y = A_y_int & ((1 << 255) - 1)
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

# Basepoint 
By = 4 * pow(5, -1, p) % p
# Bx from jpssl (correct twisted Edwards Bx)
Bx_jpssl = 15112221349535400772501151409588531511454012693041857206046113283949847762202
B = (Bx_jpssl, By)

# Affine point ops
def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    t_val = d * x1 * x2 % p * y1 % p * y2 % p
    x3 = (x1 * y2 + x2 * y1) % p * pow(1 + t_val, -1, p) % p
    y3 = (y1 * y2 + x1 * x2) % p * pow(1 - t_val, -1, p) % p
    return (x3, y3)

def scalar_mult(k_val, P):
    R = None
    Q = P
    while k_val:
        if k_val & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k_val >>= 1
    return R

# Compute k*A
A = (A_x, A_y)
kA = scalar_mult(k_int, A)
print(f"\nk*A: x={kA[0]}, y={kA[1]}")

# Compute S*B
SB = scalar_mult(S_int, B)
print(f"S*B: x={SB[0]}, y={SB[1]}")

# S*B - k*A (should equal R)
neg_kA = ((p - kA[0]) % p, kA[1])
SB_minus_kA = point_add(SB, neg_kA)
R_y = SB_minus_kA[1].to_bytes(32, 'little')
R_calc = int.from_bytes(R_y, 'little')
if SB_minus_kA[0] & 1:
    R_calc |= (1 << 255)
R_calc_bytes = R_calc.to_bytes(32, 'little')

print(f"\nS*B - k*A: x={SB_minus_kA[0]}, y={SB_minus_kA[1]}")
print(f"S*B - k*A encoded: {R_calc_bytes.hex()}")
print(f"Expected R:        {R.hex()}")
print(f"Match: {R_calc_bytes.hex() == R.hex()}")

# Encode k*A and S*B
kA_y = kA[1].to_bytes(32, 'little')
kA_enc = int.from_bytes(kA_y, 'little')
if kA[0] & 1: kA_enc |= (1 << 255)
print(f"\nk*A encoded: {kA_enc.to_bytes(32, 'little').hex()}")

SB_y = SB[1].to_bytes(32, 'little')
SB_enc = int.from_bytes(SB_y, 'little')
if SB[0] & 1: SB_enc |= (1 << 255)
print(f"S*B encoded: {SB_enc.to_bytes(32, 'little').hex()}")
