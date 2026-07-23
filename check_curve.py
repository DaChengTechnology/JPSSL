#!/usr/bin/env python3
"""Rigorously verify Ed25519 basepoint by deriving Bx from curve equation"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

# By = 4/5 mod p (RFC 8032)
By = 4 * pow(5, -1, p) % p
print(f"By = {By}")
print(f"By hex (LE): {By.to_bytes(32,'little').hex()}")

# Expected: 58 66 66 ... (repeating 66)
print(f"Expected:    5866666666666666666666666666666666666666666666666666666666666666")

By2 = pow(By, 2, p)
print(f"\nBy^2 = {By2}")

# From curve eq: -x^2 + y^2 = 1 + d*x^2*y^2
# => y^2 - x^2 = 1 + d*x^2*y^2
# => y^2 - 1 = x^2 * (1 + d*y^2)
# => x^2 = (y^2 - 1) / (1 + d*y^2)
num = (By2 - 1) % p
den = (1 + d * By2) % p
x2 = num * pow(den, -1, p) % p
print(f"x^2 = {x2}")

# Square root
x_cand = pow(x2, (p+3)//8, p)
print(f"x_cand^2 mod p = {pow(x_cand, 2, p)}")
print(f"x^2 = {x2}")
if pow(x_cand, 2, p) != x2:
    sqrt_m1 = pow(2, (p-1)//4, p)
    x_cand = x_cand * sqrt_m1 % p
    print(f"After sqrt_m1: x_cand = {x_cand}")
    print(f"x_cand^2 mod p = {pow(x_cand, 2, p)}")

assert pow(x_cand, 2, p) == x2, "sqrt failed"

# Choose even root
if x_cand & 1:
    x_cand = p - x_cand
    print(f"Negated to even: {x_cand}")

Bx = x_cand
print(f"\nBx = {Bx}")
print(f"Bx hex (LE): {Bx.to_bytes(32,'little').hex()}")

# Verify B on curve
lhs = (By2 - pow(Bx, 2, p)) % p
rhs = (1 + d * pow(Bx, 2, p) * By2) % p
print(f"\nLHS = {lhs}")
print(f"RHS = {rhs}")
print(f"B on curve: {lhs == rhs}")

# RFC Bx
Bx_rfc = 15112221349535891490771889845789546913814871384922459474716389586016139295636
print(f"\nRFC Bx:  {Bx_rfc}")
print(f"Our Bx:  {Bx}")
print(f"Match:   {Bx == Bx_rfc}")

# Compute 2B
Bx2_val = pow(Bx, 2, p)
t_val = d * Bx2_val % p * By2 % p
x3 = (2 * Bx * By) % p * pow(1 + t_val, -1, p) % p
y3 = (By2 + Bx2_val) % p * pow(1 - t_val, -1, p) % p

print(f"\n2B x = {x3}")
print(f"2B y = {y3}")

lhs2 = (-pow(x3,2,p) + pow(y3,2,p)) % p
rhs2 = (1 + d * pow(x3,2,p) * pow(y3,2,p)) % p
print(f"2B on curve: {lhs2 == rhs2}")

# Encode
y_enc = y3.to_bytes(32, 'little')
if x3 & 1:
    y_enc = bytearray(y_enc)
    y_enc[31] |= 0x80
    y_enc = bytes(y_enc)
print(f"2B encoded: {y_enc.hex()}")
print(f"jpssl 2B:   8e2d7ca65bc1760a1b4aad88a996b93ed114dce596cfe13a6e9e78d147a733e0")
print(f"x3 is even: {x3 % 2 == 0}")
