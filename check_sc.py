#!/usr/bin/env python3
"""Compute correct Ed25519 basepoint Bx via Montgomery birational map from u=9"""
p = 2**255 - 19

# Montgomery curve: v^2 = u^3 + 486662*u^2 + u
A_mont = 486662
u = 9
v2 = (pow(u, 3, p) + A_mont * pow(u, 2, p) + u) % p
print(f"u = 9")
print(f"v^2 = {v2}")

# v = sqrt(v2)
v = pow(v2, (p+3)//8, p)
if pow(v, 2, p) != v2:
    sqrt_m1 = pow(2, (p-1)//4, p)
    v = v * sqrt_m1 % p
assert pow(v, 2, p) == v2, "v sqrt failed"
print(f"v = {v}")

# Birational map to Edwards:
# x = sqrt(-A-2) * u / v
# y = (u-1)/(u+1)
# d = -(A-2)/(A+2) = -486660/486664 = -121665/121666

sqrt_neg_A_minus_2 = pow(-A_mont - 2, (p+3)//8, p)
if pow(sqrt_neg_A_minus_2, 2, p) != (-A_mont - 2) % p:
    sqrt_m1 = pow(2, (p-1)//4, p)
    sqrt_neg_A_minus_2 = sqrt_neg_A_minus_2 * sqrt_m1 % p
assert pow(sqrt_neg_A_minus_2, 2, p) == (-A_mont - 2) % p

print(f"\nsqrt(-486664) = {sqrt_neg_A_minus_2}")

# Edwards coordinates
Bx_mont = sqrt_neg_A_minus_2 * u % p * pow(v, -1, p) % p
By_mont = (u - 1) * pow(u + 1, -1, p) % p

print(f"\nBx (from Montgomery) = {Bx_mont}")
print(f"By (from Montgomery) = {By_mont}")

# Verify By = 4/5
By_direct = 4 * pow(5, -1, p) % p
print(f"By direct = {By_direct}")
print(f"By match: {By_mont == By_direct}")

d = (-121665 * pow(121666, -1, p)) % p

# Verify B on twisted Edwards
lhs = (-pow(Bx_mont, 2, p) + pow(By_mont, 2, p)) % p
rhs = (1 + d * pow(Bx_mont, 2, p) * pow(By_mont, 2, p)) % p
print(f"\nB on twisted Edwards: LHS={lhs}, RHS={rhs}, match={lhs==rhs}")

# Compare with RFC
Bx_rfc = 15112221349535891490771889845789546913814871384922459474716389586016139295636
print(f"\nMontgomery-derived Bx: {Bx_mont}")
print(f"RFC Bx:                {Bx_rfc}")
print(f"Match: {Bx_mont == Bx_rfc}")

# Encode
print(f"\nBx hex (LE): {Bx_mont.to_bytes(32,'little').hex()}")
print(f"By hex (LE): {By_mont.to_bytes(32,'little').hex()}")

# Our derived Bx (wrong one)
our_Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
print(f"\nWrong Bx:         {our_Bx}")
print(f"Wrong Bx hex (LE):{our_Bx.to_bytes(32,'little').hex()}")
print(f"Correct Bx hex:   {Bx_mont.to_bytes(32,'little').hex()}")

# Check: is wrong Bx the "-v" choice? 
v_neg = (p - v) % p
Bx_alt = sqrt_neg_A_minus_2 * u % p * pow(v_neg, -1, p) % p
print(f"\nBx with -v: {Bx_alt}")
print(f"Match wrong: {Bx_alt == our_Bx}")
