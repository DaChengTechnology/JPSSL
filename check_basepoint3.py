#!/usr/bin/env python3
"""Check if basepoint B is on the curve, then compute 2B correctly using Python bigint"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
print(f"p = {p}")
print(f"d = {d}")

# B from RFC 8032
Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960

print(f"\nBx = {Bx}")
print(f"By = {By}")

# Verify B on curve: -x^2 + y^2 = 1 + d*x^2*y^2
lhs = (-pow(Bx, 2, p) + pow(By, 2, p)) % p
rhs = (1 + d * pow(Bx, 2, p) * pow(By, 2, p)) % p
print(f"LHS = {lhs}")
print(f"RHS = {rhs}")
print(f"B on curve: {lhs == rhs}")

# Compute t for doubling: d * x^2 * y^2
Bx2 = pow(Bx, 2, p)
By2 = pow(By, 2, p)
t = (d * Bx2 % p * By2) % p
print(f"\nd*Bx^2*By^2 = {t}")

# Doubling formula for twisted Edwards a=-1:
# x3 = 2*x*y / (1 + d*x^2*y^2) = 2*x*y * (1+t)^(-1)
# y3 = (y^2 + x^2) / (1 - d*x^2*y^2) = (y^2 + x^2) * (1-t)^(-1)

x3 = (2 * Bx * By) % p
x3 = x3 * pow(1 + t, -1, p) % p

y3 = (By2 + Bx2) % p
y3 = y3 * pow(1 - t, -1, p) % p

print(f"\n2B x = {x3}")
print(f"2B y = {y3}")

# Verify 2B on curve
lhs2 = (-pow(x3, 2, p) + pow(y3, 2, p)) % p
rhs2 = (1 + d * pow(x3, 2, p) * pow(y3, 2, p)) % p
print(f"2B LHS = {lhs2}")
print(f"2B RHS = {rhs2}")
print(f"2B on curve: {lhs2 == rhs2}")

# Encode: y only, with sign bit
y_enc = y3.to_bytes(32, 'little')
if x3 & 1:
    y_enc = bytearray(y_enc)
    y_enc[31] |= 0x80
    y_enc = bytes(y_enc)
print(f"\n2B encoded: {y_enc.hex()}")
print(f"jpssl 2B:   8e2d7ca65bc1760a1b4aad88a996b93ed114dce596cfe13a6e9e78d147a733e0")

# Alternative: use untwisted formula (a=+1)
x3_u = (2 * Bx * By) % p
x3_u = x3_u * pow(1 + t, -1, p) % p
y3_u = (By2 - Bx2) % p
y3_u = y3_u * pow(1 - t, -1, p) % p
print(f"\nUntwisted 2B x: {x3_u}")
print(f"Untwisted 2B y: {y3_u}")
lhs_u = (pow(x3_u, 2, p) + pow(y3_u, 2, p)) % p
rhs_u = (1 + d * pow(x3_u, 2, p) * pow(y3_u, 2, p)) % p
print(f"Untwisted 2B on curve: {lhs_u == rhs_u}")
