#!/usr/bin/env python3
"""Compute correct 2B coordinates and compare with jpssl output."""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

# Correct basepoint (matches jpssl constants)
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

print(f"Bx = {Bx}")
print(f"By = {By}")
print(f"B on curve: {(-pow(Bx,2,p) + pow(By,2,p)) % p == (1 + d*pow(Bx,2,p)*pow(By,2,p)) % p}")

# Correct doubling formula for a=-1 (RFC 8032)
X, Y, Z = Bx, By, 1
A = pow(X, 2, p)
B = pow(Y, 2, p)
C = 2 * pow(Z, 2, p)
D = (-A) % p
E = (pow((X + Y) % p, 2, p) - A - B) % p
F = (D - C) % p
G = (D - B) % p
H = (D + B) % p

X3 = E * F % p
Y3 = G * H % p
T3 = E * H % p
Z3 = F * G % p

x3 = X3 * pow(Z3, -1, p) % p
y3 = Y3 * pow(Z3, -1, p) % p
t3 = T3 * pow(Z3, -1, p) % p

print(f"\n2B x = {x3}")
print(f"2B y = {y3}")
print(f"2B x bytes = {x3.to_bytes(32, 'little').hex()}")
print(f"2B y bytes = {y3.to_bytes(32, 'little').hex()}")

# Verify on curve
lhs = (-pow(x3, 2, p) + pow(y3, 2, p)) % p
rhs = (1 + d * pow(x3, 2, p) * pow(y3, 2, p)) % p
print(f"2B on curve: {lhs == rhs}")
print(f"T == x*y: {t3 == (x3 * y3) % p}")

# Also verify via simple affine doubling
def point_double_affine(x, y, p, d):
    t = d * x * x % p * y * y % p
    x3 = (2 * x * y) % p * pow(1 + t, -1, p) % p
    y3 = (y * y - x * x) % p * pow(1 - t, -1, p) % p
    return x3, y3

x_dbl, y_dbl = point_double_affine(Bx, By, p, d)
print(f"\nAffine doubling check:")
print(f"2B x = {x_dbl}")
print(f"2B y = {y_dbl}")
print(f"Match: {x_dbl == x3 and y_dbl == y3}")

# jpssl output for 2B was:
# 8377d2aea705716b7865fdda04145c46a19930d39c4d473b709dc53bbe3b4c5f
jpssl_2b = bytes.fromhex("8377d2aea705716b7865fdda04145c46a19930d39c4d473b709dc53bbe3b4c5f")
print(f"\njpssl 2B bytes: {jpssl_2b.hex()}")
print(f"correct 2B bytes: {y3.to_bytes(32, 'little').hex()}")
# The sign bit is in the last byte
y3_bytes = bytearray(y3.to_bytes(32, 'little'))
if x3 & 1:
    y3_bytes[31] |= 0x80
print(f"correct 2B (with sign): {y3_bytes.hex()}")
