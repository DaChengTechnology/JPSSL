#!/usr/bin/env python3
"""Compute 2*B using pure affine doubling and compare with jpssl"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960

# Affine doubling on twisted Edwards -x^2+y^2=1+d*x^2*y^2
# x3 = (2*x1*y1) / (1 + d*x1^2*y1^2)
# y3 = (y1^2 + x1^2) / (1 - d*x1^2*y1^2)
# Actually for a=-1: x3 = (2*x*y)/(1 + d*x^2*y^2), y3 = (y^2 + x^2)/(1 - d*x^2*y^2)
# Wait, let me re-derive:
# For twisted Edwards with a=-1: -x^2 + y^2 = 1 + d*x^2*y^2
# Doubling formula: 
#   B = (x1 + y1)^2
#   C = x1^2
#   D = y1^2
#   E = a*C = -C
#   F = E + D = D - C
#   H = Z1^2  (Z=1 in affine)
#   I = 2*H = 2
#   J = F - I = D - C - 2
#   Wait, I'm confusing myself.
#
# Let me use the simple well-known doubling formula:
# For curve x^2 + y^2 = 1 + d*x^2*y^2 (untwisted) or -x^2 + y^2 = 1 + d*x^2*y^2 (twisted a=-1)
#
# The unified addition formula for twisted Edwards with a=-1:
#   x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
#   y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
#
# For doubling (x2=x1, y2=y1):
#   x3 = (2*x*y) / (1 + d*x^2*y^2)
#   y3 = (y^2 + x^2) / (1 - d*x^2*y^2)

t_num = d * pow(Bx, 2, p) % p * pow(By, 2, p) % p
x3 = (2 * Bx * By) % p * pow(1 + t_num, -1, p) % p
y3 = (pow(By, 2, p) + pow(Bx, 2, p)) % p * pow(1 - t_num, -1, p) % p

print(f"2B x = {x3}")
print(f"2B y = {y3}")
y_enc = y3.to_bytes(32, 'little')
if x3 & 1:
    y_enc = bytearray(y_enc)
    y_enc[31] |= 0x80
    y_enc = bytes(y_enc)
print(f"2B encoded: {y_enc.hex()}")
print(f"x3 is even: {x3 % 2 == 0}")

# Verify on curve
lhs = (-pow(x3, 2, p) + pow(y3, 2, p)) % p
rhs = (1 + d * pow(x3, 2, p) * pow(y3, 2, p)) % p
print(f"2B on curve: {lhs == rhs}")

# Now also test: what is jpssl 2*B value?
jpssl_2b = bytes.fromhex("8e2d7ca65bc1760a1b4aad88a996b93ed114dce596cfe13a6e9e78d147a733e0")
jpssl_2b_y = int.from_bytes(jpssl_2b, 'little')
sign_bit = (jpssl_2b_y >> 255) & 1
jpssl_2b_y = jpssl_2b_y & ((1 << 255) - 1)
print(f"\njpssl 2B y: {jpssl_2b_y}")
print(f"jpssl sign bit: {sign_bit}")
print(f"Correct y: {y3}")
print(f"y match: {jpssl_2b_y == y3}")
print(f"x3 even matches sign bit=0: {(x3 % 2 == 0) == (sign_bit == 0)}")

# What was the "expected" 6f6ded8b...?
alt_2b = bytes.fromhex("6f6ded8bb2ecda5ff43fba8216ab4628841516838bdf662bba0ddb7232a4913b")
alt_2b_y = int.from_bytes(alt_2b, 'little') & ((1 << 255) - 1)
print(f"\nAlternate 2B y: {alt_2b_y}")
print(f"y match correct: {alt_2b_y == y3}")

# The alt seems to correspond to a different point. Let me check what x it corresponds to.
# Recover x from y
y2_alt = pow(alt_2b_y, 2, p)
u_alt = (y2_alt - 1) % p
v_alt = (1 + d * y2_alt) % p
x2_alt = u_alt * pow(v_alt, -1, p) % p
x_alt = pow(x2_alt, (p+3)//8, p)
if pow(x_alt, 2, p) != x2_alt:
    sqrt_m1 = pow(2, (p-1)//4, p)
    x_alt = x_alt * sqrt_m1 % p
print(f"Alt 2B x: {x_alt}")
print(f"Alt 2B on curve: {(-pow(x_alt,2,p)+pow(alt_2b_y,2,p))%p == (1+d*pow(x_alt,2,p)*pow(alt_2b_y,2,p))%p}")
