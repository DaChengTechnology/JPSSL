#!/usr/bin/env python3
"""Find correct T3 for p1p1_to_p3."""
import hashlib
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
d2 = (2 * d) % p

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
B = (Bx, By, 1, Bx * By % p)

def ge_p2_dbl(P):
    X, Y, Z, _ = P
    A = pow(X, 2, p); B = pow(Y, 2, p); C = 2 * pow(Z, 2, p)
    E = (pow((X + Y) % p, 2, p) - A - B) % p
    G = (B - A) % p; F = (G - C) % p; H = (-(A + B)) % p
    return (E * F % p, G * H % p, F * G % p, E * H % p)

def ge_add(P, Q):
    X1, Y1, Z1, T1 = P; X2, Y2, Z2, T2 = Q
    a = (Y1 - X1) * (Y2 - X2) % p
    b = (Y1 + X1) * (Y2 + X2) % p
    c = T1 * T2 % p * d2 % p
    dd = Z1 * Z2 % p * 2 % p
    e = (b - a) % p; f = (dd - c) % p; g = (dd + c) % p; h = (b + a) % p
    return (e * f % p, g * h % p, f * g % p, e * h % p)

# Test 2B: X3=XT, Y3=YT, Z3=ZT, find correct T3
p1p1 = ge_add(B, B)
X_p, Y_p, Z_p, T_p = p1p1
Z3 = Z_p * T_p % p
x_2b = X_p * T_p % p * pow(Z3, -1, p) % p
y_2b = Y_p * T_p % p * pow(Z3, -1, p) % p

# T3 should satisfy: T3/Z3 = x*y
target_t = x_2b * y_2b % p
print(f"Target T3/Z3 = {target_t}")
print(f"x*y = {x_2b * y_2b % p}")

# Try all products for T3
for tname, tval in [("XY", X_p*Y_p%p), ("XZ", X_p*Z_p%p), ("XT", X_p*T_p%p),
                      ("YZ", Y_p*Z_p%p), ("YT", Y_p*T_p%p), ("ZT", Z_p*T_p%p)]:
    if tname in ("XT", "YT", "ZT"):  # already used
        continue
    t_ratio = tval * pow(Z3, -1, p) % p
    print(f"T3={tname}: T3/Z3 == x*y? {t_ratio == target_t}")

# Full scalar mult with correct T3
# Try T3 = X*Z
def p1p1_to_p3_xz(P1P1):
    X, Y, Z, T = P1P1
    return (X * T % p, Y * T % p, Z * T % p, X * Z % p)

# Try T3 = Y*Z
def p1p1_to_p3_yz(P1P1):
    X, Y, Z, T = P1P1
    return (X * T % p, Y * T % p, Z * T % p, Y * Z % p)

def ge_scalarmult_base(scalar_bytes, conv_func):
    first = -1
    for i in range(255, -1, -1):
        if (scalar_bytes[i >> 3] >> (i & 7)) & 1:
            first = i; break
    if first < 0:
        return (0, 1, 1, 0)
    R = B
    for i in range(first - 1, -1, -1):
        t = ge_p2_dbl(R)
        R = conv_func(t)
        if (scalar_bytes[i >> 3] >> (i & 7)) & 1:
            t = ge_add(R, B)
            R = conv_func(t)
    return R

seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])
h = bytearray(hashlib.sha512(seed).digest())
h[0] &= 248; h[31] &= 127; h[31] |= 64

for name, conv in [("T3=XY", lambda P: (P[0]*P[3]%p, P[1]*P[3]%p, P[2]*P[3]%p, P[0]*P[1]%p)),
                   ("T3=XZ", p1p1_to_p3_xz),
                   ("T3=YZ", p1p1_to_p3_yz)]:
    A = ge_scalarmult_base(bytes(h[:32]), conv)
    x = A[0] * pow(A[2], -1, p) % p
    y = A[1] * pow(A[2], -1, p) % p
    pub = bytearray(y.to_bytes(32, 'little'))
    if x & 1: pub[31] |= 0x80
    t_inv = A[3] * pow(A[2], -1, p) % p
    print(f"\n{name}: pub={pub.hex()}")
    print(f"  match={pub.hex() == 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'}")
    print(f"  T==x*y: {t_inv == (x*y) % p}")
