#!/usr/bin/env python3
import hashlib
p = 2**448 - 2**224 - 1
d = (-39081) % p
L = 2**446 - 13818066809895115352007386748515426880336692474882178609894552837804553022741537

def fe_add(a, b): return (a + b) % p
def fe_sub(a, b): return (a - b) % p
def fe_mul(a, b): return (a * b) % p
def fe_sq(a): return (a * a) % p
def fe_inv(a): return pow(a, p - 2, p)

def point_add(P, Q):
    X1, Y1, Z1 = P; X2, Y2, Z2 = Q
    A = fe_mul(Z1, Z2); B = fe_sq(A)
    C = fe_mul(X1, X2); D = fe_mul(Y1, Y2)
    E = fe_mul(fe_mul(C, D), d)
    F = fe_sub(B, E); G = fe_add(B, E)
    H = fe_mul(fe_add(X1, Y1), fe_add(X2, Y2))
    return (fe_mul(fe_mul(A, F), fe_sub(fe_sub(H, C), D)),
            fe_mul(fe_mul(A, G), fe_sub(D, C)),
            fe_mul(F, G))

def scalar_mult(s, P):
    Q = (0, 1, 1); cur = P
    for i in range(448):
        if (s >> i) & 1: Q = point_add(Q, cur)
        cur = point_add(cur, cur)
    return Q

# Test: [1] * P = P
P = (3, 4, 1)  # some point, not on curve but tests arithmetic
R1 = scalar_mult(1, P)
zi = fe_inv(R1[2])
print("[1]*P == P?", fe_mul(R1[0], zi) == P[0], fe_mul(R1[1], zi) == P[1])

# Test: [2]*P == P+P
R2 = scalar_mult(2, P)
Rpp = point_add(P, P)
zi2 = fe_inv(R2[2]); zi3 = fe_inv(Rpp[2])
print("[2]*P == P+P?", fe_mul(R2[0], zi2) == fe_mul(Rpp[0], zi3),
      fe_mul(R2[1], zi2) == fe_mul(Rpp[1], zi3))

# Test: [3]*P == P+P+P
R3 = scalar_mult(3, P)
Rppp = point_add(point_add(P, P), P)
zi4 = fe_inv(R3[2]); zi5 = fe_inv(Rppp[2])
print("[3]*P == P+P+P?", fe_mul(R3[0], zi4) == fe_mul(Rppp[0], zi5),
      fe_mul(R3[1], zi4) == fe_mul(Rppp[1], zi5))

# Now test with an actual curve point (y=4)
y = 4; y2 = fe_sq(y)
u = fe_sub(y2, 1); v = fe_sub(fe_mul(d, y2), 1)
x2 = fe_mul(u, fe_inv(v)); x = pow(x2, (p+1)//4, p)
if fe_sq(x) == x2:
    P_curve = (x, y, 1)
    # [1]*P = P
    R = scalar_mult(1, P_curve)
    zi = fe_inv(R[2])
    print("[1]*P_curve == P_curve?", fe_mul(R[0], zi) == x, fe_mul(R[1], zi) == y)
    # [2]*P = P+P
    R2 = scalar_mult(2, P_curve)
    Rpp = point_add(P_curve, P_curve)
    zi2 = fe_inv(R2[2]); zi3 = fe_inv(Rpp[2])
    print("[2]*P_curve == P_curve+P_curve?", 
          fe_mul(R2[0], zi2) == fe_mul(Rpp[0], zi3),
          fe_mul(R2[1], zi2) == fe_mul(Rpp[1], zi3))
