#!/usr/bin/env python3
"""
Find the correct ge_p2_dbl formula by testing all permutations.
We know the correct affine result, so we just need to find which
projective formula + p1p1_to_p3 mapping gives the right answer.
"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

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

# Correct affine 2B
t_affine = d * pow(Bx, 2, p) * pow(By, 2, p) % p
x2B = (2 * Bx * By) % p * pow(1 + t_affine, -1, p) % p
y2B = (pow(By, 2, p) + pow(Bx, 2, p)) % p * pow(1 - t_affine, -1, p) % p
print(f"Correct affine 2B: x={x2B}, y={y2B}")
print(f"On curve: {(-pow(x2B,2,p)+pow(y2B,2,p))%p == (1+d*pow(x2B,2,p)*pow(y2B,2,p))%p}")

# The P1P1 to P3 conversion in the code is:
# X3 = X*T, Y3 = Y*Z, Z3 = Z*T, T3 = X*Y
# So: x = X3/Z3 = (X*T)/(Z*T) = X/Z
#     y = Y3/Z3 = (Y*Z)/(Z*T) = Y/T
#     t = T3/Z3 = (X*Y)/(Z*T)
# For P2 doubling, the P1P1 result (X:Y:Z:T) maps to:
#   x = X/Z, y = Y/T
# (Note: NOT x = X/Z, y = Y/Z!)

# So the doubling formula should produce a P1P1 point (X:Y:Z:T) where:
#   x3 = X/Z = 2xy/(1+dx²y²)
#   y3 = Y/T = (y²+x²)/(1-dx²y²)  [a=-1]

# With P2 input (X:Y:Z), x=X/Z, y=Y/Z:
# x3 = 2XY / (Z² + dX²Y²/Z²) = 2XYZ² / (Z⁴ + dX²Y²)
# y3 = (Y²+X²) / (Z² - dX²Y²/Z²) = (Y²+X²)Z² / (Z⁴ - dX²Y²)
#    = (Y²+X²)Z² / ((Z²+dX²Y²/Z²)(Z²-dX²Y²/Z²))... no
#    Let's just say:
#    x3 = 2XY / (Z² + dX²Y²/Z²)
#    But in P1P1: X/Z and Y/T are the result coordinates.
#    So: X_p1p1 / Z_p1p1 = 2XY / (Z² + dX²Y²)
#        Y_p1p1 / T_p1p1 = (X²+Y²) / (Z² - dX²Y²)
#
# Hmm this is getting complex. Let me just try the ACTUAL ref10 formula.
# 
# The ACTUAL Bernstein ref10 ge_p2_dbl.c (verified from multiple sources):
# For the twisted Edwards curve with a=-1 (Ed25519):
#
#   fe a,b,c,e,f,g,h;
#   fe_sq(a, p->X);       // a = X²
#   fe_sq(b, p->Y);       // b = Y²
#   fe_sq(c, p->Z);       // c = Z²
#   fe_add(c, c, c);      // c = 2Z²
#   fe_add(h, a, b);      // h = A+B = X²+Y²
#   fe_sub(e, h, c);      // e = (X²+Y²) - 2Z²
#   fe_add(f, a, a);      // f = 2A = 2X²
#   fe_sub(f, f, h);      // f = 2X² - (X²+Y²) = X² - Y²
#   fe_sub(g, b, a);      // g = Y² - X²
#   fe_add(g, g, c);      // g = (Y²-X²) + 2Z²
#   fe_neg(g, g);         // g = -((Y²-X²)+2Z²) = X²-Y²-2Z²
#   // Wait, that gives g = -(Y²-X²+2Z²) = X²-Y²-2Z²
#   // And f = X²-Y²
#   // So f = X²-Y², g = (X²-Y²) - 2Z²
#   // Hmm, that means g = f - 2Z²
#
# Actually let me just look at the ACTUAL ref10 source from libsodium:
# https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.c
#
# void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p) {
#     fe a, b, c, e, f, g, h;
#     fe_sq(a, p->X);
#     fe_sq(b, p->Y);
#     fe_sq(c, p->Z);
#     fe_add(c, c, c);
#     fe_add(h, a, b);
#   // fe_sub(e, h, c);
#     fe_sub(f, a, b);     // f = a - b
#   // fe_add(g, f, c);    // Wait, no...
#     ...
# }
#
# I don't have the exact source, but I can derive it.
# The key insight: in the P1P1 result, x = X/Z, y = Y/T.
# The doubling formula should produce:
#   X/Z = 2XY / (Z² + dX²Y²)  [wrong, this should be / (Z²*(1+d*x²y²)) ]
# Wait, let me think more carefully.
#
# P2 input: (X:Y:Z) with x=X/Z, y=Y/Z
# P1P1 output: (X':Y':Z':T') with x3 = X'/Z', y3 = Y'/T'
#
# The doubling formulas:
# x3 = 2xy / (1 + dx²y²) = 2(X/Z)(Y/Z) / (1 + d(X/Z)²(Y/Z)²)
#    = 2XY / (Z² + dX²Y²/Z²) = 2XYZ² / (Z⁴ + dX²Y²)
# y3 = (y²+x²) / (1 - dx²y²) = ((Y/Z)²+(X/Z)²) / (1 - d(X/Z)²(Y/Z)²)
#    = (Y²+X²) / (Z² - dX²Y²/Z²) = (Y²+X²)Z² / (Z⁴ - dX²Y²)
#
# So: X'/Z' = 2XYZ² / (Z⁴ + dX²Y²)
#     Y'/T' = (X²+Y²)Z² / (Z⁴ - dX²Y²)
#
# We can choose: Z' = (Z⁴ + dX²Y²)(Z⁴ - dX²Y²) = Z⁸ - d²X⁴Y⁴
# But that's expensive. Instead, we use the trick of splitting:
# Z' = Z² - dX²Y²/Z²  ... no, we need integer arithmetic.
#
# The ref10 approach: use the a=-1 doubling formula from
# "Twisted Edwards Curves" (Bernstein, Birkner, Joye, Lange, Peters 2008)
# Formula DBL (a=-1) from Table 1:
# A = X²
# B = Y²
# C = 2Z²
# D = a·A = -A
# E = (X+Y)² - A - B = 2XY
# F = D - C = -A - 2Z² = -(A+2Z²)
# G = D - B = -A - B = -(A+B)
# H = D + B = -A + B = B - A
# X3 = E·F = 2XY · (-(A+2Z²))
# Y3 = G·H = (-(A+B)) · (B-A)
# T3 = E·H = 2XY · (B-A)
# Z3 = F·G = (-(A+2Z²)) · (-(A+B)) = (A+2Z²)(A+B)
#
# Then P1P1 → P3: x3 = X3/Z3, y3 = Y3/T3 (NOT Y3/Z3!)
# Wait, the p1p1_to_p3 conversion is:
#   X3_ext = X·T, Y3_ext = Y·Z, Z3_ext = Z·T, T3_ext = X·Y
# And in extended coords: x = X3_ext/Z3_ext, y = Y3_ext/Z3_ext
# So x = (X·T)/(Z·T) = X/Z
#    y = (Y·Z)/(Z·T) = Y/T
# 
# So the P1P1 coords map as: x = X/Z, y = Y/T
# Therefore we need: X/Z = x3, Y/T = y3
# 
# Let me verify: with the ref10 DBL formula,
# x3 = X3/Z3 = E·F / (F·G) = E/G = 2XY / (-(A+B)) = -2XY/(A+B)
# y3 = Y3/T3 = G·H / (E·H) = G/E = -(A+B) / (2XY) = -(X²+Y²)/(2XY)
#
# But affine says x3 = 2xy/(1+dx²y²) and y3 = (x²+y²)/(1-dx²y²)
# So we need: -2XY/(A+B) = 2XY/(1+dA*B)   [A=X², B=Y², Z=1]
#    i.e., -(A+B) = (1+dAB)
#    i.e., -(X²+Y²) = 1 + dX²Y²
#
# This is NOT generally true! So the ref10 DBL formula does NOT directly
# give the affine result through x=X/Z, y=Y/T.
#
# Hmm, wait. Let me re-read the P1P1 to P3 conversion more carefully.
# In the code:
# ge_p1p1_to_p3: X = p->X * p->T, Y = p->Y * p->Z, Z = p->Z * p->T, T = p->X * p->Y
# So: x = X/Z = (X_p1p1 * T_p1p1) / (Z_p1p1 * T_p1p1) = X_p1p1 / Z_p1p1
#     y = Y/Z = (Y_p1p1 * Z_p1p1) / (Z_p1p1 * T_p1p1) = Y_p1p1 / T_p1p1
#
# So x = X_p1p1 / Z_p1p1, y = Y_p1p1 / T_p1p1. This is what I said.
# 
# With the ref10 DBL:
# X_p1p1 = E·F = 2XY·F
# Z_p1p1 = F·G
# Y_p1p1 = G·H
# T_p1p1 = E·H
#
# x = X_p1p1/Z_p1p1 = E·F/(F·G) = E/G = 2XY/(-(A+B)) = -2XY/(X²+Y²)
# y = Y_p1p1/T_p1p1 = G·H/(E·H) = G/E = -(A+B)/(2XY) = -(X²+Y²)/(2XY)
#
# But we want:
# x3 = 2XY/(Z²+dX²Y²) = 2XY/(1+dAB)   [Z=1]
# y3 = (X²+Y²)/(Z²-dX²Y²) = (X²+Y²)/(1-dAB)
#
# So: -2XY/(X²+Y²) should equal 2XY/(1+dAB)
# => -(X²+Y²) = 1+dAB
# => -X²-Y²-1 = dX²Y²
#
# This is NOT the curve equation! The curve equation is -X²+Y² = 1+dX²Y²
# => -X²+Y²-1 = dX²Y²
# 
# So -X²-Y²-1 ≠ -X²+Y²-1 (they differ by 2Y²).
# This means the ref10 formula with P1P1 mapping gives a WRONG result!
#
# Unless... the ref10 formula is actually DIFFERENT from what I wrote above.
# Let me check if maybe the mapping is x=X*T/Z, y=Y*Z/T or something else.

# Actually, wait. I think I need to check the ACTUAL p1p1_to_p2 and p1p1_to_p3
# conversions more carefully. In the code:
#
# ge_p1p1_to_p2: X = X*T, Y = Y*Z, Z = Z*T
# ge_p1p1_to_p3: X = X*T, Y = Y*Z, Z = Z*T, T = X*Y
#
# So for P2: x = X/Z = (X_p1p1 * T_p1p1) / (Z_p1p1 * T_p1p1) = X/Z (p1p1)
#            y = Y/Z = (Y_p1p1 * Z_p1p1) / (Z_p1p1 * T_p1p1) = Y/T (p1p1)
#
# And for P3: same x and y as P2, plus T = X_p1p1 * Y_p1p1 / (Z_p1p1 * T_p1p1)
#
# So the mapping IS x = X_p1p1/Z_p1p1, y = Y_p1p1/T_p1p1.
# 
# Given that, the ref10 DBL formula with F = -(A+2Z²), G = -(A+B) gives:
# x = E/G = 2XY/(-(X²+Y²)) 
# y = G/E = -(X²+Y²)/(2XY)
# 
# For Z=1: x = 2xy/(-(x²+y²)), y = -(x²+y²)/(2xy)
# This is NOT the same as x3 = 2xy/(1+dx²y²), y3 = (x²+y²)/(1-dx²y²)
#
# Unless the curve equation makes these equal...
# -x²+y² = 1+dx²y² => d = (y²-x²-1)/(x²y²)
# 1+dx²y² = y²-x²
# 1-dx²y² = 2-y²+x² ... no, 1-dx²y² = 1-(y²-x²-1) = 2-y²+x²
#
# So x3 = 2xy/(y²-x²)
# And the ref10 gives: x = 2xy/(-(x²+y²)) = -2xy/(x²+y²)
# These are NOT equal.
#
# So I must be wrong about the ref10 formula. Let me try to find the actual one
# by brute force.

# The correct mapping: x = X_p1p1/Z_p1p1, y = Y_p1p1/T_p1p1
# We need: x = x3 = 2xy/(1+dx²y²), y = y3 = (x²+y²)/(1-dx²y²)
# For Z=1: x3 = 2XY/(1+dAB), y3 = (A+B)/(1-dAB) where A=X², B=Y²
#
# So: X_p1p1/Z_p1p1 = 2XY/(1+dAB)
#     Y_p1p1/T_p1p1 = (A+B)/(1-dAB)
#
# We need to find X,Y,Z,T such that:
#   X = E, Z = G where E/G = 2XY/(1+dAB)
#   Y = G2, T = E2 where G2/E2 = (A+B)/(1-dAB)
#
# A natural choice: E = 2XY, G = 1+dAB, G2 = A+B, E2 = 1-dAB
# But 1+dAB requires computing d*X²*Y² which is extra multiplications.
#
# The ref10 trick is to use the curve equation to avoid computing dAB:
# -x²+y² = 1+dx²y² => 1+dAB = -A+B (when Z=1)
#                  => 1-dAB = 1-(B-A-1) = 2-B+A = A+2-B... no
# Actually: 1+dx²y² = y²-x² = B-A (using curve eq with Z=1)
# So: E/G = 2XY/(B-A) => E = 2XY, G = B-A
#     G2/E2 = (A+B)/(1-dAB)
#     1-dAB = 1-(B-A-1) = 2-B+A ... hmm
#     1-dAB = 2-(B-A) = 2-B+A ... no, 1+dAB = B-A, so dAB = B-A-1
#     1-dAB = 1-(B-A-1) = 2-B+A = A-B+2 = A-B+2Z² (for Z=1)
# So: E2 = A-B+2Z², G2 = A+B
# 
# And: X_p1p1 = E = 2XY = (X+Y)²-X²-Y²
#      Z_p1p1 = G = B-A = Y²-X²
#      Y_p1p1 = G2 = A+B = X²+Y²
#      T_p1p1 = E2 = A-B+2Z² = X²-Y²+2Z²
#
# Let me verify:
X, Y, Z = Bx, By, 1
A = pow(X, 2, p)
B = pow(Y, 2, p)
E_ref = (pow((X+Y)%p, 2, p) - A - B) % p  # 2XY
G_ref = (B - A) % p  # Y²-X²  (Z_p1p1)
G2_ref = (A + B) % p  # X²+Y²  (Y_p1p1)
E2_ref = (A - B + 2*pow(Z, 2, p)) % p  # X²-Y²+2Z²  (T_p1p1)

x_ref = E_ref * pow(G_ref, -1, p) % p
y_ref = G2_ref * pow(E2_ref, -1, p) % p
print(f"\nRef-derived formula:")
print(f"x = {x_ref}")
print(f"y = {y_ref}")
print(f"on curve: {(-pow(x_ref,2,p)+pow(y_ref,2,p))%p == (1+d*pow(x_ref,2,p)*pow(y_ref,2,p))%p}")
print(f"matches affine: {x_ref == x2B and y_ref == y2B}")

# So the correct formula is:
# e = (X+Y)² - X² - Y² = 2XY
# g = Y² - X²    (Z_p1p1)
# h = X² + Y²    (Y_p1p1)
# f = X² - Y² + 2Z²    (T_p1p1)
# X_p1p1 = e, Y_p1p1 = h, Z_p1p1 = g, T_p1p1 = f
# i.e. r->X = e, r->Y = h, r->Z = g, r->T = f
#
# Wait, but that's not in the standard E*F, G*H, E*H, F*G form.
# The P1P1 form stores (X:Y:Z:T) and the result is x=X/Z, y=Y/T.
# So we can directly assign:
# r->X = e  (2XY)
# r->Y = h  (X²+Y²)
# r->Z = g  (Y²-X²)  -- note: Z denominator for x
# r->T = f  (X²-Y²+2Z²) -- note: T denominator for y

# But the ref10 code uses fe_mul to produce the P1P1 result, not direct assignment.
# The reason is that the P1P1 form is used for BOTH addition and doubling, and
# the multiplication form (E*F, G*H, E*H, F*G) is the unified interface.
#
# So the ref10 formula must be:
# X_p1p1 = e * f    where e*f = 2XY * (X²-Y²+2Z²)
# Z_p1p1 = g * h... wait, that doesn't match.
#
# Actually, let me think about it differently.
# The P1P1 form is (X:Y:Z:T) with x = X*Z, y = Y*T... no.
# 
# Actually, looking at ge_p1p1_to_p2:
#   X = p->X * p->T
#   Y = p->Y * p->Z
#   Z = p->Z * p->T
# So P2.X = X_p1p1 * T_p1p1, P2.Y = Y_p1p1 * Z_p1p1, P2.Z = Z_p1p1 * T_p1p1
# And x = P2.X/P2.Z = (X_p1p1*T_p1p1)/(Z_p1p1*T_p1p1) = X_p1p1/Z_p1p1
#     y = P2.Y/P2.Z = (Y_p1p1*Z_p1p1)/(Z_p1p1*T_p1p1) = Y_p1p1/T_p1p1
#
# So we need:
# X_p1p1 / Z_p1p1 = 2XY / (Y²-X²)    [using 1+dAB = B-A from curve eq]
# Y_p1p1 / T_p1p1 = (X²+Y²) / (X²-Y²+2Z²)  [using 1-dAB = A-B+2Z²]
#
# In the E*F, G*H, E*H, F*G form:
# X_p1p1 = E*F, Z_p1p1 = F*G  =>  x = E*F/(F*G) = E/G
# Y_p1p1 = G*H, T_p1p1 = E*H  =>  y = G*H/(E*H) = G/E
#
# So: E/G = 2XY/(Y²-X²)
#     G/E = (X²+Y²)/(X²-Y²+2Z²)
#
# From E/G: E = 2XY, G = Y²-X²
# From G/E: G = X²+Y², E = X²-Y²+2Z²
#
# These are INCONSISTENT! E can't be both 2XY and X²-Y²+2Z².
# G can't be both Y²-X² and X²+Y².
#
# So the standard E*F, G*H, E*H, F*G form does NOT work for this approach.
# The ref10 must use a DIFFERENT combination.
#
# Let me try all 24 permutations of assigning e,f,g,h to X,Y,Z,T:
print("\n=== Brute force search for correct formula ===")
vals = {
    'A': A, 'B': B, 'C': C,
    '2XY': E_ref,  # (X+Y)^2 - X^2 - Y^2
    'B-A': (B - A) % p,     # Y^2 - X^2
    'A+B': (A + B) % p,     # X^2 + Y^2
    'A-B': (A - B) % p,     # X^2 - Y^2
    '-A-C': (-A - C) % p,   # -X^2 - 2Z^2
    '-A-B': (-A - B) % p,   # -(X^2+Y^2)
    'B-A-C': (B - A - C) % p,  # Y^2-X^2-2Z^2
    'A-B+C': (A - B + C) % p,  # X^2-Y^2+2Z^2
    '-A-B-C': (-A - B - C) % p, # -(X^2+Y^2+2Z^2)
}

found = False
keys = list(vals.keys())
for kx in keys:
    for ky in keys:
        for kz in keys:
            for kt in keys:
                xv = vals[kx] * pow(vals[kz], -1, p) % p
                yv = vals[ky] * pow(vals[kt], -1, p) % p
                if xv == x2B and yv == y2B:
                    print(f"FOUND! X={kx}, Y={ky}, Z={kz}, T={kt}")
                    found = True
if not found:
    print("No match found with simple fractions.")
    # Try products of two terms
    print("Trying products of two terms...")
    for k1 in keys:
        for k2 in keys:
            for k3 in keys:
                for k4 in keys:
                    X_p = vals[k1] * vals[k2] % p
                    Y_p = vals[k3] * vals[k4] % p
                    for k5 in keys:
                        for k6 in keys:
                            Z_p = vals[k5] * vals[k6] % p
                            for k7 in keys:
                                for k8 in keys:
                                    T_p = vals[k7] * vals[k8] % p
                                    if Z_p != 0 and T_p != 0:
                                        xv = X_p * pow(Z_p, -1, p) % p
                                        yv = Y_p * pow(T_p, -1, p) % p
                                        if xv == x2B and yv == y2B:
                                            print(f"FOUND! X={k1}*{k2}, Y={k3}*{k4}, Z={k5}*{k6}, T={k7}*{k8}")
                                            found = True
                                            break
                                if found: break
                            if found: break
                        if found: break
                    if found: break
                if found: break
            if found: break
        if found: break
