#!/usr/bin/env python3
"""Verify correct doubling formula for twisted Edwards a=-1."""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

# Basepoint
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

print(f"B on curve: {(-pow(Bx,2,p) + pow(By,2,p)) % p == (1 + d*pow(Bx,2,p)*pow(By,2,p)) % p}")

# Affine doubling for twisted Edwards a=-1: -x^2 + y^2 = 1 + d*x^2*y^2
# The correct doubling formula (Hisil-Wong-Carter-Dawson 2008):
# x3 = 2*x*y / (1 + d*x^2*y^2)
# y3 = (y^2 - a*x^2) / (1 - d*x^2*y^2)  where a=-1
#    = (y^2 + x^2) / (1 - d*x^2*y^2)
def dbl_affine_correct(x, y, p, d):
    x2 = pow(x, 2, p)
    y2 = pow(y, 2, p)
    xy = x * y % p
    t = d * x2 * y2 % p
    x3 = (2 * xy) % p * pow(1 + t, -1, p) % p
    y3 = (y2 + x2) % p * pow(1 - t, -1, p) % p  # y^2 + x^2 (a=-1)
    return x3, y3

x2B, y2B = dbl_affine_correct(Bx, By, p, d)
print(f"\nAffine doubling (correct formula):")
print(f"2B x = {x2B}")
print(f"2B y = {y2B}")

lhs = (-pow(x2B, 2, p) + pow(y2B, 2, p)) % p
rhs = (1 + d * pow(x2B, 2, p) * pow(y2B, 2, p)) % p
print(f"2B on curve: {lhs == rhs}")

# Now the projective doubling formula for a=-1 (RFC 8032)
# A = X^2, B = Y^2, C = 2*Z^2
# D = -A (a=-1)
# E = (X+Y)^2 - A - B
# F = D - C
# G = D - B
# H = D + B
# X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
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

print(f"\nProjective doubling (RFC formula):")
print(f"2B x = {x3}")
print(f"2B y = {y3}")
print(f"2B T = {t3}")

lhs_p = (-pow(x3, 2, p) + pow(y3, 2, p)) % p
rhs_p = (1 + d * pow(x3, 2, p) * pow(y3, 2, p)) % p
print(f"2B on curve: {lhs_p == rhs_p}")
print(f"T == x*y: {t3 == (x3 * y3) % p}")
print(f"Matches affine: {x3 == x2B and y3 == y2B}")

# Hmm, the RFC formula gives different results from affine.
# Let me check the ref10 formula more carefully.
# 
# The ACTUAL ref10 ge_p2_dbl.c (from SUPERCOP/libsodium):
# For a=-1, the code uses the UNIFIED doubling formula.
# Let me try the formula from RFC 8032 Section 5.1.4 (which is for a=-1):
#
# Actually, RFC 8032 says the doubling formula is the SAME as addition 
# with P=Q. Let me look at this differently.
#
# The Edwards addition formula for -x^2 + y^2 = 1 + d*x^2*y^2:
# x3 = (x1*y2 + x2*y1) / (1 + d*x1*y1*x2*y2)   [for a=-1, NOT d*x1*x2*y1*y2]
# Wait, let me be more careful. The GENERAL Edwards addition is:
# For a*x^2 + y^2 = 1 + d*x^2*y^2:
# x3 = (x1*y2 + x2*y1) / (1 + d*x1*y1*x2*y2)
# y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*y1*x2*y2)
# With a=-1: y3 = (y1*y2 + x1*x2) / (1 - d*x1*y1*x2*y2)
#
# For doubling (x1=x2, y1=y2):
# x3 = (2*x*y) / (1 + d*x^2*y^2)
# y3 = (y^2 + x^2) / (1 - d*x^2*y^2)
#
# This is what I computed above as dbl_affine_correct, and it's on the curve!
# But the projective formula gives a different result...

# Let me try the ref10 projective doubling formula.
# From Bernstein's "ref10" implementation:
# ge_p2_dbl computes:
#   a = X^2
#   b = Y^2
#   c = 2*Z^2
#   h = a + b          (h = A + B)
#   e = h - c          (e = (A+B) - 2*Z^2)   -- NOT (X+Y)^2-A-B!
#   f = 2*a - h        (f = 2*A - (A+B) = A - B)
#   g = a - b          (g = A - B, = -(B-A))
# Wait, that's for a=-1 too? Let me check.
# 
# Actually the ref10 has TWO versions: one for a=-1 (Ed25519) and one for a=1.
# The a=-1 version (ge_p2_dbl.c for Ed25519):

# Let me try this formula:
# a = X^2
# b = Y^2
# c = 2*Z^2
# h = a + b
# e = h - c
# f = 2*a - h = a - b
# g = -(a - b) = b - a   ... wait
# 
# Actually, I think the correct ref10 formula for a=-1 is:
# The "unified" formula where D = a*A = -A
# But ref10 avoids computing D explicitly by rearranging:
# F = D - C = -A - 2*Z^2 = -(A + 2*Z^2) = -(h + c - 2*b + 2*b)... this is getting messy.
# 
# Let me try yet another approach: use the formula that the affine check says is correct.
# Affine: x3 = 2xy/(1+dx²y²), y3 = (y²+x²)/(1-dx²y²)
# Projective: x = X/Z, y = Y/Z
# x3 = 2*(X/Z)*(Y/Z) / (1 + d*(X/Z)^2*(Y/Z)^2)
#    = 2*X*Y*Z^2 / (Z^4 + d*X^2*Y^2)  ... multiply num and denom by Z^4
# y3 = ((Y/Z)^2 + (X/Z)^2) / (1 - d*(X/Z)^2*(Y/Z)^2)
#    = (Y^2 + X^2)*Z^2 / (Z^4 - d*X^2*Y^2)
#
# In projective: X3/Z3 = x3, Y3/Z3 = y3
# X3 = 2*X*Y, Y3 = Y^2+X^2 (wait, but that's for a=1...)
# Z3 = Z^4 - d*X^2*Y^2... no, we need to be more careful.
# 
# Actually, for the P1P1 form (X3 = E*F, Y3 = G*H, Z3 = F*G, T3 = E*H):
# The result is (X3*Z3 : Y3*Z3 : Z3 : T3*Z3) in extended coords
# i.e., x = X3/Z3, y = Y3/Z3, t = T3/Z3
#
# So: x3 = E*F / (F*G) = E/G
#     y3 = G*H / (F*G) = H/F
#     t3 = E*H / (F*G)
#
# For the correct affine result:
# x3 = 2xy / (1 + dx²y²)
# y3 = (y² + x²) / (1 - dx²y²)    [a=-1]
#
# So we need:
# E/G = 2xy / (1 + dx²y²)
# H/F = (y² + x²) / (1 - dx²y²)
#
# Let me try:
# E = (X+Y)^2 - X^2 - Y^2 = 2XY  (in field, without mod)
# G = (Z^2 + d*X^2*Y^2) ... this would be 1 + d*x^2*y^2 when Z=1
# F = (Z^2 - d*X^2*Y^2) ... this would be 1 - d*x^2*y^2 when Z=1  
# H = X^2 + Y^2 ... this would be x^2 + y^2 when Z=1
#
# Let's check: E/G = 2XY / (Z^2 + d*X^2*Y^2) = 2xy / (1 + d*x^2*y^2) when Z=1 ✓
# H/F = (X^2+Y^2) / (Z^2 - d*X^2*Y^2) = (x^2+y^2) / (1 - d*x^2*y^2) when Z=1 ✓
#
# But this uses Z^2 and d*X^2*Y^2 which requires extra multiplications.
# The ref10 formula avoids this by using a=-1 trick.
#
# For a=-1:
# x3 = 2xy / (1 + dx²y²)
# y3 = (y² + x²) / (1 - dx²y²)
#
# The ref10 formula with A=X^2, B=Y^2, C=2Z^2:
# D = -A
# E = (X+Y)^2 - A - B = 2XY
# F = D - C = -A - 2Z^2
# G = D - B = -A - B  = -(A+B)
# H = D + B = -A + B = B - A
# X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
#
# x3 = E*F / (F*G) = E/G = 2XY / (-(A+B)) = -2XY / (A+B)
# But affine says x3 = 2xy / (1 + dx²y²) = 2XY / (Z^2 + dX^2Y^2)  (Z=1)
#   = 2XY / (1 + d*A*B)  (with A=X^2, B=Y^2)
#
# So we need: -(A+B) = -(X^2+Y^2) to equal (1 + d*X^2*Y^2)???
# That's clearly not true.
#
# So either the RFC formula is wrong, or my affine formula is wrong, or
# the projective formula maps differently than I think.
#
# Let me just compute everything numerically and see what works.

# Test ALL possible projective formulas
print("\n=== Testing different projective doubling formulas ===")

# Formula 1: RFC 8032 (D=-A)
# Already computed above, gives wrong result

# Formula 2: What if D = A (a=+1, untwisted)?
D2 = A  # D = a*A = A (a=+1)
E2 = (pow((X + Y) % p, 2, p) - A - B) % p  # same E
F2 = (D2 - C) % p  # A - 2*Z^2
G2 = (D2 - B) % p  # A - B
H2 = (D2 + B) % p  # A + B

X3_2 = E2 * F2 % p
Y3_2 = G2 * H2 % p
T3_2 = E2 * H2 % p
Z3_2 = F2 * G2 % p

x3_2 = X3_2 * pow(Z3_2, -1, p) % p
y3_2 = Y3_2 * pow(Z3_2, -1, p) % p
print(f"Formula a=+1: x={x3_2}, y={y3_2}")
print(f"  on curve (twisted): {(-pow(x3_2,2,p)+pow(y3_2,2,p))%p == (1+d*pow(x3_2,2,p)*pow(y3_2,2,p))%p}")
print(f"  matches affine: {x3_2 == x2B and y3_2 == y2B}")

# Formula 3: ref10 actual code (swap g and h, fix f)
# a=X^2, b=Y^2, c=2*Z^2
# e = (X+Y)^2 - a - b  (= 2XY)
# g = b - a            (= H in RFC = B-A)
# f = -a - c           (= F in RFC = -A-2Z^2)  FIXED
# h = -(a+b)           (= G in RFC = -(A+B))
# X3 = e*f, Y3 = g*h, T3 = e*g, Z3 = f*h  SWAPPED
g3 = (B - A) % p  # = H
f3 = (-A - C) % p  # = F (FIXED)
h3 = (-(A + B)) % p  # = G
X3_3 = E * f3 % p
Y3_3 = g3 * h3 % p
T3_3 = E * g3 % p  # FIXED: e*g instead of e*h
Z3_3 = f3 * h3 % p  # FIXED: f*h instead of f*g

x3_3 = X3_3 * pow(Z3_3, -1, p) % p
y3_3 = Y3_3 * pow(Z3_3, -1, p) % p
t3_3 = T3_3 * pow(Z3_3, -1, p) % p
print(f"\nFormula 3 (fixed): x={x3_3}, y={y3_3}")
print(f"  on curve: {(-pow(x3_3,2,p)+pow(y3_3,2,p))%p == (1+d*pow(x3_3,2,p)*pow(y3_3,2,p))%p}")
print(f"  matches affine: {x3_3 == x2B and y3_3 == y2B}")
print(f"  T == x*y: {t3_3 == (x3_3 * y3_3) % p}")

# Formula 4: What if the ref10 code is actually correct for a DIFFERENT variable naming?
# Let me try: X3=e*f, Y3=g*h, T3=e*g, Z3=f*h (swap T and Z from original)
# with the ORIGINAL (buggy) f = (b-a)-c
g4 = (B - A) % p
f4 = (g4 - C) % p  # original buggy f
h4 = (-(A + B)) % p
X3_4 = E * f4 % p
Y3_4 = g4 * h4 % p
T3_4 = E * g4 % p  # swap: e*g
Z3_4 = f4 * h4 % p  # swap: f*h

x3_4 = X3_4 * pow(Z3_4, -1, p) % p
y3_4 = Y3_4 * pow(Z3_4, -1, p) % p
print(f"\nFormula 4 (swap T/Z, buggy f): x={x3_4}, y={y3_4}")
print(f"  on curve: {(-pow(x3_4,2,p)+pow(y3_4,2,p))%p == (1+d*pow(x3_4,2,p)*pow(y3_4,2,p))%p}")
print(f"  matches affine: {x3_4 == x2B and y3_4 == y2B}")
