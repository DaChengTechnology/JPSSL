#!/usr/bin/env python3
"""Brute force T3: try all possible products of P1P1 components."""
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

# Test 2B to find correct T3
p1p1 = ge_add(B, B)
X_p, Y_p, Z_p, T_p = p1p1
Z3 = Z_p * T_p % p
x_2b = X_p * T_p % p * pow(Z3, -1, p) % p
y_2b = Y_p * T_p % p * pow(Z3, -1, p) % p
target_t = x_2b * y_2b % p

# Try ALL possible T3 values: products of 2, 3, or 4 P1P1 components
# But also try: T3 = (something) * (something else) where the something
# can be a single P1P1 component or a sum/difference of components.
# 
# Actually, T3 should be such that T3/Z3 = x*y = (XT/ZT)*(YT/ZT) = XY/Z²
# So T3 = XY * Z3 / Z² = XY * ZT / Z² = XY * T / Z
# That's T3 = XY*T/Z which requires division... not a simple product.
#
# But in the original (buggy) code: Z3 = Z*T, T3 = X*Y
# T3/Z3 = XY/(ZT) which is NOT equal to x*y = XY/Z²
# because ZT ≠ Z² in general.
#
# The issue is that with the correct conversion X3=XT, Y3=YT, Z3=ZT,
# we get x = X/Z and y = Y/Z (since X3/Z3 = XT/(ZT) = X/Z, Y3/Z3 = YT/(ZT) = Y/Z).
# Wait! Y3 = YT, Z3 = ZT, so y = Y3/Z3 = YT/(ZT) = Y/Z.
# And x = X3/Z3 = XT/(ZT) = X/Z.
# So x = X/Z and y = Y/Z, which means x*y = XY/Z².
# T3 should be XY/Z² * Z3 = XY/Z² * ZT = XY*T/Z.
# But T3 = X*Y gives T3/Z3 = XY/(ZT), which is NOT x*y = XY/Z².
#
# For T3/Z3 = x*y = XY/Z², we need T3 = XY * Z3 / Z² = XY * ZT / Z² = XY * T / Z.
# This is not a simple product of P1P1 fields.
#
# HOWEVER: in the original ref10, the p1p1_to_p3 conversion is:
# X3 = X*T, Y3 = Y*Z, Z3 = Z*T, T3 = X*Y
# This gives: x = XT/(ZT) = X/Z, y = YZ/(ZT) = Y/T
# So x = X/Z and y = Y/T (DIFFERENT denominators!)
# Then T3/Z3 = XY/(ZT) and x*y = (X/Z)*(Y/T) = XY/(ZT) = T3/Z3. ✓
#
# So in the original ref10, T3=XY IS correct, but only when Y3=Y*Z (not Y*T)!
# The bug is that with Y3=Y*T, the mapping changes and T3=XY no longer works.
#
# This means the CORRECT ref10 formula is:
# X3 = X*T, Y3 = Y*Z, Z3 = Z*T, T3 = X*Y
# which gives x = X/Z, y = Y/T, t = XY/(ZT)
# And x*y = (X/Z)*(Y/T) = XY/(ZT) = t ✓
#
# But our Python test showed that ge_add(B,B) with Y3=YZ gives WRONG y!
# Let me re-verify...
print("=== Re-checking Y3=YZ (original code) ===")
# ge_add(B,B) with Y3=YZ:
x_orig = X_p * T_p % p * pow(Z3, -1, p) % p  # X3=XT, Z3=ZT => x = X/Z
y_orig = Y_p * Z_p % p * pow(Z3, -1, p) % p  # Y3=YZ, Z3=ZT => y = Y/T
t_orig = X_p * Y_p % p * pow(Z3, -1, p) % p   # T3=XY, Z3=ZT => t = XY/(ZT)
print(f"x = {x_orig}, match 2B: {x_orig == x_2b}")
print(f"y = {y_orig}, match 2B: {y_orig == y_2b}")
print(f"t = {t_orig}")
print(f"x*y = {x_orig * y_orig % p}")
print(f"t == x*y: {t_orig == (x_orig * y_orig) % p}")

# So Y3=YZ gives y = Y/T (not Y/Z), and y is WRONG for 2B.
# But Y3=YT gives y = Y/Z (correct for 2B) but T3=XY gives t = XY/(ZT) ≠ x*y.
#
# The FUNDAMENTAL issue: the P1P1 form has the constraint that
# (X*Y)/(Z*T) = x*y for the original mapping (Y3=YZ).
# If we change to Y3=YT, then we need a different T3.
#
# What if the ref10 P1P1 form is NOT (e*f, g*h, f*g, e*h)?
# What if it's (e*f, g*h, e*h, f*g) -- i.e., Z and T are swapped?
# Then with X3=X*T=e*f*f*g, Y3=Y*Z=g*h*e*h, Z3=Z*T=f*g*e*h:
# x = X*T/(Z*T) = e*f/(f*g) = e/g  [wrong, same as before]
# y = Y*Z/(Z*T) = g*h/(e*h) = g/e  [wrong, y=1/x]
# That doesn't help.
#
# What if the P1P1 assignment for ge_p2_dbl is:
# r->X = e*f, r->Y = g*h, r->T = f*g, r->Z = e*h
# (swap Z and T)?
# Then with original p1p1_to_p3 (X3=XT, Y3=YZ, Z3=ZT):
# x = X*T/(Z*T) = e*f*f*g / (e*h*f*g) = e*f / (e*h) = f/h
# y = Y*Z/(Z*T) = g*h*e*h / (e*h*f*g) = g*h / (f*g) = h/f
# So y = h/f = 1/x again!
#
# The real question: what P1P1 assignment + p1p1_to_p3 mapping gives
# BOTH correct x, correct y, AND correct T=x*y?
# Let me search exhaustively.
print("\n=== Exhaustive search for P1P1 assignment + p1p1_to_p3 ===")

# All possible assignments of (e*f, g*h, e*h, f*g) to (X,Y,Z,T)
from itertools import permutations

vals = {'ef': e_add * f_add % p, 'gh': g_add * h_add % p, 
        'eh': e_add * h_add % p, 'fg': f_add * g_add % p}

# Hmm, e_add etc. are from ge_add. Let me recompute.
e_add = (b_add - a_add) % p  # already computed above? No, let me use ge_add result
# Actually I already have p1p1 = ge_add(B,B), which gives (e*f, g*h, f*g, e*h)
# The question is: what if the assignment is different?
# i.e., what if ge_p2_dbl/ge_add assigns the products differently to X,Y,Z,T?

# Let me try all 24 permutations of assigning the 4 products to X,Y,Z,T
# and all 4 p1p1_to_p3 mappings (XY, XZ, XT, YZ, YT, ZT for Y3, keeping X3=XT, Z3=ZT)
import itertools

products = [p1p1[0], p1p1[1], p1p1[2], p1p1[3]]  # ef, gh, fg, eh
prod_names = ['ef', 'gh', 'fg', 'eh']

# For ge_add(B,B), the 4 products are:
# ef = e_add * f_add
# gh = g_add * h_add
# fg = f_add * g_add  (this is Z in the code)
# eh = e_add * h_add  (this is T in the code)
# 
# The code assigns: X=ef, Y=gh, Z=fg, T=eh
# But maybe the correct assignment is different.
# Let's try all permutations.

# Recompute the 4 products directly
e_val = e_add
f_val = f_add
g_val = g_add
h_val = h_add

prods = {
    'ef': e_val * f_val % p,
    'gh': g_val * h_val % p,
    'eh': e_val * h_val % p,
    'fg': f_val * g_val % p,
}

# Target
t_aff = d * pow(Bx, 2, p) * pow(By, 2, p) % p
x2B = (2 * Bx * By) % p * pow(1 + t_aff, -1, p) % p
y2B = (pow(By, 2, p) + pow(Bx, 2, p)) % p * pow(1 - t_aff, -1, p) % p

found = False
for perm in itertools.permutations(['ef', 'gh', 'eh', 'fg']):
    X_v, Y_v, Z_v, T_v = prods[perm[0]], prods[perm[1]], prods[perm[2]], prods[perm[3]]
    # Try p1p1_to_p3: X3=XT, Z3=ZT, and try all Y3 and T3 options
    Z3_v = Z_v * T_v % p
    x_v = X_v * T_v % p * pow(Z3_v, -1, p) % p  # X3=XT
    if x_v != x2B:
        continue
    for yname in ['XY', 'XZ', 'XT', 'YZ', 'YT', 'ZT']:
        Y3_v = {
            'XY': X_v * Y_v % p, 'XZ': X_v * Z_v % p, 'XT': X_v * T_v % p,
            'YZ': Y_v * Z_v % p, 'YT': Y_v * T_v % p, 'ZT': Z_v * T_v % p,
        }[yname]
        y_v = Y3_v * pow(Z3_v, -1, p) % p
        if y_v != y2B:
            continue
        # Found correct x and y! Now find T3 such that T3/Z3 = x*y
        target_t3 = x_v * y_v % p
        for tname in ['XY', 'XZ', 'XT', 'YZ', 'YT', 'ZT']:
            T3_v = {
                'XY': X_v * Y_v % p, 'XZ': X_v * Z_v % p, 'XT': X_v * T_v % p,
                'YZ': Y_v * Z_v % p, 'YT': Y_v * T_v % p, 'ZT': Z_v * T_v % p,
            }[tname]
            if T3_v * pow(Z3_v, -1, p) % p == target_t3:
                print(f"FOUND! X={perm[0]}, Y={perm[1]}, Z={perm[2]}, T={perm[3]}, "
                      f"Y3={yname}, T3={tname}")
                found = True
if not found:
    print("No match found with 2-product T3.")
    # The T3 might need to be a ratio like X*Y*Z/T or similar
    # Let's compute what T3/Z3 should be
    # x*y = (X/Z)*(Y/Z) = XY/Z² (with the Y3=YT mapping)
    # T3/Z3 = x*y => T3 = XY*Z3/Z² = XY*ZT/Z² = XY*T/Z
    # So T3 = XY*T/Z, which is NOT a simple product.
    # 
    # This means we CAN'T have a correct T3 with simple products when Y3=YT.
    # The original ref10 uses Y3=YZ which gives y=Y/T and T3=XY with t=XY/(ZT)=x*y.
    # But Y3=YZ gives WRONG y!
    #
    # So the REAL bug must be in the ge_p2_dbl/ge_add formula itself,
    # not just in p1p1_to_p3.
    print("\nThe issue is that Y3=YT gives correct x,y but no valid T3.")
    print("The original Y3=YZ gives correct T3 but wrong y.")
    print("This means the ge_p2_dbl formula is ALSO wrong!")
