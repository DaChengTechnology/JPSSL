#!/usr/bin/env python3
"""Find the correct multiplication form for ge_p2_dbl."""
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
print(f"Correct 2B: x={x2B}, y={y2B}")

# The correct P1P1 assignment (from our derivation):
# X_p1p1 = 2XY = e
# Z_p1p1 = Y²-X² = g  
# Y_p1p1 = X²+Y² = h
# T_p1p1 = X²-Y²+2Z² = f
#
# In the E*F, G*H, E*H, F*G form:
# We need: X_p1p1 = e*f, Z_p1p1 = f*g, Y_p1p1 = g*h, T_p1p1 = e*h
# So: e*f = 2XY, f*g = Y²-X², g*h = X²+Y², e*h = X²-Y²+2Z²
#
# From e*f = 2XY and e*h = X²-Y²+2Z²:
#   h/f = (X²-Y²+2Z²) / (2XY)
# From f*g = Y²-X² and g*h = X²+Y²:
#   h/f = (X²+Y²) / (Y²-X²)
#
# Let's check if these are equal:
X, Y, Z = Bx, By, 1
A = pow(X, 2, p)
B = pow(Y, 2, p)
C = 2 * pow(Z, 2, p)

hf1 = (A - B + C) * pow(2 * X * Y, -1, p) % p
hf2 = (A + B) * pow(B - A, -1, p) % p
print(f"h/f (from e,f): {hf1}")
print(f"h/f (from f,g): {hf2}")
print(f"Equal: {hf1 == hf2}")

# If they're equal, then we can find e,f,g,h such that:
# e*f = 2XY, f*g = B-A, g*h = A+B, e*h = A-B+C
# Let's try: e = 2XY, h = A-B+C
# Then: f = 1, g = (B-A)
# Check: f*g = 1*(B-A) = B-A ✓
#         g*h = (B-A)*(A-B+C) ... should be A+B
#         e*h = 2XY*(A-B+C) ... should be A-B+C
# Wait, e*h should be A-B+C but e=2XY, h=A-B+C, so e*h = 2XY*(A-B+C)
# That's not equal to A-B+C unless 2XY=1.
# So this doesn't work with f=1.

# Let me try a different approach. The ref10 code uses the multiplication
# form for a reason: it allows sharing intermediate values between doubling
# and addition. Let me try to match the correct P1P1 assignment to the
# multiplication form.

# We need: e*f = 2XY, f*g = B-A, g*h = A+B, e*h = A-B+C
# This means: (e*f)*(g*h) = (e*h)*(f*g) => 2XY*(A+B) = (A-B+C)*(B-A)
# Check:
lhs = (2 * X * Y) * (A + B) % p
rhs = (A - B + C) * (B - A) % p
print(f"\nConsistency check: 2XY*(A+B) = {(A-B+C)*(B-A)%p}")
print(f"                   (A-B+C)*(B-A) = {(A-B+C)*(B-A)%p}")
print(f"Equal: {lhs == rhs}")

# If not equal, the multiplication form can't represent our assignment.
# Let's check:
if lhs != rhs:
    print("Multiplication form is INCONSISTENT with direct assignment!")
    print("The ref10 must use a different P1P1->P3 mapping or different formula.")
    
    # Let me try the OTHER mapping: maybe x = X/T, y = Y/Z instead?
    # That would be if p1p1_to_p3 was: X3 = X*Z, Y3 = Y*T, Z3 = Z*T, T3 = X*Y
    # Then x = X*Z/(Z*T) = X/T, y = Y*T/(Z*T) = Y/Z
    # But the code clearly says X3 = X*T, Y3 = Y*Z, Z3 = Z*T
    
    # Actually wait - maybe the ref10 P1P1 form is DIFFERENT from what
    # this code uses. In the original ref10:
    # ge_p1p1_to_p2: X = X*Z, Y = Y*T, Z = Z*T
    # NOT X = X*T, Y = Y*Z, Z = Z*T !
    
    # Let me check if the code's p1p1_to_p2/p3 is WRONG (swapped Z and T)
    print("\n=== Testing if p1p1_to_p3 has swapped Z/T ===")
    # If the correct mapping is: x = X/T, y = Y/Z
    # Then with the original (buggy) code's formula:
    # x = E*F / (E*H) = F/H = (B-A-2Z²) / (-(A+B))  -- for original buggy f
    # y = G*H / (F*G) = H/F = (-(A+B)) / (B-A-2Z²)
    
    # With the RFC formula (D=-A):
    # x = E*F / (E*H) = F/H = (-A-2Z²) / (B-A)  [F = D-C, H = D+B = B-A]
    # y = G*H / (F*G) = H/F = (B-A) / (-A-2Z²)
    # But we want x3 = 2XY/(1+dAB) = 2XY/(B-A) [using curve eq]
    # So F/H = 2XY/(B-A) => (-A-2Z²)/(B-A) = 2XY/(B-A) => -A-2Z² = 2XY
    # That's not right either.
    
    # Let me try: if p1p1 uses x = X*Z, y = Y*T (different from code's X*T, Y*Z)
    # Then for p1p1_to_p3: X3 = X*Z, Y3 = Y*T, Z3 = Z*T
    # x = X3/Z3 = X*Z/(Z*T) = X/T
    # y = Y3/Z3 = Y*T/(Z*T) = Y/Z
    # So we need: X/T = x3, Y/Z = y3
    # With multiplication form: X=e*f, Y=g*h, Z=f*g, T=e*h
    # x = e*f/(e*h) = f/h
    # y = g*h/(f*g) = h/f
    # So: f/h = x3 = 2XY/(B-A), h/f = y3 = (A+B)/(A-B+C)
    # i.e., f/h = 2XY/(B-A) and h/f = (A+B)/(A-B+C)
    # Product: (f/h)*(h/f) = 1 = 2XY*(A+B)/((B-A)*(A-B+C))
    # Check:
    prod = (2 * X * Y) * (A + B) % p * pow((B - A) * (A - B + C) % p, -1, p) % p
    print(f"Product check: {prod == 1}")
    
    # If not 1, try yet another mapping.
    # Maybe p1p1_to_p3 should be: X3 = X*Y, Y3 = Y*Z, Z3 = Z*T, T3 = X*T
    # (swap X and Y in the multiplication)
    
    # Actually, let me just try ALL possible p1p1_to_p3 mappings.
    # The P1P1 result is (e*f, g*h, e*h, f*g) = (X, Y, Z, T) in some order.
    # The to_p3 conversion multiplies pairs to get extended coords.
    # Standard: X3 = X*T, Y3 = Y*Z, Z3 = Z*T
    # This gives x = X/Z, y = Y/T (as in the code)
    
    # But maybe it should be: X3 = X*Z, Y3 = Y*T, Z3 = Z*T
    # This gives x = X/T, y = Y/Z
    
    # OR maybe the ref10 p1p1 is structured differently.
    # Let me just test all 4 combinations:
    # 1) x = X/Z, y = Y/T  (code's current mapping)
    # 2) x = X/T, y = Y/Z  (swapped)
    # 3) x = X/Y, y = Z/T  (unlikely)
    # 4) x = Y/Z, x = X/T  (unlikely)
    
    E_val = (pow((X+Y)%p, 2, p) - A - B) % p  # 2XY
    
    # RFC formula: D=-A, F=-A-2Z², G=-A-B, H=B-A
    D = (-A) % p
    F_rfc = (D - C) % p  # -A-2Z²
    G_rfc = (D - B) % p  # -A-B
    H_rfc = (D + B) % p  # B-A
    
    # P1P1 values with RFC formula:
    X_p1p1 = E_val * F_rfc % p  # E*F
    Y_p1p1 = G_rfc * H_rfc % p  # G*H
    Z_p1p1 = F_rfc * G_rfc % p  # F*G (code says Z = F*G)
    T_p1p1 = E_val * H_rfc % p  # E*H (code says T = E*H)
    
    for name, xx, yy in [("x=X/Z, y=Y/T", (X_p1p1, Z_p1p1), (Y_p1p1, T_p1p1)),
                          ("x=X/T, y=Y/Z", (X_p1p1, T_p1p1), (Y_p1p1, Z_p1p1)),
                          ("x=Y/Z, y=X/T", (Y_p1p1, Z_p1p1), (X_p1p1, T_p1p1)),
                          ("x=Y/T, y=X/Z", (Y_p1p1, T_p1p1), (X_p1p1, Z_p1p1))]:
        xv = xx[0] * pow(xx[1], -1, p) % p
        yv = yy[0] * pow(yy[1], -1, p) % p
        match = xv == x2B and yv == y2B
        print(f"  {name}: x_match={xv==x2B}, y_match={yv==y2B}, full={match}")

# So the issue might be that the code's p1p1_to_p3 mapping is WRONG,
# or the doubling formula assignment is wrong.
# Let me check what the ACTUAL ref10 does:
# In ref10, ge_p1p1_to_p2 is:
#   fe_mul(r->X, p->X, p->T);
#   fe_mul(r->Y, p->Y, p->Z);
#   fe_mul(r->Z, p->Z, p->T);
# This gives x = X*T/(Z*T) = X/Z, y = Y*Z/(Z*T) = Y/T
# 
# And ge_p2_dbl in ref10 is:
#   fe_sq(a, p->X);       // a = X²
#   fe_sq(b, p->Y);       // b = Y²
#   fe_sq(c, p->Z);       // c = Z²
#   fe_add(c, c, c);      // c = 2Z²
#   fe_add(h, a, b);      // h = A+B
#   fe_sub(e, h, c);      // e = (A+B) - 2Z²
#   fe_add(f, a, a);      // f = 2A
#   fe_sub(f, f, h);      // f = 2A - (A+B) = A - B
#   fe_sub(g, b, a);      // g = B - A
#   fe_add(g, g, c);      // g = (B-A) + 2Z²
#   fe_neg(g, g);         // g = -(B-A+2Z²) = A - B - 2Z²
#   ...
# Wait, that gives g = A - B - 2Z² = f - 2Z² where f = A-B
# Then the multiplication:
#   fe_mul(r->X, e, f);    // X = e*f = ((A+B)-2Z²) * (A-B)
#   fe_mul(r->Y, g, h);    // Y = g*h = (A-B-2Z²) * (A+B)
#   fe_mul(r->T, e, h);    // T = e*h = ((A+B)-2Z²) * (A+B)
#   fe_mul(r->Z, f, g);    // Z = f*g = (A-B) * (A-B-2Z²)
# 
# Let me test THIS formula!

print("\n=== Testing actual ref10 formula ===")
A_val = pow(X, 2, p)
B_val = pow(Y, 2, p)
C_val = 2 * pow(Z, 2, p)

h_val = (A_val + B_val) % p       # A+B
e_val = (h_val - C_val) % p       # (A+B) - 2Z²
f_val = (2 * A_val - h_val) % p   # A - B
g_val = (B_val - A_val) % p       # B - A
g_val = (g_val + C_val) % p       # (B-A) + 2Z²
g_val = (-g_val) % p              # -(B-A+2Z²) = A-B-2Z²

X_p = e_val * f_val % p   # e*f
Y_p = g_val * h_val % p   # g*h
T_p = e_val * h_val % p   # e*h
Z_p = f_val * g_val % p   # f*g

# x = X/Z = e*f / (f*g) = e/g
x_ref10 = X_p * pow(Z_p, -1, p) % p
# y = Y/T = g*h / (e*h) = g/e
y_ref10 = Y_p * pow(T_p, -1, p) % p

print(f"ref10 x = {x_ref10}")
print(f"ref10 y = {y_ref10}")
print(f"on curve: {(-pow(x_ref10,2,p)+pow(y_ref10,2,p))%p == (1+d*pow(x_ref10,2,p)*pow(y_ref10,2,p))%p}")
print(f"matches affine: {x_ref10 == x2B and y_ref10 == y2B}")
