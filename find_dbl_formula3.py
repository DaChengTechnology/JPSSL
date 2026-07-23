#!/usr/bin/env python3
"""Re-check the consistency and find correct formula."""
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

X, Y, Z = Bx, By, 1
A = pow(X, 2, p)
B = pow(Y, 2, p)
C = 2 * pow(Z, 2, p)

# Correct affine 2B
t_affine = d * A * B % p
x2B = (2 * X * Y) % p * pow(1 + t_affine, -1, p) % p
y2B = (B + A) % p * pow(1 - t_affine, -1, p) % p

# The consistency check from before
lhs = (2 * X * Y) * (A + B) % p
rhs = (A - B + C) * (B - A) % p
print(f"Consistency: lhs={lhs}, rhs={rhs}, equal={lhs == rhs}")

# The direct P1P1 assignment that works:
# x = X_p1p1/Z_p1p1 = 2XY/(B-A)  [using curve eq: 1+dAB = B-A for Z=1]
# y = Y_p1p1/T_p1p1 = (A+B)/(A-B+C) [using curve eq: 1-dAB = A-B+C for Z=1]
# 
# Since this works (verified earlier), let me find the multiplication form.
# We need: e*f = 2XY, f*g = B-A, g*h = A+B, e*h = A-B+C
# From e*f=2XY and f*g=B-A: e/g = 2XY/(B-A)
# From g*h=A+B and e*h=A-B+C: g/e = (A+B)/(A-B+C)
# Product: (e/g)*(g/e) = 1 = 2XY*(A+B)/((B-A)*(A-B+C))
# Check:
prod = (2*X*Y) * (A+B) % p * pow((B-A) * (A-B+C) % p, -1, p) % p
print(f"Product = {prod}, is 1: {prod == 1}")

# Since the product IS 1, the multiplication form IS consistent!
# So we need: e*f = 2XY, f*g = B-A, g*h = A+B, e*h = A-B+C
# Let's solve: choose e = 2XY, then f = 1, g = B-A, h = (A+B)/(B-A)...
# No, we need e,h as well.
# From e*f=2XY and e*h=A-B+C: f/h = 2XY/(A-B+C)
# From f*g=B-A and g*h=A+B: f/h = (B-A)/(A+B)
# So: 2XY/(A-B+C) = (B-A)/(A+B)
# Cross multiply: 2XY*(A+B) = (A-B+C)*(B-A)
# This is exactly our consistency check, which PASSED!
# So the multiplication form is consistent.

# Now let's choose: e = 2XY (which is (X+Y)^2 - X^2 - Y^2)
# Then: f = 1 (constant), g = (B-A)/f = B-A, h = (A+B)/g = (A+B)/(B-A)
# But h = (A+B)/(B-A) requires an inversion, which is bad.

# Better: choose e = 2XY, h = A-B+C
# Then: f = (A-B+C)/(2XY)  ... also requires inversion.

# The ref10 approach is different: it doesn't use the curve equation directly.
# Instead, it uses the formula from the paper with D = a*A = -A.
# Let me re-examine why the RFC formula didn't work.

# The RFC formula (D=-A):
# E = (X+Y)^2 - A - B = 2XY
# F = D - C = -A - 2Z^2
# G = D - B = -A - B = -(A+B)
# H = D + B = B - A
# X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
# 
# x = X3/Z3 = E*F/(F*G) = E/G = 2XY / (-(A+B)) = -2XY/(A+B)
# y = Y3/T3 = G*H/(E*H) = G/E = -(A+B)/(2XY)
#
# But we want: x = 2XY/(B-A), y = (A+B)/(A-B+C)
# 
# So: -2XY/(A+B) should equal 2XY/(B-A)
# => -(A+B) = (B-A) => -A-B = B-A => -2B = 0, which is false.
#
# This means the RFC formula (D=a*A) is NOT the same as what the ref10 uses!
# The ref10 must use a DIFFERENT formula.

# Let me try the formula where:
# e = (A+B) - C  (NOT (X+Y)^2 - A - B)
# f = A - B
# g = A - B - 2Z^2  (= f - C)
# h = A + B
# X3 = e*f, Y3 = g*h, T3 = e*h, Z3 = f*g
# x = e*f/(f*g) = e/g = ((A+B)-C) / (A-B-C) = (A+B-2Z^2)/(A-B-2Z^2)
# y = g*h/(e*h) = g/e = (A-B-2Z^2)/(A+B-2Z^2)
# 
# This gives x = 1/y, which is clearly wrong.

# Let me try another formula:
# e = (X+Y)^2 - A - B = 2XY
# f = A - B  (NOT -A-C)
# g = -(A+B)  (same as before)
# h = B - A  (= -f)
# X3 = e*f = 2XY*(A-B)
# Y3 = g*h = -(A+B)*(B-A) = (A+B)*(A-B)
# T3 = e*h = 2XY*(B-A) = -2XY*(A-B)
# Z3 = f*g = (A-B)*(-(A+B)) = -(A-B)*(A+B)
# x = X3/Z3 = 2XY*(A-B) / (-(A-B)*(A+B)) = -2XY/(A+B)
# y = Y3/T3 = (A+B)*(A-B) / (-2XY*(A-B)) = -(A+B)/(2XY)
# Same as before! This is the same formula with different variable names.

# The issue is fundamental: the E*F, G*H, E*H, F*G structure with 
# x = E/G, y = G/E means y = 1/x (since x = E/G and y = G/E = 1/x).
# But for Ed25519, x and y are NOT reciprocals!

# Wait, that can't be right. Let me re-read the P1P1 mapping.
# ge_p1p1_to_p3: X3 = X*T, Y3 = Y*Z, Z3 = Z*T, T3 = X*Y
# x = X3/Z3 = X*T/(Z*T) = X/Z
# y = Y3/Z3 = Y*Z/(Z*T) = Y/T
# 
# So x = X/Z and y = Y/T. These are INDEPENDENT ratios.
# With X=e*f, Y=g*h, Z=f*g, T=e*h:
# x = e*f/(f*g) = e/g
# y = g*h/(e*h) = g/e
# So y = 1/x!!! 
#
# But for a point on the curve, y is NOT 1/x. So the multiplication form
# X=e*f, Y=g*h, Z=f*g, T=e*h CANNOT represent an arbitrary point.
# It can only represent points where y = 1/x.
#
# This means the ge_p2_dbl code MUST use a DIFFERENT assignment, not the
# standard E*F, G*H, E*H, F*G form.
#
# OR: the P1P1->P3 conversion in the code is WRONG.
# The correct ref10 conversion should give independent x and y.
# Let me check: maybe the correct conversion is:
# X3 = X*T, Y3 = Y*Z, Z3 = Z*T (for P2)
# which gives x = X/Z, y = Y/T... and y = G/E = 1/x. 
# That means ALL points produced by this P1P1 system have y = 1/x, 
# which is absurd.
#
# I must be making an error somewhere. Let me verify with ge_add.
# ge_add: a=Y-X, b=Y+X, c=T*T*d2, d=Z*Z*2, e=b-a, f=d-c, g=d+c, h=b+a
# r->X = e*f, r->Y = g*h, r->T = e*h, r->Z = f*g
# x = e*f/(f*g) = e/g = (b-a)/(d+c) = (2X)/(2Z^2+2T1*T2*d2) ... wait
# e = b-a = (Y1+X1)-(Y1-X1) = 2*X1 ... but this is point addition, 
# so the variables are mixed between P and Q.
# Let me look at this more carefully.

# For ge_add(P, Q):
# a = (Y1-X1) * (Y2-X2)
# b = (Y1+X1) * (Y2+X2)
# c = T1 * T2 * d2
# d = Z1 * Z2 * 2
# e = b - a
# f = d - c
# g = d + c
# h = b + a
# r->X = e*f
# r->Y = g*h
# r->T = e*h
# r->Z = f*g
# 
# x = e*f / (f*g) = e/g = (b-a)/(d+c)
# y = g*h / (e*h) = g/e = (d+c)/(b-a)
# 
# So y = 1/x AGAIN! This can't be right.
# Unless I'm wrong about the P1P1->P3 conversion.
#
# WAIT. Let me re-read the code more carefully.

# ge_p1p1_to_p3: 
#   fe_mul(r->X, p->X, p->T);   // X3 = X * T
#   fe_mul(r->Y, p->Y, p->Z);   // Y3 = Y * Z
#   fe_mul(r->Z, p->Z, p->T);   // Z3 = Z * T
#   fe_mul(r->T, p->X, p->Y);   // T3 = X * Y
#
# So in P3 (extended coords): x = X3/Z3 = X*T/(Z*T) = X/Z, y = Y3/Z3 = Y*Z/(Z*T) = Y/T
# With P1P1 from ge_add: X=e*f, Y=g*h, Z=f*g, T=e*h
# x = e*f / (f*g) = e/g
# y = g*h / (e*h) = g/e
# So y = g/e = 1/(e/g) = 1/x. 
#
# THIS IS THE BUG! The p1p1_to_p3 conversion is wrong!
# 
# The CORRECT ref10 conversion is:
# X3 = X * T, Y3 = Y * Z, Z3 = Z * T, T3 = X * Y
# In ref10: x = X3/Z3 = X*T/(Z*T) = X/Z
#           y = Y3/Z3 = Y*Z/(Z*T) = Y/T
#           t = T3/Z3 = X*Y/(Z*T)
#
# But with ge_p2_dbl producing X=e*f, Y=g*h, Z=f*g, T=e*h:
# x = e*f/(f*g) = e/g
# y = g*h/(e*h) = g/e
# So y = 1/x. This means ge_p2_dbl with this conversion CANNOT work.
#
# UNLESS... the correct formula uses a DIFFERENT assignment of e,f,g,h
# to X,Y,Z,T in the P1P1 struct.
#
# In the ref10 code, the P1P1 struct has fields (X, Y, Z, T).
# The doubling/addition formulas assign to these fields.
# But the mapping to the final result depends on which field
# gets which product.
#
# For ge_p2_dbl, the CORRECT ref10 assignment is:
# r->X = e * f
# r->Y = g * h
# r->Z = f * g  
# r->T = e * h
# BUT the P1P1->P3 conversion is:
# X3 = X * Z  (NOT X * T!)
# Y3 = Y * T  (NOT Y * Z!)
# Z3 = Z * T
# T3 = X * Y
#
# Wait, maybe the ref10 uses X*Z, Y*T instead of X*T, Y*Z!
# Let me check: with X3 = X*Z, Y3 = Y*T, Z3 = Z*T:
# x = X*Z / (Z*T) = X/T = e*f/(e*h) = f/h
# y = Y*T / (Z*T) = Y/Z = g*h/(f*g) = h/f
# So x = f/h and y = h/f = 1/x. STILL 1/x!
#
# Hmm, let me try: X3 = X*Y, Y3 = Z*T, Z3 = Z*T, T3 = X*Y
# x = X*Y/(Z*T) = e*f*g*h/(f*g*e*h) = 1. Nope.
#
# OK so the issue is that with X=e*f, Y=g*h, Z=f*g, T=e*h:
# ANY pairing of (X or Y) * (Z or T) gives:
# X*Z = e*f*f*g, X*T = e*f*e*h, Y*Z = g*h*f*g, Y*T = g*h*e*h
# Ratios: X*Z/(Z*T) = e*f/(e*h) = f/h, Y*Z/(Z*T) = g*h/(e*h) = g/e
# Or: X*T/(Z*T) = e*f/(f*g) = e/g, Y*Z/(Z*T) = g*h/(f*g) = h/f
# 
# For x=e/g, y=h/f: x*y = (e*h)/(g*f) = (e*h)/(f*g) = T/Z
# For x=f/h, y=g/e: x*y = (f*g)/(h*e) = Z/T = 1/(T/Z)
# 
# Neither gives independent x and y.
# 
# THE CONCLUSION: The standard ref10 E*F, G*H, E*H, F*G form with
# p1p1_to_p3: X3=X*T, Y3=Y*Z, Z3=Z*T DOES produce y=1/x.
# This means either:
# 1. My understanding of the ref10 is wrong, OR
# 2. The code's p1p1_to_p3 is wrong
# 
# Let me verify by checking if ge_add works correctly.
# If ge_add also produces y=1/x, then the p1p1_to_p3 conversion is wrong.

print("\n=== Checking if ge_add works ===")
# ge_add(P, Q) with P=B, Q=B (i.e., 2B via addition)
# a = (Y1-X1)*(Y2-X2)
# b = (Y1+X1)*(Y2+X2)
# c = T1*T2*d2
# d = Z1*Z2*2
# e = b-a, f = d-c, g = d+c, h = b+a
# X = e*f, Y = g*h, T = e*h, Z = f*g

X1, Y1, Z1, T1 = Bx, By, 1, Bx*By%p
X2, Y2, Z2, T2 = Bx, By, 1, Bx*By%p

a_add = (Y1 - X1) * (Y2 - X2) % p
b_add = (Y1 + X1) * (Y2 + X2) % p
d2_val = (2 * d) % p
c_add = T1 * T2 % p * d2_val % p
d_add = Z1 * Z2 % p * 2 % p
e_add = (b_add - a_add) % p
f_add = (d_add - c_add) % p
g_add = (d_add + c_add) % p
h_add = (b_add + a_add) % p

X_p1p1_add = e_add * f_add % p
Y_p1p1_add = g_add * h_add % p
T_p1p1_add = e_add * h_add % p
Z_p1p1_add = f_add * g_add % p

# Code's p1p1_to_p3: X3 = X*T, Y3 = Y*Z, Z3 = Z*T
X3_add = X_p1p1_add * T_p1p1_add % p
Y3_add = Y_p1p1_add * Z_p1p1_add % p
Z3_add = Z_p1p1_add * T_p1p1_add % p

x_add = X3_add * pow(Z3_add, -1, p) % p
y_add = Y3_add * pow(Z3_add, -1, p) % p
print(f"ge_add(B,B) x = {x_add}")
print(f"ge_add(B,B) y = {y_add}")
print(f"y == 1/x: {y_add == pow(x_add, -1, p)}")
print(f"matches 2B: {x_add == x2B and y_add == y2B}")
print(f"on curve: {(-pow(x_add,2,p)+pow(y_add,2,p))%p == (1+d*pow(x_add,2,p)*pow(y_add,2,p))%p}")

# Try swapped: X3 = X*Z, Y3 = Y*T, Z3 = Z*T
X3_swap = X_p1p1_add * Z_p1p1_add % p
Y3_swap = Y_p1p1_add * T_p1p1_add % p
Z3_swap = Z_p1p1_add * T_p1p1_add % p

x_swap = X3_swap * pow(Z3_swap, -1, p) % p
y_swap = Y3_swap * pow(Z3_swap, -1, p) % p
print(f"\nSwapped p1p1_to_p3:")
print(f"ge_add(B,B) x = {x_swap}")
print(f"ge_add(B,B) y = {y_swap}")
print(f"y == 1/x: {y_swap == pow(x_swap, -1, p)}")
print(f"matches 2B: {x_swap == x2B and y_swap == y2B}")
