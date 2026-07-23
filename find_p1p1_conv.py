#!/usr/bin/env python3
"""Find the correct p1p1_to_p3 conversion."""
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

# Correct 2B (affine)
t_affine = d * pow(Bx, 2, p) * pow(By, 2, p) % p
x2B = (2 * Bx * By) % p * pow(1 + t_affine, -1, p) % p
y2B = (pow(By, 2, p) + pow(Bx, 2, p)) % p * pow(1 - t_affine, -1, p) % p

# ge_add(B, B) = 2B
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

X_p1p1 = e_add * f_add % p
Y_p1p1 = g_add * h_add % p
T_p1p1 = e_add * h_add % p
Z_p1p1 = f_add * g_add % p

# Try ALL possible p1p1_to_p3 conversions
# X3, Y3 can each be one of: X*Y, X*Z, X*T, Y*Z, Y*T, Z*T
# Z3 must involve Z and T (to cancel out properly)
# T3 (for extended) must give T = XY/Z
print("=== Testing all p1p1_to_p3 conversions ===")
print(f"Target: x={x2B}, y={y2B}")
print()

products = {
    'XY': X_p1p1 * Y_p1p1 % p,
    'XZ': X_p1p1 * Z_p1p1 % p,
    'XT': X_p1p1 * T_p1p1 % p,
    'YZ': Y_p1p1 * Z_p1p1 % p,
    'YT': Y_p1p1 * T_p1p1 % p,
    'ZT': Z_p1p1 * T_p1p1 % p,
}

# Z3 is always Z*T (this is standard)
Z3_val = products['ZT']

for xname in ['XY', 'XZ', 'XT', 'YZ', 'YT', 'ZT']:
    for yname in ['XY', 'XZ', 'XT', 'YZ', 'YT', 'ZT']:
        if xname == yname:
            continue
        xv = products[xname] * pow(Z3_val, -1, p) % p
        yv = products[yname] * pow(Z3_val, -1, p) % p
        if xv == x2B and yv == y2B:
            print(f"MATCH! X3={xname}, Y3={yname}, Z3=ZT")
