#!/usr/bin/env python3
"""
Exhaustive search for correct ge_p2_dbl + p1p1_to_p3 combination.
We search ALL possible assignments of intermediate products to P1P1 fields,
AND all possible p1p1_to_p3 mappings.
"""
import hashlib
from itertools import permutations, product
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
B_p3 = (Bx, By, 1, Bx * By % p)

# Correct 2B
t_aff = d * pow(Bx, 2, p) * pow(By, 2, p) % p
x2B = (2 * Bx * By) % p * pow(1 + t_aff, -1, p) % p
y2B = (pow(By, 2, p) + pow(Bx, 2, p)) % p * pow(1 - t_aff, -1, p) % p

# For doubling, the intermediate values are:
A = pow(Bx, 2, p)
B = pow(By, 2, p)
C = 2  # 2*Z^2 with Z=1
E = (pow((Bx + By) % p, 2, p) - A - B) % p  # 2*BX*BY
# Other possible intermediate values
vals = {
    'A': A, 'B': B, 'C': C, 'E': E,
    'B-A': (B - A) % p,
    'A-B': (A - B) % p,
    'A+B': (A + B) % p,
    '-A-B': (-A - B) % p,
    'A-B+C': (A - B + C) % p,
    'B-A+C': (B - A + C) % p,
    'B-A-C': (B - A - C) % p,
    'A-B-C': (A - B - C) % p,
    '-A-C': (-A - C) % p,
    '-B-C': (-B - C) % p,
    'A+C': (A + C) % p,
    'B+C': (B + C) % p,
}

keys = list(vals.keys())

# For P1P1: (X, Y, Z, T) with 4 products of pairs from {e,f,g,h}
# p1p1_to_p3: X3 = pair1, Y3 = pair2, Z3 = pair3, T3 = pair4
# where each pair is a product of two P1P1 fields
# x = X3/Z3, y = Y3/Z3, t = T3/Z3

# But actually, the P1P1 fields themselves are products of intermediate values.
# Let's think differently: the 4 P1P1 fields are 4 products of intermediate values.
# Let's try: the 4 fields are chosen from the vals above (or products of 2 vals).

# Actually, let's simplify. The P1P1 has 4 fields, each is a product of 2 intermediates.
# But the p1p1_to_p3 multiplies pairs of P1P1 fields.
# So ultimately, X3/Y3/Z3/T3 are each products of 4 intermediates (or 2 P1P1 fields).

# Let's just search: what 4 products of intermediates (from vals) can serve as
# X3, Y3, Z3, T3 such that x=X3/Z3, y=Y3/Z3, t=T3/Z3=x*y?
# Each of X3,Y3,Z3,T3 is a product of 2 vals.

print("Searching for (X3, Y3, Z3, T3) as products of 2 intermediates...")
print(f"Target: x={x2B}, y={y2B}")

found = False
val_keys = list(vals.keys())
n = len(val_keys)
for i1 in range(n):
    for i2 in range(n):
        X3 = vals[val_keys[i1]] * vals[val_keys[i2]] % p
        if X3 == 0: continue
        for i3 in range(n):
            for i4 in range(n):
                Z3 = vals[val_keys[i3]] * vals[val_keys[i4]] % p
                if Z3 == 0: continue
                x = X3 * pow(Z3, -1, p) % p
                if x != x2B: continue
                for i5 in range(n):
                    for i6 in range(n):
                        Y3 = vals[val_keys[i5]] * vals[val_keys[i6]] % p
                        y = Y3 * pow(Z3, -1, p) % p
                        if y != y2B: continue
                        target_t = x * y % p
                        for i7 in range(n):
                            for i8 in range(n):
                                T3 = vals[val_keys[i7]] * vals[val_keys[i8]] % p
                                t = T3 * pow(Z3, -1, p) % p
                                if t == target_t:
                                    print(f"FOUND! X3={val_keys[i1]}*{val_keys[i2]}, "
                                          f"Y3={val_keys[i5]}*{val_keys[i6]}, "
                                          f"Z3={val_keys[i3]}*{val_keys[i4]}, "
                                          f"T3={val_keys[i7]}*{val_keys[i8]}")
                                    found = True
    if found:
        break

if not found:
    print("Not found with 2-intermediate products.")
    # Try with single intermediates
    print("\nSearching with single intermediates...")
    for k1 in val_keys:
        for k2 in val_keys:
            Z3 = vals[k1] * vals[k2] % p
            if Z3 == 0: continue
            x = X3_single = vals[k1]  # Try X3 = single val
            # Actually this doesn't make sense. Let me try X3, Y3, Z3, T3 as single vals.
            pass
    print("Trying X3, Y3, Z3, T3 as single intermediates...")
    for k1 in val_keys:
        for k2 in val_keys:
            if k1 == k2: continue
            for k3 in val_keys:
                if k3 in (k1, k2): continue
                for k4 in val_keys:
                    if k4 in (k1, k2, k3): continue
                    Z3 = vals[k1]
                    if Z3 == 0: continue
                    x = vals[k2] * pow(Z3, -1, p) % p
                    if x != x2B: continue
                    y = vals[k3] * pow(Z3, -1, p) % p
                    if y != y2B: continue
                    t_target = x * y % p
                    t = vals[k4] * pow(Z3, -1, p) % p
                    if t == t_target:
                        print(f"FOUND (single)! X3={k2}, Y3={k3}, Z3={k1}, T3={k4}")
                        found = True
    if not found:
        print("Not found with single intermediates either.")
