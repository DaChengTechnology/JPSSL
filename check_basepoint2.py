p = 2**255 - 19
d = -121665 * pow(121666, -1, p) % p

# RFC 8032 Section 5.1 basepoint
Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960

print("=== Verification of RFC 8032 constants ===")
print(f"d = {d}")
print(f"Bx = {Bx}")
print(f"By = {By}")
print()

# 1. Verify d
print("=== Verify d ===")
print(f"121666 * d mod p = {(121666 * d) % p}")
print(f"p - 121665 = {p - 121665}")
print(f"Match? {(121666 * d) % p == p - 121665}")
print()

# 2. Curve equation: -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)
x2 = pow(Bx, 2, p)
y2 = pow(By, 2, p)
lhs = (y2 - x2) % p
rhs = (1 + d * x2 * y2) % p
print("=== Curve equation check: -x^2 + y^2 = 1 + d*x^2*y^2 ===")
print(f"LHS (-x^2 + y^2) mod p = {lhs}")
print(f"RHS (1 + d*x^2*y^2) mod p = {rhs}")
print(f"Match? {lhs == rhs}")
print()

# 3. Try untwisted: x^2 + y^2 = 1 + d*x^2*y^2
lhs2 = (x2 + y2) % p
print("=== Untwisted: x^2 + y^2 = 1 + d*x^2*y^2 ===")
print(f"LHS (x^2 + y^2) mod p = {lhs2}")
print(f"RHS (1 + d*x^2*y^2) mod p = {rhs}")
print(f"Match? {lhs2 == rhs}")
print()

# 4. Try with different d: what if d = -d?
d2 = (-d) % p
lhs3 = (y2 - x2) % p
rhs3 = (1 + d2 * x2 * y2) % p
print("=== With negated d ===")
print(f"d' = {d2}")
print(f"LHS (-x^2 + y^2) mod p = {lhs3}")
print(f"RHS (1 + d'*x^2*y^2) mod p = {rhs3}")
print(f"Match? {lhs3 == rhs3}")
print()

# 5. What's the X-recovery formula? x = sqrt((y^2-1)/(d*y^2+1))
# Actually for -x^2 + y^2 = 1 + d*x^2*y^2:
# y^2 - 1 = x^2 + d*x^2*y^2 = x^2 * (1 + d*y^2)
# x^2 = (y^2 - 1) / (1 + d*y^2)   ✓ This is the formula used by RFC
print("=== Recover x from y using the recovery formula ===")
y = By
y2 = pow(y, 2, p)
num = y2 - 1
denom = 1 + d * y2
x2_recovered = num * pow(denom, -1, p) % p
print(f"x^2 recovered = {x2_recovered}")
print(f"x^2 direct    = {x2}")
print(f"Match? {x2_recovered == x2}")
print()

# 6. Compute sqrt of recovered x^2
# Since p = 5 mod 8, use the standard algorithm
def sqrt_mod_p(a):
    """Compute sqrt(a) mod p using p = 5 mod 8 algorithm."""
    a1 = pow(a, (p + 3) // 8, p)
    if pow(a1, 2, p) == a:
        return a1
    # Check a1^2 == -a
    if pow(a1, 2, p) == (-a) % p:
        sqrtm1 = pow(2, (p - 1) // 4, p)
        return (a1 * sqrtm1) % p
    # Alternative: 2a * (4a)^((p-5)/8)
    alt = (2 * a) % p * pow(4 * a, (p - 5) // 8, p) % p
    if pow(alt, 2, p) == a:
        return alt
    return None

x_recovered = sqrt_mod_p(x2_recovered)
x_neg = (-x_recovered) % p

print(f"Positive sqrt of x^2 = {x_recovered}")
print(f"Negative sqrt of x^2 = {x_neg}")
print(f"RFC Bx               = {Bx}")
print(f"Match positive? {x_recovered == Bx}")
print(f"Match negative? {x_neg == Bx}")
print(f"x_recovered LSB = {x_recovered & 1}")
print(f"satisfies curve eq? ", end="")
lx = (y2 - pow(x_recovered, 2, p)) % p
rx = (1 + d * pow(x_recovered, 2, p) * y2) % p
print(f"{lx == rx}")
print()

# 7. Try computing sqrt of x2 directly (what RFC would do for sign recovery)
x_from_y = sqrt_mod_p(x2_recovered)
# Choose x with desired sign bit (0 for basepoint)
if (x_from_y & 1) != 0:
    x_from_y = (-x_from_y) % p
print(f"x recovered with positive LSB = {x_from_y}")
print(f"RFC Bx = {Bx}")
print(f"Match? {x_from_y == Bx}")

# Check curve equation with this x
lx3 = (y2 - pow(x_from_y, 2, p)) % p
rx3 = (1 + d * pow(x_from_y, 2, p) * y2) % p
print(f"x_from_y satisfies curve equation? {lx3 == rx3}")
