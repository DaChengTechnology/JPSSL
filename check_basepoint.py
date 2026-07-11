p = 2**255 - 19
d = -121665 * pow(121666, -1, p) % p

# RFC 8032 Section 5.1 basepoint
Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960

print(f"p = {p}")
print(f"d = {d}")
print(f"d (hex) = {d.to_bytes(32, 'little').hex()}")
print(f"Bx = {Bx}")
print(f"By = {By}")

# Verify curve equation: -x^2 + y^2 = 1 + d * x^2 * y^2 (mod p)
# => y^2 - x^2 = 1 + d*x^2*y^2
# => y^2 - 1 = x^2 * (1 + d*y^2)
# => x^2 = (y^2 - 1) / (1 + d*y^2)
lhs = (-pow(Bx, 2, p) + pow(By, 2, p)) % p
rhs = (1 + d * pow(Bx, 2, p) * pow(By, 2, p)) % p
print(f"\nCurve check: LHS = {lhs}, RHS = {rhs}, match = {lhs == rhs}")

# Now recompute x from y
y = By
y2 = pow(y, 2, p)
x2 = (y2 - 1) * pow(1 + d * y2, -1, p) % p
print(f"\nComputed x^2 = {x2}")

# sqrt mod p using (p+3)/8 trick since p = 5 mod 8
# For a square a, sqrt is a^((p+3)/8) or 2*a*(4*a)^((p-5)/8)
# Actually, for p = 5 mod 8:
# Let a1 = a^((p+3)/8) mod p
# If a1^2 == a mod p, then a1 is the sqrt
# Else if a1^2 == -a mod p, then sqrt = a1 * sqrt(-1) mod p = a1 * 2^((p-1)/4) mod p

# Compute sqrt of x2
a1 = pow(x2, (p + 3) // 8, p)
# Check if a1^2 == x2
if pow(a1, 2, p) == x2:
    x_computed = a1
    print(f"sqrt found directly: a1 works")
else:
    # Check if (a1^2) % p == p - x2 (i.e., a1^2 == -x2)
    if pow(a1, 2, p) == p - x2:
        # Multiply by sqrt(-1) = 2^((p-1)/4)
        sqrtm1 = pow(2, (p - 1) // 4, p)
        x_computed = a1 * sqrtm1 % p
        print(f"sqrt found via sqrt(-1) adjustment")
    else:
        # Check 2*a*(4*a)^((p-5)/8)
        x_computed = (2 * x2 * pow(4 * x2, (p - 5) // 8, p)) % p
        print(f"sqrt found via alternative method")

print(f"\nComputed x = {x_computed}")
print(f"RFC x = {Bx}")
print(f"Match: {x_computed == Bx}")

# Check parity (LSB) - for basepoint, sign bit should be 0 (positive x = LSB = 0)
print(f"\nComputed x LSB = {x_computed & 1}")
print(f"RFC x LSB = {Bx & 1}")

# Try negating computed x
x_neg = p - x_computed
print(f"Negated computed x LSB = {x_neg & 1}")

# Convert to bytes
x_bytes = x_computed.to_bytes(32, 'little')
print(f"\nComputed x bytes: {x_bytes.hex()}")
Bx_bytes = Bx.to_bytes(32, 'little')
print(f"RFC x bytes:      {Bx_bytes.hex()}")

# Check curve equation with computed x
lhs2 = (-pow(x_computed, 2, p) + pow(y, 2, p)) % p
rhs2 = (1 + d * pow(x_computed, 2, p) * pow(y, 2, p)) % p
print(f"\nCurve check (computed x): LHS = {lhs2}, RHS = {rhs2}, match = {lhs2 == rhs2}")

# What about the RFC Bx - what y does it correspond to?
# Try: is RFC Bx = p - computed_x?
print(f"\nIs RFC Bx = -computed_x? {Bx == p - x_computed}")
print(f"p - computed_x = {p - x_computed}")

# Let me also double-check: what is y = 4/5 mod p?
y_4_5 = 4 * pow(5, -1, p) % p
print(f"\ny from 4/5 = {y_4_5}")
print(f"By == y(4/5)? {By == y_4_5}")
