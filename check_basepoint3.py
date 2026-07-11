p = 2**255 - 19

# RFC values
Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
d = -121665 * pow(121666, -1, p) % p

x2 = pow(Bx, 2, p)
y2 = pow(By, 2, p)

print(f"d = {d}")
print(f"Bx² = {x2}")
print(f"By² = {y2}")
print()

# Try ALL possible equation combinations to find which one makes (Bx, By) satisfy
# or which x² formula gives Bx²
forms = [
    ("-x² + y² = 1 + d*x²*y² (twisted)", 
     lambda: (y2 - x2) % p,
     lambda: (1 + d * x2 * y2) % p),
    ("-x² + y² = 1 - d*x²*y²", 
     lambda: (y2 - x2) % p,
     lambda: (1 - d * x2 * y2) % p),
    ("x² + y² = 1 + d*x²*y² (untwisted)", 
     lambda: (x2 + y2) % p,
     lambda: (1 + d * x2 * y2) % p),
    ("x² + y² = 1 - d*x²*y²", 
     lambda: (x2 + y2) % p,
     lambda: (1 - d * x2 * y2) % p),
    ("-x² - y² = 1 + d*x²*y²", 
     lambda: (-x2 - y2) % p,
     lambda: (1 + d * x2 * y2) % p),
    ("-x² + y² = 1 + d*x²*y²", 
     lambda: (y2 - x2) % p,
     lambda: (1 + d * x2 * y2) % p),
]

print("=== Curve equation checks ===")
for name, lhs_fn, rhs_fn in forms:
    l = lhs_fn()
    r = rhs_fn()
    if l == r:
        print(f"✓ MATCH: {name}")
        print(f"  LHS = RHS = {l}")
    else:
        print(f"✗ No: {name}")

print()

# Now try all possible x² recovery formulas to see which gives Bx²
forms_x2 = [
    ("(y² - 1)/(1 + d*y²)", (y2 - 1) * pow(1 + d * y2, -1, p) % p),
    ("(y² - 1)/(d*y² + 1)", (y2 - 1) * pow(d * y2 + 1, -1, p) % p),
    ("(1 - y²)/(1 + d*y²)", (1 - y2) * pow(1 + d * y2, -1, p) % p),
    ("(1 - y²)/(1 - d*y²)", (1 - y2) * pow(1 - d * y2, -1, p) % p),
    ("(y² - 1)/(1 - d*y²)", (y2 - 1) * pow(1 - d * y2, -1, p) % p),
    ("(1 - y²)/(d*y² - 1)", (1 - y2) * pow(d * y2 - 1, -1, p) % p),
    ("(y² - 1)/(d*y² - 1)", (y2 - 1) * pow(d * y2 - 1, -1, p) % p),
    ("(y² - 1)/(d²*y² + 1)", (y2 - 1) * pow(pow(d,2,p) * y2 + 1, -1, p) % p),
]

print(f"Bx² (direct) = {x2}")
print()
print("=== x² recovery formulas ===")
for name, val in forms_x2:
    if val == x2:
        print(f"✓ MATCH: {name}")
        print(f"  x² = {val}")
    else:
        print(f"✗ No: {name}")
        print(f"  got = {val}")
