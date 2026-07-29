#!/usr/bin/env python3
"""Python simulation of fe448_mul and fe448_reduce to find overflow bug."""

MASK56 = (1 << 56) - 1
P = (1 << 448) - (1 << 224) - 1

def fe448_frombytes(s):
    """Simulate fe448_frombytes: 56 bytes -> 8 limbs of 56 bits"""
    h = [0] * 8
    for i in range(8):
        v = 0
        for j in range(6, -1, -1):
            v = (v << 8) | s[7*i + j]
        h[i] = v & MASK56
    return h

def fe448_to_big(h):
    """Convert 8-limb representation to an integer"""
    val = 0
    for i in range(8):
        val += h[i] << (56 * i)
    return val

def fe448_reduce_py(full):
    """Python implementation of fe448_reduce, returns out[0..7]"""
    # The do-while fold loop
    again = True
    while again:
        again = False
        for m in range(8):
            hi = full[8 + m]
            if hi != 0:
                if m < 4:
                    full[m] += hi
                    full[m + 4] += hi
                else:
                    full[m] += 2 * hi
                    full[m - 4] += hi
                full[8 + m] = 0
                again = True
    
    out = [0] * 8
    carry = 0
    for i in range(8):
        c = full[i] + carry
        out[i] = c & MASK56
        carry = c >> 56
    
    if carry:
        out[0] += carry
        out[4] += carry
        c = 0
        for i in range(8):
            v = out[i] + c
            out[i] = v & MASK56
            c = v >> 56
        while c:
            out[0] += c
            c = out[0] >> 56
            out[0] &= MASK56
            out[4] += c
            c = out[4] >> 56
            out[4] &= MASK56
            for i in range(1, 8):
                if i == 4:
                    continue
                out[i] += c
                c = out[i] >> 56
                out[i] &= MASK56
                if not c:
                    break
    
    return out

def fe448_mul_py(f, g):
    """Python implementation of fe448_mul"""
    full = [0] * 16
    for i in range(8):
        for j in range(8):
            full[i + j] += f[i] * g[j]
    out = fe448_reduce_py(full)
    
    # Conditional subtraction (out - p if out >= p)
    val = fe448_to_big(out)
    if val >= P:
        val -= P
        for i in range(8):
            out[i] = (val >> (56 * i)) & MASK56
    
    return out

def fe448_sq_py(f):
    """Python implementation of fe448_sq"""
    return fe448_mul_py(f, f)

def fe448_invert_py(z):
    """Python implementation of fe448_invert"""
    res = z.copy()
    acc = z.copy()
    for i in range(1, 448):
        acc = fe448_sq_py(acc)
        bit = (i != 1 and i != 224)
        if bit:
            res = fe448_mul_py(res, acc)
    return res

def fe448_tobytes_py(h):
    """Python implementation of fe448_tobytes"""
    v = [0] * 8
    carry = 0
    for i in range(8):
        c = h[i] + carry
        v[i] = c & MASK56
        carry = c >> 56
    
    if carry:
        v[0] += carry
        v[4] += carry
        c = 0
        for i in range(8):
            val = v[i] + c
            v[i] = val & MASK56
            c = val >> 56
        while c:
            v[0] += c
            c = v[0] >> 56
            v[0] &= MASK56
            v[4] += c
            c = v[4] >> 56
            v[4] &= MASK56
            for i in range(1, 8):
                if i == 4:
                    continue
                v[i] += c
                c = v[i] >> 56
                v[i] &= MASK56
                if not c:
                    break
    
    # Conditional subtraction: out >= p?
    w = v.copy()
    cc = 1
    for i in range(8):
        if cc == 0:
            break
        c = w[i] + cc
        w[i] = c & MASK56
        cc = c >> 56
    
    c4 = w[4] + 1
    w[4] = c4 & MASK56
    cc = c4 >> 56
    for i in range(5, 8):
        if cc == 0:
            break
        c = w[i] + cc
        w[i] = c & MASK56
        cc = c >> 56
    
    if cc != 0:
        v = w[:]
    
    # Write bytes
    s = [0] * 56
    for i in range(8):
        x = v[i]
        for j in range(7):
            s[7*i + j] = (x >> (8 * j)) & 0xFF
    return bytes(s)


# Test 1: 2^2 mod p
two = fe448_frombytes(b'\x02' + b'\x00' * 55)
result = fe448_mul_py(two, two)
print("2^2 limbs:", [hex(x) for x in result])
print("2^2 value:", fe448_to_big(result))
print("2^2 bytes:", fe448_tobytes_py(result).hex())

# Test 2: compute inverse of 2
inv2_expected_val = (P + 1) // 2
inv2_expected_limbs = [(inv2_expected_val >> (56*i)) & MASK56 for i in range(8)]
print("\nExpected inv2 limbs:", [hex(x) for x in inv2_expected_limbs])
print("Expected inv2 bytes:", fe448_tobytes_py(inv2_expected_limbs).hex())

# Compute inv2 using our Python invert
print("\nComputing inv2 via fe448_invert_py...")
inv2 = fe448_invert_py(two)
print("inv2 limbs:", [hex(x) for x in inv2])
print("inv2 bytes:", fe448_tobytes_py(inv2).hex())
print("inv2 value:", fe448_to_big(inv2))
print("Expected value:", inv2_expected_val)
print("Match:", fe448_to_big(inv2) == inv2_expected_val)

# Verify: 2 * inv2 mod p
prod = fe448_mul_py(two, inv2)
print("\n2 * inv2 limbs:", [hex(x) for x in prod])
print("2 * inv2 value:", fe448_to_big(prod))
print("2 * inv2 bytes:", fe448_tobytes_py(prod).hex())

# Test 3: check that fe448_reduce_py works for the multiplication case
full = [0] * 16
for i in range(8):
    for j in range(8):
        full[i+j] += two[i] * two[j]
print("\nfull[0..15] for 2*2:", [hex(x) for x in full])
out = fe448_reduce_py(full)
print("out limbs:", [hex(x) for x in out])
print("out value:", fe448_to_big(out))
