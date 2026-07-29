#!/usr/bin/env python3
"""Pure Python X448 Montgomery ladder for debugging"""
p = 2**448 - 2**224 - 1
a24 = 39081

def cswap(swap, x2, x3):
    if swap:
        return x3, x2
    return x2, x3

def x448(scalar_bytes, u_coord=5):
    s = bytearray(scalar_bytes)
    s[0] &= 0xFC
    s[55] |= 0x80
    k = int.from_bytes(s, 'little')
    
    x1 = u_coord % p
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    
    for t in range(447, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt
        
        A = (x2 + z2) % p
        AA = (A * A) % p
        B = (x2 - z2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = ((DA + CB) * (DA + CB)) % p
        z3 = (x1 * ((DA - CB) * (DA - CB))) % p
        x2 = (AA * BB) % p
        z2 = (E * (AA + a24 * E)) % p
    
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)
    
    result = (x2 * pow(z2, p-2, p)) % p
    return result.to_bytes(56, 'little')

scalar = bytes(range(56))
result = x448(scalar)
print("Python result:", result.hex())
expected = bytes.fromhex("3c6fd1d02960e0d9e93308fc65736141c30db307977f81b7b10996e51e53f573e5c86621205ff491209d3b7cd7933428177ba4defae14dc1")
print("Expected:     ", expected.hex())
print("Match:", result == expected)
