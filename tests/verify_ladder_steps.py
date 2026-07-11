#!/usr/bin/env python3
"""Output intermediate ladder states for first N rounds with RFC test vector"""
p = 2**255 - 19

def x25519_intermediate(scalar_bytes, N=5):
    u = 9
    e = bytearray(scalar_bytes)
    e[0] &= 248; e[31] &= 127; e[31] |= 64
    k = int.from_bytes(e, 'little')
    
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    
    for t in range(254, 254 - N, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        
        A = (x2 + z2) % p
        B = (x2 - z2) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = ((DA + CB) ** 2) % p
        z3 = (x1 * ((DA - CB) ** 2)) % p
        x2 = (A * A * B * B) % p
        E = (A*A - B*B) % p
        z2 = (E * (A*A + 121665 * E)) % p
        
        print(f"Round {254-t}: kt={kt} x2={x2} z2={z2} x3={x3} z3={z3}")
    
    print(f"\nFinal swap: {swap}")

alice_priv = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
x25519_intermediate(alice_priv, 5)
