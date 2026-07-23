#!/usr/bin/env python3
"""Verify jpssl fe constants and operations"""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
d2 = (2 * d) % p

print(f"p = 2^255 - 19 = {p}")
print(f"d = -121665/121666 = {d}")
print(f"d2 = 2*d = {d2}")

d_bytes = d.to_bytes(32, 'little')
d2_bytes = d2.to_bytes(32, 'little')

print(f"d bytes:  {[b for b in d_bytes]}")
print(f"d2 bytes: {[b for b in d2_bytes]}")

# jpssl d bytes: {163,120,89,19,202,77,235,117,171,216,65,65,77,10,112,0,152,232,121,119,121,64,199,140,115,254,111,43,238,108,3,82}
jpssl_d = [163,120,89,19,202,77,235,117,171,216,65,65,77,10,112,0,152,232,121,119,121,64,199,140,115,254,111,43,238,108,3,82]
print(f"jpssl d  : {jpssl_d}")
print(f"d match: {list(d_bytes) == jpssl_d}")

# jpssl d2 bytes: {89,241,178,38,148,155,214,235,86,177,131,130,154,20,224,0,48,209,243,238,242,128,142,25,231,252,223,86,220,217,6,36}
jpssl_d2 = [89,241,178,38,148,155,214,235,86,177,131,130,154,20,224,0,48,209,243,238,242,128,142,25,231,252,223,86,220,217,6,36]
print(f"jpssl d2 : {jpssl_d2}")
print(f"d2 match: {list(d2_bytes) == jpssl_d2}")

# Bx and By
Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960

print(f"\nBx = {Bx}")
print(f"By = {By}")
Bx_bytes = Bx.to_bytes(32, 'little')
By_bytes = By.to_bytes(32, 'little')
print(f"Bx bytes: {[b for b in Bx_bytes]}")
print(f"By bytes: {[b for b in By_bytes]}")

# jpssl Bx: {26,213,37,143,96,45,86,201,178,167,37,149,96,199,44,105,92,220,214,253,49,226,164,192,254,83,110,205,211,54,105,33}
jpssl_Bx = [26,213,37,143,96,45,86,201,178,167,37,149,96,199,44,105,92,220,214,253,49,226,164,192,254,83,110,205,211,54,105,33]
print(f"Bx match: {list(Bx_bytes) == jpssl_Bx}")

jpssl_By = [88,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102]
print(f"By match: {list(By_bytes) == jpssl_By}")

# Now test: what does fe_frombytes + fe_mul give for Bx * By?
# Simulate fe_impl::fe_frombytes
def load_4(b, offset):
    return b[offset] | (b[offset+1] << 8) | (b[offset+2] << 16) | (b[offset+3] << 24)

def load_3(b, offset):
    return b[offset] | (b[offset+1] << 8) | (b[offset+2] << 16)

def fe_frombytes(s):
    """Return 10 limbs as Python integers (not reduced to small radix)"""
    h0 = load_4(s, 0)
    h1 = load_3(s, 4) << 6
    h2 = load_3(s, 7) << 5
    h3 = load_3(s, 10) << 3
    h4 = load_3(s, 13) << 2
    h5 = load_4(s, 16)
    h6 = load_3(s, 20) << 7
    h7 = load_3(s, 23) << 5
    h8 = load_3(s, 26) << 4
    h9 = (load_3(s, 29) & 0x7fffff) << 2
    # Two-pass carry
    for _ in range(2):
        c = h0 >> 26; h1 += c; h0 -= c << 26
        c = h1 >> 25; h2 += c; h1 -= c << 25
        c = h2 >> 26; h3 += c; h2 -= c << 26
        c = h3 >> 25; h4 += c; h3 -= c << 25
        c = h4 >> 26; h5 += c; h4 -= c << 26
        c = h5 >> 25; h6 += c; h5 -= c << 25
        c = h6 >> 26; h7 += c; h6 -= c << 26
        c = h7 >> 25; h8 += c; h7 -= c << 25
        c = h8 >> 26; h9 += c; h8 -= c << 26
        c = h9 >> 25; h0 += c * 19; h9 -= c << 25
    return [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9]

def fe_tobytes(h):
    """Convert 10 limbs back to 32 bytes"""
    h = list(h)
    q = (19 * h[9] + (1 << 24)) >> 25
    q = (h[0] + q) >> 26
    q = (h[1] + q) >> 25
    q = (h[2] + q) >> 26
    q = (h[3] + q) >> 25
    q = (h[4] + q) >> 26
    q = (h[5] + q) >> 25
    q = (h[6] + q) >> 26
    q = (h[7] + q) >> 25
    q = (h[8] + q) >> 26
    q = (h[9] + q) >> 25
    h[0] += 19 * q
    h[1] += h[0] >> 26; h[0] &= 0x3ffffff
    h[2] += h[1] >> 25; h[1] &= 0x1ffffff
    h[3] += h[2] >> 26; h[2] &= 0x3ffffff
    h[4] += h[3] >> 25; h[3] &= 0x1ffffff
    h[5] += h[4] >> 26; h[4] &= 0x3ffffff
    h[6] += h[5] >> 25; h[5] &= 0x1ffffff
    h[7] += h[6] >> 26; h[6] &= 0x3ffffff
    h[8] += h[7] >> 25; h[7] &= 0x1ffffff
    h[9] += h[8] >> 26; h[8] &= 0x3ffffff
    h[9] &= 0x1ffffff
    s = [0]*32
    s[0] = h[0] & 0xff
    s[1] = (h[0] >> 8) & 0xff
    s[2] = (h[0] >> 16) & 0xff
    s[3] = ((h[0] >> 24) | ((h[1] & 0x3f) << 2)) & 0xff
    s[4] = (h[1] >> 6) & 0xff
    s[5] = (h[1] >> 14) & 0xff
    s[6] = ((h[1] >> 22) | ((h[2] & 0x1f) << 3)) & 0xff
    s[7] = (h[2] >> 5) & 0xff
    s[8] = (h[2] >> 13) & 0xff
    s[9] = ((h[2] >> 21) | ((h[3] & 7) << 5)) & 0xff
    s[10] = (h[3] >> 3) & 0xff
    s[11] = (h[3] >> 11) & 0xff
    s[12] = ((h[3] >> 19) | ((h[4] & 3) << 6)) & 0xff
    s[13] = (h[4] >> 2) & 0xff
    s[14] = (h[4] >> 10) & 0xff
    s[15] = (h[4] >> 18) & 0xff
    s[16] = (h[5] >> 0) & 0xff
    s[17] = (h[5] >> 8) & 0xff
    s[18] = (h[5] >> 16) & 0xff
    s[19] = ((h[5] >> 24) | ((h[6] & 0x7f) << 1)) & 0xff
    s[20] = (h[6] >> 7) & 0xff
    s[21] = (h[6] >> 15) & 0xff
    s[22] = ((h[6] >> 23) | ((h[7] & 0x1f) << 3)) & 0xff
    s[23] = (h[7] >> 5) & 0xff
    s[24] = (h[7] >> 13) & 0xff
    s[25] = ((h[7] >> 21) | ((h[8] & 0xf) << 4)) & 0xff
    s[26] = (h[8] >> 4) & 0xff
    s[27] = (h[8] >> 12) & 0xff
    s[28] = ((h[8] >> 20) | ((h[9] & 3) << 6)) & 0xff
    s[29] = (h[9] >> 2) & 0xff
    s[30] = (h[9] >> 10) & 0xff
    s[31] = (h[9] >> 18) & 0xff
    return bytes(s)

# Test roundtrip
bx_limbs = fe_frombytes(Bx_bytes)
bx_back = fe_tobytes(bx_limbs)
print(f"\nBx roundtrip match: {bx_back == Bx_bytes}")

by_limbs = fe_frombytes(By_bytes)
by_back = fe_tobytes(by_limbs)
print(f"By roundtrip match: {by_back == By_bytes}")

# Now simulate fe_mul exactly as jpssl does it
def jpssl_fe_mul(f, g):
    f0,f1,f2,f3,f4,f5,f6,f7,f8,f9 = f
    g0,g1,g2,g3,g4,g5,g6,g7,g8,g9 = g
    g1_19 = g1 * 19; g2_19 = g2 * 19; g3_19 = g3 * 19; g4_19 = g4 * 19
    g5_19 = g5 * 19; g6_19 = g6 * 19; g7_19 = g7 * 19; g8_19 = g8 * 19; g9_19 = g9 * 19
    
    h0 = f0*g0 + f1*2*g9_19 + f2*g8_19 + f3*2*g7_19 + f4*g6_19 + f5*2*g5_19 + f6*g4_19 + f7*2*g3_19 + f8*g2_19 + f9*2*g1_19
    h1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19 + f5*g6_19 + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19
    h2 = f0*g2 + f1*2*g1 + f2*g0 + f3*2*g9_19 + f4*g8_19 + f5*2*g7_19 + f6*g6_19 + f7*2*g5_19 + f8*g4_19 + f9*2*g3_19
    h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19 + f5*g8_19 + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19
    h4 = f0*g4 + f1*2*g3 + f2*g2 + f3*2*g1 + f4*g0 + f5*2*g9_19 + f6*g8_19 + f7*2*g7_19 + f8*g6_19 + f9*2*g5_19
    h5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0 + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19
    h6 = f0*g6 + f1*2*g5 + f2*g4 + f3*2*g3 + f4*g2 + f5*2*g1 + f6*g0 + f7*2*g9_19 + f8*g8_19 + f9*2*g7_19
    h7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2 + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19
    h8 = f0*g8 + f1*2*g7 + f2*g6 + f3*2*g5 + f4*g4 + f5*2*g3 + f6*g2 + f7*2*g1 + f8*g0 + f9*2*g9_19
    h9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4 + f6*g3 + f7*g2 + f8*g1 + f9*g0
    
    c = (h0 + (1 << 25)) >> 26; h1 += c; h0 -= c << 26
    c = (h4 + (1 << 25)) >> 26; h5 += c; h4 -= c << 26
    c = (h1 + (1 << 24)) >> 25; h2 += c; h1 -= c << 25
    c = (h5 + (1 << 24)) >> 25; h6 += c; h5 -= c << 25
    c = (h2 + (1 << 25)) >> 26; h3 += c; h2 -= c << 26
    c = (h6 + (1 << 25)) >> 26; h7 += c; h6 -= c << 26
    c = (h3 + (1 << 24)) >> 25; h4 += c; h3 -= c << 25
    c = (h7 + (1 << 24)) >> 25; h8 += c; h7 -= c << 25
    c = (h4 + (1 << 25)) >> 26; h5 += c; h4 -= c << 26
    c = (h8 + (1 << 25)) >> 26; h9 += c; h8 -= c << 26
    c = (h9 + (1 << 24)) >> 25; h0 += c * 19; h9 -= c << 25
    c = (h0 + (1 << 25)) >> 26; h1 += c; h0 -= c << 26
    c = (h1 + (1 << 24)) >> 25; h2 += c; h1 -= c << 25
    
    return [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9]

# Test: Bx * By using fe_mul
t_limbs = jpssl_fe_mul(bx_limbs, by_limbs)
t_bytes = fe_tobytes(t_limbs)
T_expected = (Bx * By) % p
T_bytes_expected = T_expected.to_bytes(32, 'little')
print(f"\nBx * By fe_mul encoded: {t_bytes.hex()}")
print(f"Bx * By expected:       {T_bytes_expected.hex()}")
print(f"Match: {t_bytes == T_bytes_expected}")

# Test X^2 via fe_sq
a_limbs = jpssl_fe_mul(bx_limbs, bx_limbs)
a_bytes = fe_tobytes(a_limbs)
A_expected = (Bx * Bx) % p
A_bytes_expected = A_expected.to_bytes(32, 'little')
print(f"\nBx^2 fe_sq encoded: {a_bytes.hex()}")
print(f"Bx^2 expected:       {A_bytes_expected.hex()}")
print(f"Match: {a_bytes == A_bytes_expected}")
