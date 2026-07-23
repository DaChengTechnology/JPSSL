#!/usr/bin/env python3
"""Generate Ed25519 test vectors for debugging jpssl"""
import hashlib
import struct

# Use RFC 8032 Test 1 seed and expected values
seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])

# Step 1: SHA-512(seed) and clamp
h = bytearray(hashlib.sha512(seed).digest())
h[0] &= 248
h[31] &= 127
h[31] |= 64
s = bytes(h[:32])  # secret scalar (clamped)
prefix = bytes(h[32:])  # 32-byte prefix

# Step 2: r = SHA-512(prefix || msg) mod l
msg = b''
r_hash = hashlib.sha512(prefix + msg).digest()
l = 2**252 + 27742317777372353535851937790883648493
r_int = int.from_bytes(r_hash, 'little') % l

# Step 3: R = r * B
# For now, use known expected R
R_expected = bytes([0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
                    0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
                    0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
                    0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55])

# Step 4: k = SHA-512(R || A || msg) mod l
A = bytes([0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
           0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
           0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
           0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a])
k_hash = hashlib.sha512(R_expected + A + msg).digest()
k_int = int.from_bytes(k_hash, 'little') % l

# Step 5: S = (r + k * s) mod l
s_int = int.from_bytes(s, 'little')
S_int = (r_int + k_int * s_int) % l

print("=== Test Vectors for jpssl Debugging ===")
print(f"s (clamped scalar): {s.hex()}")
print(f"prefix:              {prefix.hex()}")
print(f"SHA-512(prefix||''):{r_hash.hex()}")
print(f"r (mod l):           {r_int.to_bytes(32,'little').hex()}")
print(f"R (expected):        {R_expected.hex()}")
print(f"SHA-512(R||A||''):  {k_hash.hex()}")
print(f"k (mod l):           {k_int.to_bytes(32,'little').hex()}")
print(f"k (decimal):         {k_int}")
print(f"S (expected):        {S_int.to_bytes(32,'little').hex()}")
print()

# Print as C array initializer
def c_array(name, data):
    hex_str = ','.join(f'0x{b:02x}' for b in data)
    print(f'static const uint8_t {name}[{len(data)}] = {{{hex_str}}};')

c_array("RFC_SEED", seed)
c_array("RFC_S", s)
c_array("RFC_PREFIX", prefix)
c_array("RFC_R", R_expected)
c_array("RFC_A", A)
print()

# Now let's compute what jpssl produces for k*A and S*B
# using simple Python point arithmetic on Ed25519
p = 2**255 - 19
d_val = (-121665 * pow(121666, -1, p)) % p

def point_add(P, Q):
    """Affine point addition on twisted Edwards curve -x^2+y^2=1+d*x^2*y^2"""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    t_val = d_val * x1 * x2 % p * y1 % p * y2 % p
    x3 = (x1 * y2 + x2 * y1) % p * pow(1 + t_val, -1, p) % p
    y3 = (y1 * y2 + x1 * x2) % p * pow(1 - t_val, -1, p) % p
    return (x3, y3)

def scalar_mult(k, P):
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

# Compute basepoint B from RFC 8032
By = 4 * pow(5, -1, p) % p
Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636 % p
B = (Bx, By)

# Compute k*A (affine)
A_point = int.from_bytes(A, 'little')  # A is y only, with sign bit
Ay = A_point & ((1 << 255) - 1)  # clear sign bit
# Need to recover Ax from Ay
Ay2 = Ay * Ay % p
u = (Ay2 - 1) % p
v = (1 + d_val * Ay2) % p
Ax2 = u * pow(v, -1, p) % p
Ax = pow(Ax2, (p+3)//8, p)
if Ax * Ax % p != Ax2:
    Ax = Ax * pow(2, (p-1)//4, p) % p
if (Ax & 1) != ((A_point >> 255) & 1):
    Ax = p - Ax

print(f"Ax = {Ax}")
print(f"Ay = {Ay}")

kA = scalar_mult(k_int, (Ax, Ay))
print(f"k*A = ({kA[0]}, {kA[1]})")
kA_y_bytes = kA[1].to_bytes(32, 'little')
kA_result = int.from_bytes(kA_y_bytes, 'little')
if kA[0] & 1:
    kA_result |= (1 << 255)
print(f"k*A encoded: {kA_result.to_bytes(32,'little').hex()}")
print(f"jpssl k*A:   56c2f1df06ddab893cbf48e5de7500704b22f20e07ca1a362e3364766d4f7e06")

# Compute S*B
SB = scalar_mult(S_int, B)
print(f"S*B = ({SB[0]}, {SB[1]})")
SB_y_bytes = SB[1].to_bytes(32, 'little')
SB_result = int.from_bytes(SB_y_bytes, 'little')
if SB[0] & 1:
    SB_result |= (1 << 255)
print(f"S*B encoded: {SB_result.to_bytes(32,'little').hex()}")
print(f"jpssl S*B:   fe6c8a99af92f9e5f16dc1c5366f9c2cd9c5e890f27544e542cfa5d6dddd9427")

# Compute S*B - k*A (which should equal R)
neg_kA = ((p - kA[0]) % p, kA[1])
SB_minus_kA = point_add(SB, neg_kA)
print(f"\nS*B - k*A (should equal R):")
print(f"  x = {SB_minus_kA[0]}")
print(f"  y = {SB_minus_kA[1]}")
res_y = SB_minus_kA[1].to_bytes(32, 'little')
res = int.from_bytes(res_y, 'little')
if SB_minus_kA[0] & 1:
    res |= (1 << 255)
print(f"  encoded: {res.to_bytes(32,'little').hex()}")
print(f"  R:       {R_expected.hex()}")
print(f"  match: {res.to_bytes(32,'little').hex() == R_expected.hex()}")
