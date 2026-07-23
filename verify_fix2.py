#!/usr/bin/env python3
"""Use cryptography library to get correct Bx and verify everything"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import hashlib

p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
l = 2**252 + 27742317777372353535851937790883648493

# RFC 8032 Test 1
seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])
expected_sig = bytes([0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
                      0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
                      0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
                      0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
                      0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
                      0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
                      0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
                      0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b])

# Get pub key from seed
priv = Ed25519PrivateKey.from_private_bytes(seed)
pub = priv.public_key()
pub_bytes = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
print(f"Pub key: {pub_bytes.hex()}")

# Sign with private key
sig = priv.sign(b'')
print(f"Signature: {sig.hex()}")
print(f"Expected:  {expected_sig.hex()}")
print(f"Sig match: {sig == expected_sig}")

# Verify
pub.verify(sig, b'')
print("OpenSSL verify: PASS")

# Now recover Bx from the curve with By=4/5
By = 4 * pow(5, -1, p) % p
By2 = pow(By, 2, p)

# From twisted Edwards: -x^2 + y^2 = 1 + d*x^2*y^2
# x^2 = (y^2 - 1) / (1 + d*y^2)
num = (By2 - 1) % p
den = (1 + d * By2) % p
x2 = num * pow(den, -1, p) % p
x_cand = pow(x2, (p+3)//8, p)
if pow(x_cand, 2, p) != x2:
    sqrt_m1 = pow(2, (p-1)//4, p)
    x_cand = x_cand * sqrt_m1 % p
assert pow(x_cand, 2, p) == x2

# Choose even root
if x_cand & 1:
    x_cand = p - x_cand
Bx = x_cand

print(f"\nBx = {Bx}")
print(f"Bx bytes (LE): {Bx.to_bytes(32,'little').hex()}")
print(f"By = {By}")
print(f"By bytes (LE): {By.to_bytes(32,'little').hex()}")

# Verify B on twisted Edwards
print(f"B on curve: {(-pow(Bx,2,p)+pow(By,2,p))%p == (1+d*pow(Bx,2,p)*pow(By,2,p))%p}")

# Compare Bx with RFC value
rfc_Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
print(f"Bx == RFC Bx: {Bx == rfc_Bx}")
print(f"RFC Bx: {rfc_Bx}")
print(f"RFC Bx bytes: {rfc_Bx.to_bytes(32,'little').hex()}")

# Also try with different d interpretation
d_pos = (121665 * pow(121666, -1, p)) % p
# For x^2 + y^2 = 1 + d*x^2*y^2 (untwisted)
num_u = (1 - By2) % p
den_u = (1 - d * By2) % p
x2_u = num_u * pow(den_u, -1, p) % p
x_cand_u = pow(x2_u, (p+3)//8, p)
if pow(x_cand_u, 2, p) != x2_u:
    sqrt_m1 = pow(2, (p-1)//4, p)
    x_cand_u = x_cand_u * sqrt_m1 % p
if x_cand_u & 1:
    x_cand_u = p - x_cand_u
print(f"\nUntwisted Bx: {x_cand_u}")
print(f"Untwisted Bx bytes: {x_cand_u.to_bytes(32,'little').hex()}")
print(f"Matches RFC Bx: {x_cand_u == rfc_Bx}")
