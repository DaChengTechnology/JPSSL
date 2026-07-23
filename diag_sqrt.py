#!/usr/bin/env python3
"""Verify sqrt algorithm for RFC 8032 pubkey."""
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p

pub_hex = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
y = int.from_bytes(bytes.fromhex(pub_hex), 'little')
y2 = pow(y, 2, p)
u = (y2 - 1) % p
v = (1 + d * y2) % p

print(f'y = {y}')
print(f'y^2 = {y2}')
print(f'y^2 hex = {y2.to_bytes(32, "little").hex()}')
print(f'u = y^2-1 = {u}')
print(f'v = 1+d*y^2 = {v}')

ratio = u * pow(v, -1, p) % p
print(f'u/v = {ratio}')

qr = pow(ratio, (p-1)//2, p)
print(f'Is QR: {qr == 1}')

r = pow(ratio, (p+3)//8, p)
if pow(r, 2, p) == ratio:
    print(f'Direct sqrt: {r}')
else:
    sqrt_m1 = pow(2, (p-1)//4, p)
    r = r * sqrt_m1 % p
    if pow(r, 2, p) == ratio:
        print(f'Sqrt with sqrt(-1): {r}')
    else:
        print('No sqrt!')

# fe_sqrt_ratio formula
uv3 = u * pow(v, 3, p) % p
uv7 = u * pow(v, 7, p) % p
r2 = uv3 * pow(uv7, (p-5)//8, p) % p
print(f'\nfe_sqrt_ratio: {r2}')
if pow(r2, 2, p) * v % p == u:
    print('CORRECT!')
else:
    r2 = r2 * pow(2, (p-1)//4, p) % p
    if pow(r2, 2, p) * v % p == u:
        print('Correct with sqrt(-1)!')
    else:
        print('FAILED!')

# Now check the C++ output:
# y^2: cc74f50f73b58c471c345f4746bf62670c5d4b7856c1b69a6314db4732540d3f
print(f"\nC++ y^2 output was: cc74f50f73b58c471c345f4746bf62670c5d4b7856c1b69a6314db4732540d3f")
print(f"Python y^2 output:  {y2.to_bytes(32, 'little').hex()}")
print(f"Match: {y2.to_bytes(32, 'little').hex() == 'cc74f50f73b58c471c345f4746bf62670c5d4b7856c1b69a6314db4732540d3f'}")
