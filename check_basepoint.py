#!/usr/bin/env python3
# jpssl Bx bytes from ed25519.cpp line 62
jpssl_bx = bytes([26,213,37,143,96,45,86,201,178,167,37,149,96,199,44,105,92,220,214,253,49,226,164,192,254,83,110,205,211,54,105,33])
jpssl_bx_int = int.from_bytes(jpssl_bx, 'little')

# Correct Bx from RFC
correct_bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
correct_bx_bytes = correct_bx.to_bytes(32, 'little')

print(f'jpssl Bx int:    {jpssl_bx_int}')
print(f'Correct Bx int:  {correct_bx}')
print(f'jpssl Bx bytes:  {[b for b in jpssl_bx]}')
print(f'Correct Bx bytes:{[b for b in correct_bx_bytes]}')
print(f'Match: {jpssl_bx_int == correct_bx}')

# By
jpssl_by = bytes([88,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102])
jpssl_by_int = int.from_bytes(jpssl_by, 'little')
correct_by = 46316835694926478169428394003475163141307993866256225615783033603165251855960
print(f'\njpssl By int:    {jpssl_by_int}')
print(f'Correct By int:  {correct_by}')
print(f'By Match: {jpssl_by_int == correct_by}')

# Check: what value does jpssl Bx correspond to?
p = 2**255 - 19
print(f'\njpssl Bx mod p: {jpssl_bx_int % p}')
d = (-121665 * pow(121666, -1, p)) % p
y2 = pow(correct_by, 2, p)
rhs_x2 = (y2 - 1) * pow(1 + d * y2, -1, p) % p
x_cand = pow(rhs_x2, (p+3)//8, p)
if pow(x_cand, 2, p) != rhs_x2:
    sqrt_m1 = pow(2, (p-1)//4, p)
    x_cand = x_cand * sqrt_m1 % p
print(f'X from curve equation: {x_cand}')
print(f'X bytes: {[b for b in x_cand.to_bytes(32, "little")]}')
print(f'Is this jpssl Bx?: {x_cand == jpssl_bx_int}')
print(f'Is this correct Bx?: {x_cand == correct_bx}')
print(f'jpssl Bx is even: {jpssl_bx_int % 2 == 0}')
print(f'Correct Bx is even: {correct_bx % 2 == 0}')
