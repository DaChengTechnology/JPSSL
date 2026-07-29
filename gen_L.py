#!/usr/bin/env python3
# RFC 8032 §5.2.1: Ed448 group order
# L = 2^446 - 13818066809895115352007386748515426880336692474882178609894552837804553022741537

L = 2**446 - 13818066809895115352007386748515426880336692474882178609894552837804553022741537
print("L =", L)
print("L hex =", hex(L))

le = L.to_bytes(57, 'little')
print("\nL_BYTES (LE 57 bytes):")
# Print as C array
for i in range(0, 57, 16):
    chunk = le[i:i+16]
    hex_vals = ','.join(f'0x{b:02x}' for b in chunk)
    print(f'    {hex_vals},')

# Verify
L_check = int.from_bytes(le, 'little')
print("\nVerification:", L == L_check)

# Also print the subtractor for verification
subtractor = 13818066809895115352007386748515426880336692474882178609894552837804553022741537
print("Subtractor hex:", hex(subtractor))
