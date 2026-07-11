"""Compute correct 10-limb values for Ed25519 constants matching fe_frombytes."""
import struct

p = 2**255 - 19

def to_bytes_32(x):
    """Convert integer to 32-byte little-endian."""
    return x.to_bytes(32, 'little')

def to_signed(x):
    """Convert unsigned 32-bit to signed int32."""
    if x >= 0x80000000:
        return x - 0x100000000
    return x

def from_signed(x):
    """Convert signed int32 to unsigned 32-bit (for display)."""
    return x & 0xFFFFFFFF

def load_3(b):
    return b[0] | (b[1] << 8) | (b[2] << 16)

def load_4(b):
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

def fe_frombytes_py(s):
    """Match jpssl fe_frombytes exactly. Returns signed int32 values."""
    h0 = load_4(s[0:4])
    h1 = load_3(s[4:7]) << 6
    h2 = load_3(s[7:10]) << 5
    h3 = load_3(s[10:13]) << 3
    h4 = load_3(s[13:16]) << 2
    h5 = load_4(s[16:20])
    h6 = load_3(s[20:23]) << 7
    h7 = load_3(s[23:26]) << 5
    h8 = load_3(s[26:29]) << 4
    h9 = (load_3(s[29:32]) & 0x7fffff) << 2

    carry = [0] * 10
    carry[9] = (h9 + (1 << 24)) >> 25
    h0 += carry[9] * 19
    h9 -= carry[9] << 25

    carry[1] = (h1 + (1 << 24)) >> 25
    h2 += carry[1]
    h1 -= carry[1] << 25

    carry[3] = (h3 + (1 << 24)) >> 25
    h4 += carry[3]
    h3 -= carry[3] << 25

    carry[5] = (h5 + (1 << 24)) >> 25
    h6 += carry[5]
    h5 -= carry[5] << 25

    carry[7] = (h7 + (1 << 24)) >> 25
    h8 += carry[7]
    h7 -= carry[7] << 25

    carry[0] = (h0 + (1 << 24)) >> 25
    h1 += carry[0]
    h0 -= carry[0] << 25

    carry[2] = (h2 + (1 << 24)) >> 25
    h3 += carry[2]
    h2 -= carry[2] << 25

    carry[4] = (h4 + (1 << 24)) >> 25
    h5 += carry[4]
    h4 -= carry[4] << 25

    carry[6] = (h6 + (1 << 24)) >> 25
    h7 += carry[6]
    h6 -= carry[6] << 25

    carry[8] = (h8 + (1 << 24)) >> 25
    h9 += carry[8]
    h8 -= carry[8] << 25

    # Truncate to int32
    return [to_signed(int(h0) & 0xFFFFFFFF), to_signed(int(h1) & 0xFFFFFFFF),
            to_signed(int(h2) & 0xFFFFFFFF), to_signed(int(h3) & 0xFFFFFFFF),
            to_signed(int(h4) & 0xFFFFFFFF), to_signed(int(h5) & 0xFFFFFFFF),
            to_signed(int(h6) & 0xFFFFFFFF), to_signed(int(h7) & 0xFFFFFFFF),
            to_signed(int(h8) & 0xFFFFFFFF), to_signed(int(h9) & 0xFFFFFFFF)]

def fe_tobytes_py(h):
    """Match jpssl fe_tobytes exactly. Input should be signed int32 values (as Python ints)."""
    h0, h1, h2, h3, h4, h5, h6, h7, h8, h9 = [int(x) for x in h]

    c = (h9 + (1 << 24)) >> 25
    h0 += c * 19
    h9 -= c << 25

    c = (h1 + (1 << 24)) >> 25
    h2 += c
    h1 -= c << 25

    c = (h3 + (1 << 24)) >> 25
    h4 += c
    h3 -= c << 25

    c = (h5 + (1 << 24)) >> 25
    h6 += c
    h5 -= c << 25

    c = (h7 + (1 << 24)) >> 25
    h8 += c
    h7 -= c << 25

    c = (h0 + (1 << 24)) >> 25
    h1 += c
    h0 -= c << 25

    c = (h2 + (1 << 24)) >> 25
    h3 += c
    h2 -= c << 25

    c = (h4 + (1 << 24)) >> 25
    h5 += c
    h4 -= c << 25

    c = (h6 + (1 << 24)) >> 25
    h7 += c
    h6 -= c << 25

    c = (h8 + (1 << 24)) >> 25
    h9 += c
    h8 -= c << 25

    # Truncate to int32 before packing
    h0 = int(h0) & 0xFFFFFFFF
    h1 = int(h1) & 0xFFFFFFFF
    h2 = int(h2) & 0xFFFFFFFF
    h3 = int(h3) & 0xFFFFFFFF
    h4 = int(h4) & 0xFFFFFFFF
    h5 = int(h5) & 0xFFFFFFFF
    h6 = int(h6) & 0xFFFFFFFF
    h7 = int(h7) & 0xFFFFFFFF
    h8 = int(h8) & 0xFFFFFFFF
    h9 = int(h9) & 0xFFFFFFFF

    s = bytearray(32)
    s[0] = h0 & 0xFF
    s[1] = (h0 >> 8) & 0xFF
    s[2] = (h0 >> 16) & 0xFF
    s[3] = ((h0 >> 24) | (h1 << 2)) & 0xFF
    s[4] = (h1 >> 6) & 0xFF
    s[5] = (h1 >> 14) & 0xFF
    s[6] = ((h1 >> 22) | (h2 << 3)) & 0xFF
    s[7] = (h2 >> 5) & 0xFF
    s[8] = (h2 >> 13) & 0xFF
    s[9] = ((h2 >> 21) | (h3 << 5)) & 0xFF
    s[10] = (h3 >> 3) & 0xFF
    s[11] = (h3 >> 11) & 0xFF
    s[12] = ((h3 >> 19) | (h4 << 7)) & 0xFF
    s[13] = (h4 >> 1) & 0xFF
    s[14] = (h4 >> 9) & 0xFF
    s[15] = (h4 >> 17) & 0xFF
    s[16] = ((h4 >> 25) | (h5 << 6)) & 0xFF
    s[17] = (h5 >> 2) & 0xFF
    s[18] = (h5 >> 10) & 0xFF
    s[19] = (h5 >> 18) & 0xFF
    s[20] = ((h5 >> 26) | (h6 << 4)) & 0xFF
    s[21] = (h6 >> 4) & 0xFF
    s[22] = (h6 >> 12) & 0xFF
    s[23] = ((h6 >> 20) | (h7 << 6)) & 0xFF
    s[24] = (h7 >> 2) & 0xFF
    s[25] = (h7 >> 10) & 0xFF
    s[26] = (h7 >> 18) & 0xFF
    s[27] = ((h7 >> 26) | (h8 << 5)) & 0xFF
    s[28] = (h8 >> 3) & 0xFF
    s[29] = (h8 >> 11) & 0xFF
    s[30] = ((h8 >> 19) | (h9 << 7)) & 0xFF
    s[31] = (h9 >> 1) & 0xFF
    return bytes(s)


def limbs_from_int(x):
    """Convert big integer to 10-limb representation via fe_frombytes."""
    b = to_bytes_32(x % p)
    return fe_frombytes_py(b)

def limbs_to_int(h):
    """Convert 10-limb representation back to integer via fe_tobytes."""
    b = fe_tobytes_py(h)
    return int.from_bytes(b, 'little')

# First, verify round-trip consistency
print("=== Self-consistency test ===")
test_vals = [0, 1, p-1, 12345, 2**255 - 20, 2**254 + 123456789]
for tv in test_vals:
    limbs = limbs_from_int(tv)
    back = limbs_to_int(limbs)
    ok = back == tv % p
    print(f"  {tv}: {'OK' if ok else 'FAIL'} (got {back}, expected {tv % p})")
    if not ok:
        diff = (back - tv) % p
        print(f"    diff = {diff}")

print()
print("=== First test: verify reference fe_tobytes matches expected bytes ===")
# RFC 8032: the basepoint y coordinate 46316835... encoded to bytes should match known value
By_correct = 46316835694926478169428394003475163141307993866256225615783033603165251855960
by_bytes = to_bytes_32(By_correct)
print(f"  By bytes: {by_bytes.hex()}")
limbs = fe_frombytes_py(by_bytes)
print(f"  By limbs (signed): {limbs}")
re_bytes = fe_tobytes_py(limbs)
print(f"  By re-encoded bytes: {re_bytes.hex()}")
print(f"  Match: {re_bytes == by_bytes}")

# RFC 8032 Ed25519 basepoint
By_correct = 46316835694926478169428394003475163141307993866256225615783033603165251855960
Bx_correct = 15112221349535891490771889845789546913814871384922459474716389586016139295636

# Curve constant d = -(121665/121666) mod p
d_correct = (-121665 * pow(121666, -1, p)) % p
d2_correct = (2 * d_correct) % p

print("\n=== Correct big integer values ===")
print(f"Bx = {Bx_correct}")
print(f"By = {By_correct}")
print(f"d  = {d_correct}")
print(f"d2 = {d2_correct}")

print("\n=== Correct 10-limb values (signed int32) ===")
Bx_limbs = limbs_from_int(Bx_correct)
By_limbs = limbs_from_int(By_correct)
d_limbs = limbs_from_int(d_correct)
d2_limbs = limbs_from_int(d2_correct)

def fmt_limbs(limbs):
    return '{' + ', '.join(str(l) for l in limbs) + '}'

print(f"Bx_limbs = {fmt_limbs(Bx_limbs)}")
print(f"By_limbs = {fmt_limbs(By_limbs)}")
print(f"d_limbs  = {fmt_limbs(d_limbs)}")
print(f"d2_limbs = {fmt_limbs(d2_limbs)}")

# Verify round-trip
print("\n=== Round-trip verification ===")
for name, limbs, correct_val in [("Bx", Bx_limbs, Bx_correct),
                                   ("By", By_limbs, By_correct),
                                   ("d", d_limbs, d_correct),
                                   ("d2", d2_limbs, d2_correct)]:
    val = limbs_to_int(limbs)
    ok = val == correct_val % p
    print(f"  {name}: round-trip {'OK' if ok else 'FAIL'} (got {val}, expected {correct_val % p})")

# Also dump what the CURRENT (wrong) limbs encode to
print("\n=== Current (wrong) constants decode ===")
current_Bx_s = [34997118, 29965807, 60919191, 28512395, 7995448, 17969413, 6665989, 9520956, 20765945, 8758491]
current_Bx = [to_signed(x) for x in current_Bx_s]
current_By_s = [22364875, 2230290, 13421773, 20132659, 26843545, 6710886, 53687091, 13421772, 40265318, 26843545]
current_By = [to_signed(x) for x in current_By_s]
current_d_s = [56195235, 13857412, 51736253, 6949390, 114729, 24766616, 60832955, 30306712, 48412415, 21499315]
current_d = [to_signed(x) for x in current_d_s]
current_d2_s = [45281625, 27714825, 36363642, 13898781, 229458, 15978800, 54557047, 27058993, 29715967, 9444199]
current_d2 = [to_signed(x) for x in current_d2_s]

print(f"  current Bx decodes to: {limbs_to_int(current_Bx)}")
print(f"  correct Bx is:        {Bx_correct}")
print(f"  current By decodes to: {limbs_to_int(current_By)}")
print(f"  correct By is:        {By_correct}")
print(f"  current d decodes to:  {limbs_to_int(current_d)}")
print(f"  correct d is:         {d_correct}")
print(f"  current d2 decodes to: {limbs_to_int(current_d2)}")
print(f"  correct d2 is:        {d2_correct}")
