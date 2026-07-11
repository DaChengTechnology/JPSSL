#!/usr/bin/env python3
"""Debug fexpand/fcontract with random input"""
import random; random.seed(42)
orig = bytes([random.randint(0,255) for _ in range(32)])
print('orig:', orig.hex())

s = orig
h = [0]*10
h[0] = s[0] | (s[1]<<8) | (s[2]<<16) | (s[3]<<24)
h[1] = (s[4] | (s[5]<<8) | (s[6]<<16)) << 6
h[2] = (s[7] | (s[8]<<8) | (s[9]<<16)) << 5
h[3] = (s[10] | (s[11]<<8) | (s[12]<<16)) << 3
h[4] = (s[13] | (s[14]<<8) | (s[15]<<16)) << 2
h[5] = s[16] | (s[17]<<8) | (s[18]<<16) | (s[19]<<24)
h[6] = (s[20] | (s[21]<<8) | (s[22]<<16)) << 7
h[7] = (s[23] | (s[24]<<8) | (s[25]<<16)) << 5
h[8] = (s[26] | (s[27]<<8) | (s[28]<<16)) << 4
h[9] = ((s[29] | (s[30]<<8) | (s[31]<<16)) & 0x7fffff) << 2
print('after fexpand:', [x for x in h])

# freduce_coefficients (donna order)
c = (h[9] + (1<<24)) >> 25; h[0] += c * 19; h[9] -= c << 25
c = (h[1] + (1<<24)) >> 25; h[2] += c; h[1] -= c << 25
c = (h[3] + (1<<24)) >> 25; h[4] += c; h[3] -= c << 25
c = (h[5] + (1<<24)) >> 25; h[6] += c; h[5] -= c << 25
c = (h[7] + (1<<24)) >> 25; h[8] += c; h[7] -= c << 25
c = (h[0] + (1<<25)) >> 26; h[1] += c; h[0] -= c << 26
c = (h[2] + (1<<25)) >> 26; h[3] += c; h[2] -= c << 26
c = (h[4] + (1<<25)) >> 26; h[5] += c; h[4] -= c << 26
c = (h[6] + (1<<25)) >> 26; h[7] += c; h[6] -= c << 26
c = (h[8] + (1<<25)) >> 26; h[9] += c; h[8] -= c << 26
print('after reduce:', [x for x in h])

# fcontract (donna style, 2 passes, from high to low, ALL limbs in order)
h2 = h[:]  # copy
for _ in range(2):
    c = (h2[9] + (1<<24)) >> 25; h2[0] += c * 19; h2[9] -= c << 25
    c = (h2[8] + (1<<25)) >> 26; h2[9] += c; h2[8] -= c << 26
    c = (h2[7] + (1<<24)) >> 25; h2[8] += c; h2[7] -= c << 25
    c = (h2[6] + (1<<25)) >> 26; h2[7] += c; h2[6] -= c << 26
    c = (h2[5] + (1<<24)) >> 25; h2[6] += c; h2[5] -= c << 25
    c = (h2[4] + (1<<25)) >> 26; h2[5] += c; h2[4] -= c << 26
    c = (h2[3] + (1<<24)) >> 25; h2[4] += c; h2[3] -= c << 25
    c = (h2[2] + (1<<25)) >> 26; h2[3] += c; h2[2] -= c << 26
    c = (h2[1] + (1<<24)) >> 25; h2[2] += c; h2[1] -= c << 25
    c = (h2[0] + (1<<25)) >> 26; h2[1] += c; h2[0] -= c << 26
print('after fcontract:', [x for x in h2])
neg = any(x < 0 for x in h2)
print('has negative:', neg)

# pack
out = [0]*32
out[0] = h2[0] & 0xFF
out[1] = (h2[0] >> 8) & 0xFF
out[2] = (h2[0] >> 16) & 0xFF
out[3] = ((h2[0] >> 24) | (h2[1] << 2)) & 0xFF
out[4] = (h2[1] >> 6) & 0xFF
out[5] = (h2[1] >> 14) & 0xFF
out[6] = ((h2[1] >> 22) | (h2[2] << 3)) & 0xFF
out[7] = (h2[2] >> 5) & 0xFF
out[8] = (h2[2] >> 13) & 0xFF
out[9] = ((h2[2] >> 21) | (h2[3] << 5)) & 0xFF
out[10] = (h2[3] >> 3) & 0xFF
out[11] = (h2[3] >> 11) & 0xFF
out[12] = ((h2[3] >> 19) | (h2[4] << 7)) & 0xFF
out[13] = (h2[4] >> 1) & 0xFF
out[14] = (h2[4] >> 9) & 0xFF
out[15] = (h2[4] >> 17) & 0xFF
out[16] = ((h2[4] >> 25) | (h2[5] << 6)) & 0xFF
out[17] = (h2[5] >> 2) & 0xFF
out[18] = (h2[5] >> 10) & 0xFF
out[19] = (h2[5] >> 18) & 0xFF
out[20] = ((h2[5] >> 26) | (h2[6] << 4)) & 0xFF
out[21] = (h2[6] >> 4) & 0xFF
out[22] = (h2[6] >> 12) & 0xFF
out[23] = ((h2[6] >> 20) | (h2[7] << 6)) & 0xFF
out[24] = (h2[7] >> 2) & 0xFF
out[25] = (h2[7] >> 10) & 0xFF
out[26] = (h2[7] >> 18) & 0xFF
out[27] = ((h2[7] >> 26) | (h2[8] << 5)) & 0xFF
out[28] = (h2[8] >> 3) & 0xFF
out[29] = (h2[8] >> 11) & 0xFF
out[30] = ((h2[8] >> 19) | (h2[9] << 7)) & 0xFF
out[31] = (h2[9] >> 1) & 0xFF
print('out:', bytes(out).hex())
print('match:', orig.hex() == bytes(out).hex())
