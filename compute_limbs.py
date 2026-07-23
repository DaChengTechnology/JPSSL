#!/usr/bin/env python3
"""验证 sc_reduce：用 Python 计算 k*s+r mod L，与 C++ 的 sc_reduce 结果对比"""
L = 2**252 + 27742317777372353535851937790883648493

k = [0x8a3e7e162e525404, 0xf8d8256131ec2c13, 0x290504e7c600df6c, 0x86eabc8e4c96193d]
s = [0xa5200f90064de94f, 0xfdfe2768d980c0a3, 0x427a2ef1c00a013c, 0x307c83864f2833cb]
r_limbs = [0xc58f75ac58a07404, 0x2249107418afc2ed, 0xf244787db4af5368, 0xf38907308c893dea]

# 计算 k*s
def mul_limbs(a, b):
    result = [0] * 8
    for i in range(4):
        carry = 0
        for j in range(4):
            prod = a[i] * b[j] + result[i+j] + carry
            result[i+j] = prod & 0xFFFFFFFFFFFFFFFF
            carry = prod >> 64
        idx = i + 4
        while carry and idx < 8:
            prod = result[idx] + carry
            result[idx] = prod & 0xFFFFFFFFFFFFFFFF
            carry = prod >> 64
            idx += 1
    return result

ks = mul_limbs(k, s)

# 加 r
carry = 0
for i in range(8):
    val = ks[i] + (r_limbs[i] if i < 4 else 0) + carry
    ks[i] = val & 0xFFFFFFFFFFFFFFFF
    carry = val >> 64

# ks + r 作为 512 位整数
ksr_int = 0
for i in range(8):
    ksr_int += ks[i] << (64 * i)

result = ksr_int % L
print(f"ksr_int = {ksr_int:#x}")
print(f"ksr_int mod L = {result:#x}")
print(f"Expected S = 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
print(f"Match: {result.to_bytes(32, 'little').hex() == '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'}")

# C++ 输出：k*s+r
# buf (before reduce): 4005b4efa8e917b7b5c3664afeb64f9be8fe8fff79a7b948fc7053d61a4aedeaf082a11088d6d1a99a09dca577e1ac93ecfe6c74e96167d945615cea5ea28d19
# 解码为 limb
buf_before = bytes.fromhex("4005b4efa8e917b7b5c3664afeb64f9be8fe8fff79a7b948fc7053d61a4aedeaf082a11088d6d1a99a09dca577e1ac93ecfe6c74e96167d945615cea5ea28d19")
cpp_ksr = []
for i in range(8):
    cpp_ksr.append(int.from_bytes(buf_before[i*8:(i+1)*8], 'little'))
print(f"\nC++ ksr limbs: {[hex(x) for x in cpp_ksr]}")

# Python ksr limbs
print(f"Py  ksr limbs: {[hex(x) for x in ks]}")
print(f"Match: {cpp_ksr == ks}")

# C++ sc_reduce 结果
cpp_reduced_hex = "697713a5484c2c7556a1cf2a25b29709a3bad3d621786a29608b8be4979a1909"
print(f"\nC++ reduced: {cpp_reduced_hex}")
print(f"Python reduced: {result.to_bytes(32, 'little').hex()}")
