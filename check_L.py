#!/usr/bin/env python3
import hashlib

seed = bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")
print("seed length:", len(seed))

h = hashlib.shake_256(seed).digest(114)
print("h hex:", h.hex())

s = bytearray(h[:57])
s[0] &= 0xFC
s[55] |= 0x80
s[56] = 0x00
print("pruned s hex:", s.hex())

L = 2**446 - 13818066809895115352007386748515426880336692474882178609894552837804553022741537
print("L hex:", hex(L))

s_int = int.from_bytes(s, 'little')
s_mod = s_int % L
s_mod_bytes = s_mod.to_bytes(57, 'little')
print("s mod L hex:", s_mod_bytes.hex())

pub_expected = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
print("Expected pub:", pub_expected)

# The test uses s_hex from the test file
s_hex_test = "2a72e4f27069bb47d33a6cf076099d267a4404329145a6b1b590f42688d0b5f605c036d81eeed17483f9f56615ceee4fa70501a71fc0bb3700"
print("\nTest s_hex:", s_hex_test)
s_test = bytes.fromhex(s_hex_test)
s_test_int = int.from_bytes(s_test, 'little')
print("s_test < L:", s_test_int < L)
print("s_test mod L:", (s_test_int % L).to_bytes(57, 'little').hex())
