#!/usr/bin/env python3
p=2**255-19
r=0x40c7570f4dd54835b9131184410ed4a0cc93e7d9ad053cbc6d07a62426999502
v=0xe4bb1ba3cf1bfc5cb80430abb6551331555a82d0601ebc115c2b469f9cc81b77
u=0xcb74f50f73b58c471c345f4746bf62670c5d4b7856c1b69a6314db4732540d3f
s=pow(r,2,p)*v%p
print(f's==u: {s==u}')
print(f's hex: {s.to_bytes(32,"little").hex()}')
print(f'u hex: {u.to_bytes(32,"little").hex()}')
