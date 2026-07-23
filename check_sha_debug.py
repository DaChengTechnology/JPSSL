#!/usr/bin/env python3
import hashlib
import subprocess

seed = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
              0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
              0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
              0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])

h = hashlib.sha512(seed).digest()
print('Python SHA-512(seed):', h.hex())

print('Expected (RFC full): 307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f')
print('                     8d4cd145e5e5b9a3b7a1d5e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6')

# Clamp
h2 = bytearray(h)
h2[0] &= 248
h2[31] &= 127
h2[31] |= 64
print('Clamped scalar:     ', bytes(h2[:32]).hex())
print('Expected clamped:   307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f')

# Verify via OpenSSL CLI
result = subprocess.run(['openssl', 'dgst', '-sha512'], input=seed, capture_output=True)
print('OpenSSL SHA-512:   ', result.stdout.decode().strip())

# Now test SHA-512(R || A) for verification
R = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
A = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
kh = hashlib.sha512(R + A).digest()
print('\nSHA-512(R||A):     ', kh.hex())

# k = low 32 bytes of SHA-512(R||A) modulo l
l = 2**252 + 27742317777372353535851937790883648493
k_int = int.from_bytes(kh, 'little') % l
k_bytes = k_int.to_bytes(32, 'little')
print('k = SHA(R||A) mod l:', k_bytes.hex())
print('jpssl k from test:  86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404')
