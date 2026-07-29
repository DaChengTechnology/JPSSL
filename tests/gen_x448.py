import binascii
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives import serialization as S
b1=bytearray(56)
for i in range(7): b1[28+i]=i+1
k1=X448PrivateKey.from_private_bytes(bytes(b1))
print('limb4  =',binascii.hexlify(k1.public_key().public_bytes(S.Encoding.Raw,S.PublicFormat.Raw)).decode()[:40])
b2=bytearray(56)
for i in range(7): b2[28+i]=i+1
for i in range(7): b2[35+i]=i+1
k2=X448PrivateKey.from_private_bytes(bytes(b2))
print('limb45 =',binascii.hexlify(k2.public_key().public_bytes(S.Encoding.Raw,S.PublicFormat.Raw)).decode()[:40])
b3=bytearray(56)
for i in range(28): b3[28+i]=i
k3=X448PrivateKey.from_private_bytes(bytes(b3))
print('limb4_7=',binascii.hexlify(k3.public_key().public_bytes(S.Encoding.Raw,S.PublicFormat.Raw)).decode()[:40])
