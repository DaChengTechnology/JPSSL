p=2**448-2**224-1
inv2=pow(2,p-2,p)
b=inv2.to_bytes(56,'little')
arr='{' + ','.join('0x%02x'%x for x in b) + '}'
print('inv2 array (56 elements):')
print(arr)
print('count:', len(b))
# verify: 2*inv2 mod p = 1
print('2*inv2 mod p =', (2*inv2)%p)
