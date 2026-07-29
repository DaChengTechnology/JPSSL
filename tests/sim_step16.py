p=2**448-2**224-1
a=2
for i in range(15):
    a=a*a%p
# step 15 value (correct)
print('step15 LE:', ''.join('%02x'%x for x in a.to_bytes(56,'little')))
# Now compute step 16 = step15^2 mod p
# Simulate C++ reduction
# Convert a to 56-bit limbs
b=a.to_bytes(56,'little')
limbs=[int.from_bytes(b[7*i:7*i+7],'little') for i in range(8)]
print('limbs:', [hex(x) for x in limbs])
# schoolbook squaring
full=[0]*16
for i in range(8):
    for j in range(8):
        full[i+j]+=limbs[i]*limbs[j]
print('full[0..15]:')
for i in range(16):
    print('  [%d]=%016x'%(i,full[i]))
# reduce with C++ fold: m<4 -> m,m+4; m>=4 -> 2*hi to m, hi to m-4
while True:
    again=False
    for m in range(8):
        hi=full[8+m]
        if hi!=0:
            if m<4: full[m]+=hi; full[m+4]+=hi
            else: full[m]+=2*hi; full[m-4]+=hi
            full[8+m]=0
            again=True
    if not again: break
print('after fold:')
for i in range(16):
    print('  [%d]=%016x'%(i,full[i]))
M=(1<<56)-1
carry=0
out=[0]*8
for i in range(8):
    c=full[i]+carry
    out[i]=c&M
    carry=c>>56
print('carry:', carry)
print('out limbs:', [hex(x) for x in out])
# tobytes
res_bytes=bytearray()
for i in range(8):
    v=out[i]
    for j in range(7):
        res_bytes.append((v>>(8*j))&0xff)
print('result LE:', ''.join('%02x'%x for x in res_bytes))
# correct
correct=(a*a)%p
print('correct LE:', ''.join('%02x'%x for x in correct.to_bytes(56,'little')))
