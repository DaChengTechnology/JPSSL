p=2**448-2**224-1
inv2=pow(2,p-2,p)
b=inv2.to_bytes(56,'little')
limbs=[int.from_bytes(b[7*i:7*i+7],'little') for i in range(8)]
two=[2,0,0,0,0,0,0,0]
full=[0]*16
for i in range(8):
    for j in range(8):
        full[i+j]+=two[i]*limbs[j]
print('full before reduce:')
for i in range(16): print('  [%d]=%x'%(i,full[i]))
# reduce with 2*hi for m>=4
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
print('full after reduce:')
for i in range(16): print('  [%d]=%x'%(i,full[i]))
M=(1<<56)-1
carry=0
out=[0]*8
for i in range(8):
    c=full[i]+carry
    out[i]=c&M
    carry=c>>56
print('out limbs:', [hex(x) for x in out])
print('carry:', carry)
# direct check: 2*inv2 mod p
print('expected:', (2*inv2)%p)
