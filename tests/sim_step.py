p=2**448-2**224-1
x1=5; x2=1; z2=0; x3=5; z3=1; a24=39081
swap=0
k=0x10<<440  # e[55]=0x10 -> bit 444 set
k = (0x10) << (440)  # bit 444
# clamp
k = k & ~(0x3)  # e[0] &= 0xfc (low 2 bits clear)
k = k | (1<<447)  # e[55] |= 0x80
for i in range(447,-1,-1):
    bit=(k>>i)&1
    swap^=bit
    if swap: x2,x3=x3,x2; z2,z3=z3,z2
    swap=bit
    aa=(x2+z2)%p; bb=(x2-z2)%p; cc=(x3+z3)%p; dd=(x3-z3)%p
    da=dd*aa%p; cb=cc*bb%p
    x3=(da+cb)**2%p; t=(da-cb)%p; z3=x1*t*t%p
    x2=aa*aa%p; z2=bb*bb%p; t=(x2-z2)%p
    save=x2; x2=x2*z2%p; z2=a24*t%p; z2=(z2+save)%p; z2=z2*t%p
    if i in (447,446,445,444,443):
        print('s%d x2=%s z2=%s'%(i,''.join('%02x'%x for x in x2.to_bytes(56,'little'))[:20],''.join('%02x'%x for x in z2.to_bytes(56,'little'))[:20]))
if swap: x2,x3=x3,x2; z2,z3=z3,z2
res=x2*pow(z2,p-2,p)%p
print('result=',''.join('%02x'%x for x in res.to_bytes(56,'little'))[:40])
