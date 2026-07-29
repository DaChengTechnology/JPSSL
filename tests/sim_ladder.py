p=2**448-2**224-1
def x448_debug(k, u):
    x1=u; x2=1; z2=0; x3=u; z3=1; a24=39081
    swap=0
    for i in range(447,-1,-1):
        b=(k>>i)&1
        swap^=b
        if swap: x2,x3=x3,x2; z2,z3=z3,z2
        swap=b
        a=(x2+z2)%p; b_=(x2-z2)%p; c=(x3+z3)%p; d_=(x3-z3)%p
        da=d_*a%p; cb=c*b_%p
        x3=(da+cb)**2%p; t=(da-cb)%p; z3=x1*t*t%p
        x2=a*a%p; z2=b_*b_%p; t=(x2-z2)%p
        aa=x2; x2=x2*z2%p; z2=a24*t%p; z2=(z2+aa)%p; z2=z2*t%p
    if swap: x2,x3=x3,x2; z2,z3=z3,z2
    return x2, z2, x2*pow(z2,p-2,p)%p

x2,z2,res=x448_debug(1<<447, 5)
print('x2=', ''.join('%02x'%x for x in x2.to_bytes(56,'little')))
print('z2=', ''.join('%02x'%x for x in z2.to_bytes(56,'little')))
print('res=', ''.join('%02x'%x for x in res.to_bytes(56,'little')))
