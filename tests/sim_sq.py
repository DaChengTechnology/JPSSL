p=2**448-2**224-1
a=2
for i in range(21):
    a=a*a%p
    print('exp[%d]='%(i+1),''.join('%02x'%x for x in a.to_bytes(56,'little')))
