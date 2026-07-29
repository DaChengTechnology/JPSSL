#include "rsa.hpp"
#include <cstdio>
int main(){using namespace jpssl;
    // 2^448 mod p should be 2^224+1
    // 2^448 as bignum: d[7] = 1<<0... no, 2^448 = bit 448
    rsa_bignum two448; two448.zero(); two448.set_bit(448);
    uint8_t pbe[56]; uint8_t ple[56]; for(int i=0;i<56;++i)ple[i]=0xff; ple[28]=0xfe;
    for(int i=0;i<56;++i)pbe[i]=ple[55-i];
    rsa_bignum pp=rsa_bignum::from_bytes(pbe,56);
    rsa_bignum r; bn_mod(r,two448,pp);
    for(int i=7;i<32;++i)r.d[i]=0;
    uint8_t be[256]; r.to_bytes(be);
    printf("2^448 mod p = "); for(int i=200;i<256;++i)printf("%02x",be[i]);printf("\n");
    // expect 2^224+1: byte 224 is at position 256-32=224 from MSB... LE: byte 28 = 0x01? 
    // 2^224+1 in LE 56 bytes: bytes 0-27 = 0, byte 28 = 0x01? No: 2^224 = bit 224, in 56-byte LE that's byte 28 bit 0.
    // So LE: byte[0]=01, bytes 1-27=0, byte 28=01, rest 0. But that's 2^224+1.
    // In BE (to_bytes): last 56 bytes. 2^224+1 in BE: ...01 followed by 28 zero bytes then 01
    printf("expect LE: 01 00...00 01 00...00\n");
    return 0;
}
