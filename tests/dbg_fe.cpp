#include "fe_448.hpp"
#include <cstdio>
using namespace jpssl;
using namespace jpssl::fe448_impl;
int main(){
    uint8_t e[56]={0}; e[55]=0x10; e[0]&=0xfc; e[55]|=0x80;
    fe448 x1,x2,z2,x3,z3,a,b,c,d,da,cb,tt,a24;
    uint8_t u[56]={5};
    fe448_frombytes(x1,u);
    fe448_1(x2);fe448_0(z2);fe448_frombytes(x3,u);fe448_1(z3);
    fe448_0(a24);a24[0]=39081;
    int sw=0;
    for(int i=447;i>=0;--i){
        int bit=(e[i>>3]>>(i&7))&1;
        sw^=bit;
        fe448_cswap(x2,x3,sw);fe448_cswap(z2,z3,sw);
        sw=bit;
        fe448_add(a,x2,z2);fe448_sub(b,x2,z2);fe448_add(c,x3,z3);fe448_sub(d,x3,z3);
        fe448_mul(da,d,a);fe448_mul(cb,c,b);
        fe448_add(x3,da,cb);fe448_sq(x3,x3);fe448_sub(tt,da,cb);fe448_sq(z3,tt);fe448_mul(z3,x1,z3);
        fe448_sq(x2,a);fe448_sq(z2,b);fe448_sub(tt,x2,z2);fe448_copy(a24,x2);fe448_mul(x2,x2,z2);
        fe448_mul_small(z2,tt,39081);fe448_add(z2,z2,a24);fe448_mul(z2,z2,tt);
        if(i>=443&&i<=447){
            uint8_t xb[56],zb[56];fe448_tobytes(xb,x2);fe448_tobytes(zb,z2);
            printf("s%d x2=",i);for(int j=0;j<10;++j)printf("%02x",xb[j]);
            printf(" z2=");for(int j=0;j<10;++j)printf("%02x",zb[j]);printf("\n");
        }
    }
    return 0;
}
