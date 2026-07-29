#include "x448.hpp"
#include <cstdio>
int main(){using namespace jpssl;
    uint8_t s[56]={0}; s[55]=0x10;
    uint8_t o[56]; x448_scalar_mult(o,s,nullptr);
    printf("b55_10="); for(int i=0;i<40;++i)printf("%02x",o[i]);printf("\n");
    printf("exp     051cecadd8120a64a9807849a2d263130a90a631\n");
    return 0;
}
