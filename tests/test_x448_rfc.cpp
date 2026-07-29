#include "x448.hpp"
#include <cstdio>
#include <cstring>
int main(){using namespace jpssl;
    uint8_t sr[56];for(int i=0;i<56;++i)sr[i]=(uint8_t)i;
    uint8_t o[56];x448_scalar_mult(o,sr,nullptr);
    printf("range56=");for(int i=0;i<56;++i)printf("%02x",o[i]);printf("\n");
    printf("expect  3c6fd1d02960e0d9e93308fc65736141c30db307977f81b7b10996e51e53f573e5c86621205ff491209d3b7cd7933428177ba4defae14dc1\n");
    return memcmp(o,(const uint8_t*)"\x3c\x6f\xd1\xd0\x29\x60\xe0\xd9\xe9\x33\x08\xfc\x65\x73\x61\x41\xc3\x0d\xb3\x07\x97\x7f\x81\xb7\xb1\x09\x96\xe5\x1e\x53\xf5\x73\xe5\xc8\x66\x21\x20\x5f\xf4\x91\x20\x9d\x3b\x7c\xd7\x93\x34\x28\x17\x7b\xa4\xde\xfa\xe1\x4d\xc1",56)==0?0:1;
}
