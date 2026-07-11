#include "sha512.hpp"
#include <cstdint>
#include <cstring>
#include <cstdio>
#ifdef JP_AVX2
#include <immintrin.h>
#endif
namespace jpssl{
extern void (*sha512_transform_ptr)(uint64_t[8],const uint8_t[128]);
#ifdef JP_AVX2
static const uint64_t K[80]={
0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817};
static inline __m128i sigma0_sse(__m128i x){
    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_srli_epi64(x,1),_mm_slli_epi64(x,63)),_mm_xor_si128(_mm_srli_epi64(x,8),_mm_slli_epi64(x,56))),_mm_srli_epi64(x,7));
}
static inline __m128i sigma1_sse(__m128i x){
    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_srli_epi64(x,19),_mm_slli_epi64(x,45)),_mm_xor_si128(_mm_srli_epi64(x,61),_mm_slli_epi64(x,3))),_mm_srli_epi64(x,6));
}
void sha512_transform_opt(uint64_t h[8],const uint8_t data[128]){
    uint64_t w[80];
    const __m128i bswap=_mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7);
    for(int i=0;i<16;i+=2){__m128i v=_mm_loadu_si128((const __m128i*)(data+i*8));v=_mm_shuffle_epi8(v,bswap);_mm_storeu_si128((__m128i*)(w+i),v);}
    for(int i=16;i<80;i+=2){
        __m128i w2=_mm_loadu_si128((const __m128i*)(w+i-2)),w7=_mm_loadu_si128((const __m128i*)(w+i-7)),w15=_mm_loadu_si128((const __m128i*)(w+i-15)),w16=_mm_loadu_si128((const __m128i*)(w+i-16));
        __m128i r=_mm_add_epi64(_mm_add_epi64(sigma1_sse(w2),w7),_mm_add_epi64(sigma0_sse(w15),w16));
        _mm_storeu_si128((__m128i*)(w+i),r);
    }
    uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<80;++i){
        uint64_t t1=hh+((((e>>14)|(e<<50))^((e>>18)|(e<<46))^((e>>41)|(e<<23)))+((e&f)^(~e&g))+K[i]+w[i]);
        uint64_t t2=((((a>>28)|(a<<36))^((a>>34)|(a<<30))^((a>>39)|(a<<25)))+((a&b)^(a&c)^(b&c)));
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
static bool init_opt(){
    sha512_transform_ptr=sha512_transform_opt;
    return true;
}
static bool _init=init_opt();
#endif // JP_AVX2
}
