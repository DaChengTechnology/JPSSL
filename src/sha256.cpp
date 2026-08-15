#include "sha256.hpp"
#include "cpu_features.hpp"
#include <cstring>
namespace jpssl {

static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static inline uint32_t ROR(uint32_t x,int n){return(x>>n)|(x<<(32-n));}
#define S0(x) (ROR(x,2)^ROR(x,13)^ROR(x,22))
#define S1(x) (ROR(x,6)^ROR(x,11)^ROR(x,25))
#define s0(x) (ROR(x,7)^ROR(x,18)^(x>>3))
#define s1(x) (ROR(x,17)^ROR(x,19)^(x>>10))
#define CH(x,y,z) ((x&y)^(~x&z))
#define MAJ(x,y,z) ((x&y)^(x&z)^(y&z))

static void sha256_transform_scalar(uint32_t h[8],const uint8_t data[64]){
    uint32_t w[64];
    for(int i=0;i<16;++i)w[i]=((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|((uint32_t)data[i*4+2]<<8)|data[i*4+3];
    for(int i=16;i<64;++i)w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;++i){
        uint32_t t1=hh+S1(e)+CH(e,f,g)+K[i]+w[i],t2=S0(a)+MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

/// 分派：ARMv8 SHA-256 扩展可用时走 NEON（JP_NEON 构建）
static void sha256_transform(uint32_t h[8],const uint8_t data[64]){
#if defined(JP_NEON) && defined(__aarch64__)
    if (cpu_has_arm_sha2()) {
        sha256_transform_neon(h, data);
        return;
    }
#endif
    sha256_transform_scalar(h, data);
}

void sha256_init(sha256_ctx*ctx){ctx->h[0]=0x6a09e667;ctx->h[1]=0xbb67ae85;ctx->h[2]=0x3c6ef372;ctx->h[3]=0xa54ff53a;ctx->h[4]=0x510e527f;ctx->h[5]=0x9b05688c;ctx->h[6]=0x1f83d9ab;ctx->h[7]=0x5be0cd19;ctx->len=0;ctx->buf_len=0;}
void sha256_update(sha256_ctx*ctx,const uint8_t*data,size_t len){
    if (len == 0) return;
    ctx->len+=len;
    if(ctx->buf_len+len<64){memcpy(ctx->buf+ctx->buf_len,data,len);ctx->buf_len+=len;return;}
    size_t off=64-ctx->buf_len;
    memcpy(ctx->buf+ctx->buf_len,data,off);sha256_transform(ctx->h,ctx->buf);
    while(off+64<=len){sha256_transform(ctx->h,data+off);off+=64;}
    ctx->buf_len=len-off;memcpy(ctx->buf,data+off,ctx->buf_len);
}
void sha256_final(sha256_ctx*ctx,uint8_t digest[32]){
    uint64_t bits=ctx->len*8;
    ctx->buf[ctx->buf_len++]=0x80;
    if(ctx->buf_len>56){while(ctx->buf_len<64)ctx->buf[ctx->buf_len++]=0;sha256_transform(ctx->h,ctx->buf);ctx->buf_len=0;}
    while(ctx->buf_len<56)ctx->buf[ctx->buf_len++]=0;
    for(int i=7;i>=0;--i)ctx->buf[ctx->buf_len++]=(uint8_t)(bits>>(i*8));
    sha256_transform(ctx->h,ctx->buf);
    for(int i=0;i<4;++i){digest[i]=(uint8_t)(ctx->h[0]>>(24-i*8));digest[i+4]=(uint8_t)(ctx->h[1]>>(24-i*8));digest[i+8]=(uint8_t)(ctx->h[2]>>(24-i*8));digest[i+12]=(uint8_t)(ctx->h[3]>>(24-i*8));digest[i+16]=(uint8_t)(ctx->h[4]>>(24-i*8));digest[i+20]=(uint8_t)(ctx->h[5]>>(24-i*8));digest[i+24]=(uint8_t)(ctx->h[6]>>(24-i*8));digest[i+28]=(uint8_t)(ctx->h[7]>>(24-i*8));}
}
}
