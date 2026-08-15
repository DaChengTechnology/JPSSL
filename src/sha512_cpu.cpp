#include "sha512.hpp"
#include <cstring>
namespace jpssl{
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
static inline uint64_t ROR(uint64_t x,int n){return(x>>n)|(x<<(64-n));}
void sha512_transform_cpu(uint64_t h[8],const uint8_t data[128]){
    uint64_t w[80];
    for(int i=0;i<16;++i)w[i]=((uint64_t)data[i*8]<<56)|((uint64_t)data[i*8+1]<<48)|((uint64_t)data[i*8+2]<<40)|((uint64_t)data[i*8+3]<<32)|((uint64_t)data[i*8+4]<<24)|((uint64_t)data[i*8+5]<<16)|((uint64_t)data[i*8+6]<<8)|(uint64_t)data[i*8+7];
    for(int i=16;i<80;++i)w[i]=(ROR(w[i-2],19)^ROR(w[i-2],61)^(w[i-2]>>6))+w[i-7]+(ROR(w[i-15],1)^ROR(w[i-15],8)^(w[i-15]>>7))+w[i-16];
    uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<80;++i){uint64_t t1=hh+(ROR(e,14)^ROR(e,18)^ROR(e,41))+((e&f)^(~e&g))+K[i]+w[i],t2=(ROR(a,28)^ROR(a,34)^ROR(a,39))+((a&b)^(a&c)^(b&c));hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
void (*sha512_transform_ptr)(uint64_t[8],const uint8_t[128])=nullptr;
static bool init_cpu(){if(!sha512_transform_ptr)sha512_transform_ptr=sha512_transform_cpu;return true;}
static bool _cpu_init=init_cpu();
void sha512_init(sha512_ctx*ctx){ctx->h[0]=0x6a09e667f3bcc908;ctx->h[1]=0xbb67ae8584caa73b;ctx->h[2]=0x3c6ef372fe94f82b;ctx->h[3]=0xa54ff53a5f1d36f1;ctx->h[4]=0x510e527fade682d1;ctx->h[5]=0x9b05688c2b3e6c1f;ctx->h[6]=0x1f83d9abfb41bd6b;ctx->h[7]=0x5be0cd19137e2179;ctx->len=0;ctx->buf_len=0;ctx->is_384=false;}
void sha384_init(sha512_ctx*ctx){ctx->h[0]=0xcbbb9d5dc1059ed8;ctx->h[1]=0x629a292a367cd507;ctx->h[2]=0x9159015a3070dd17;ctx->h[3]=0x152fecd8f70e5939;ctx->h[4]=0x67332667ffc00b31;ctx->h[5]=0x8eb44a8768581511;ctx->h[6]=0xdb0c2e0d64f98fa7;ctx->h[7]=0x47b5481dbefa4fa4;ctx->len=0;ctx->buf_len=0;ctx->is_384=true;}
void sha512_update(sha512_ctx*ctx,const uint8_t*data,size_t len){
    if (len == 0) return;
    ctx->len+=len;
    if(ctx->buf_len+len<128){memcpy(ctx->buf+ctx->buf_len,data,len);ctx->buf_len+=len;return;}
    size_t off=128-ctx->buf_len;
    memcpy(ctx->buf+ctx->buf_len,data,off);sha512_transform_ptr(ctx->h,ctx->buf);
    while(off+128<=len){sha512_transform_ptr(ctx->h,data+off);off+=128;}
    ctx->buf_len=len-off;memcpy(ctx->buf,data+off,ctx->buf_len);
}
void sha512_final(sha512_ctx*ctx,uint8_t*digest){
    uint64_t bits=ctx->len*8;
    ctx->buf[ctx->buf_len++]=0x80;
    if(ctx->buf_len>112){while(ctx->buf_len<128)ctx->buf[ctx->buf_len++]=0;sha512_transform_ptr(ctx->h,ctx->buf);ctx->buf_len=0;}
    while(ctx->buf_len<112)ctx->buf[ctx->buf_len++]=0;
    for(int i=7;i>=0;--i)ctx->buf[ctx->buf_len++]=0;
    for(int i=7;i>=0;--i)ctx->buf[ctx->buf_len++]=(uint8_t)(bits>>(i*8));
    sha512_transform_ptr(ctx->h,ctx->buf);
    size_t out=ctx->is_384?48:64;
    for(size_t i=0;i<out;++i)digest[i]=(uint8_t)(ctx->h[i/8]>>(56-(i%8)*8));
}
}
