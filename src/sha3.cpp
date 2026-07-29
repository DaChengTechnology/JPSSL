#include "sha3.hpp"
#include <cstring>
namespace jpssl {

static const uint64_t RC[24]={
0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808AULL,0x8000000080008000ULL,
0x000000000000808BULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
0x000000000000008AULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000AULL,
0x000000008000808BULL,0x800000000000008BULL,0x8000000000008089ULL,0x8000000000008003ULL,
0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800AULL,0x800000008000000AULL,
0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};

static const int ROTS[5][5]={
{ 0,36, 3,41,18},{ 1,44,10,45, 2},{62, 6,43,15,61},{28,55,25,21,56},{27,20,39, 8,14}};

static inline uint64_t ROL64(uint64_t x,int n){return(x<<n)|(x>>(64-n));}

static void keccak_f1600(uint64_t s[25]){
    for(int r=0;r<24;++r){
        uint64_t C[5];
        for(int x=0;x<5;++x)C[x]=s[x]^s[x+5]^s[x+10]^s[x+15]^s[x+20];
        uint64_t D[5];
        for(int x=0;x<5;++x)D[x]=C[(x+4)%5]^ROL64(C[(x+1)%5],1);
        for(int y=0;y<5;++y)for(int x=0;x<5;++x)s[x+5*y]^=D[x];
        uint64_t b[25];
        for(int y=0;y<5;++y)for(int x=0;x<5;++x){
            int nx=y,ny=(2*x+3*y)%5;
            uint64_t v=s[x+5*y];
            int rot=ROTS[x][y];
            b[nx+5*ny]=rot?ROL64(v,rot):v;
        }
        for(int y=0;y<5;++y)for(int x=0;x<5;++x){
            int i=x+5*y;
            s[i]=b[i]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
        }
        s[0]^=RC[r];
    }
}

static void keccak_absorb(sha3_ctx*ctx){
    uint8_t*st=(uint8_t*)ctx->state;
    for(size_t i=0;i<ctx->rate_bytes;++i)st[i]^=ctx->buf[i];
    keccak_f1600(ctx->state);
}

void sha3_256_init(sha3_ctx*ctx){
    memset(ctx,0,sizeof(*ctx));
    ctx->rate_bytes=136;ctx->output_len=32;
}
void sha3_384_init(sha3_ctx*ctx){
    memset(ctx,0,sizeof(*ctx));
    ctx->rate_bytes=104;ctx->output_len=48;
}
void sha3_512_init(sha3_ctx*ctx){
    memset(ctx,0,sizeof(*ctx));
    ctx->rate_bytes=72;ctx->output_len=64;
}

void sha3_update(sha3_ctx*ctx,const uint8_t*data,size_t len){
    size_t rate=ctx->rate_bytes;
    if(ctx->buf_len>0){
        size_t space=rate-ctx->buf_len;
        size_t copy=len<space?len:space;
        memcpy(ctx->buf+ctx->buf_len,data,copy);
        ctx->buf_len+=copy;data+=copy;len-=copy;
        if(ctx->buf_len==rate){keccak_absorb(ctx);ctx->buf_len=0;}
    }
    while(len>=rate){
        uint8_t*st=(uint8_t*)ctx->state;
        for(size_t i=0;i<rate;++i)st[i]^=data[i];
        keccak_f1600(ctx->state);
        data+=rate;len-=rate;
    }
    if(len>0){memcpy(ctx->buf,data,len);ctx->buf_len=len;}
}

void sha3_final(sha3_ctx*ctx,uint8_t digest[SHA3_512_DIGEST_SIZE]){
    ctx->buf[ctx->buf_len]=0x06;ctx->buf_len++;
    while(ctx->buf_len<ctx->rate_bytes-1)ctx->buf[ctx->buf_len++]=0;
    ctx->buf[ctx->rate_bytes-1]=0x80;
    uint8_t*st=(uint8_t*)ctx->state;
    for(size_t i=0;i<ctx->rate_bytes;++i)st[i]^=ctx->buf[i];
    keccak_f1600(ctx->state);
    memcpy(digest,st,ctx->output_len);
}

// --- SHAKE XOF (FIPS 202) ---
void shake128_init(sha3_ctx*ctx){
    memset(ctx,0,sizeof(*ctx));
    ctx->rate_bytes=SHAKE128_RATE;
}
void shake256_init(sha3_ctx*ctx){
    memset(ctx,0,sizeof(*ctx));
    ctx->rate_bytes=SHAKE256_RATE;
}
void shake_update(sha3_ctx*ctx,const uint8_t*data,size_t len){
    size_t rate=ctx->rate_bytes;
    if(ctx->buf_len>0){
        size_t space=rate-ctx->buf_len;
        size_t copy=len<space?len:space;
        memcpy(ctx->buf+ctx->buf_len,data,copy);
        ctx->buf_len+=copy;data+=copy;len-=copy;
        if(ctx->buf_len==rate){keccak_absorb(ctx);ctx->buf_len=0;}
    }
    while(len>=rate){
        uint8_t*st=(uint8_t*)ctx->state;
        for(size_t i=0;i<rate;++i)st[i]^=data[i];
        keccak_f1600(ctx->state);
        data+=rate;len-=rate;
    }
    if(len>0){memcpy(ctx->buf,data,len);ctx->buf_len=len;}
}
static void shake_pad_and_permute(sha3_ctx*ctx){
    ctx->buf[ctx->buf_len]=0x1F;
    for(size_t i=ctx->buf_len+1;i<ctx->rate_bytes;++i)ctx->buf[i]=0;
    ctx->buf[ctx->rate_bytes-1]=0x80;
    uint8_t*st=(uint8_t*)ctx->state;
    for(size_t i=0;i<ctx->rate_bytes;++i)st[i]^=ctx->buf[i];
    keccak_f1600(ctx->state);
    ctx->output_len=1;
    ctx->buf_len=0;
    memcpy(ctx->buf,ctx->state,ctx->rate_bytes);
}
void shake_squeeze(sha3_ctx*ctx,uint8_t* out,size_t outlen){
    if(ctx->output_len==0)shake_pad_and_permute(ctx);
    size_t rate=ctx->rate_bytes;
    size_t off=ctx->buf_len;
    while(outlen>0){
        if(off>=rate){
            keccak_f1600(ctx->state);
            memcpy(ctx->buf,ctx->state,rate);
            off=0;
        }
        size_t n=rate-off;n=n<outlen?n:outlen;
        memcpy(out,ctx->buf+off,n);
        out+=n;off+=n;outlen-=n;
    }
    ctx->buf_len=off;
}
void shake128(const uint8_t* in,size_t inlen,uint8_t* out,size_t outlen){
    sha3_ctx ctx;shake128_init(&ctx);
    shake_update(&ctx,in,inlen);
    shake_squeeze(&ctx,out,outlen);
}
void shake256(const uint8_t* in,size_t inlen,uint8_t* out,size_t outlen){
    sha3_ctx ctx;shake256_init(&ctx);
    shake_update(&ctx,in,inlen);
    shake_squeeze(&ctx,out,outlen);
}
}
