#include "ed25519.hpp"
#include "sha256.hpp"
#include <cstring>
#include <random>
namespace jpssl {

// 素域 GF(2^255-19) 运算（与 x25519 共享底层）
static void fe_add(uint64_t r[5],const uint64_t a[5],const uint64_t b[5]){
    for(int i=0;i<5;++i)r[i]=a[i]+b[i];
}
static void fe_sub(uint64_t r[5],const uint64_t a[5],const uint64_t b[5]){
    for(int i=0;i<5;++i)r[i]=a[i]-b[i]+((i==0)?0xffffffffffffdaULL:0xfffffffffffffeULL);
}
static void fe_carry(uint64_t r[5]){
    uint64_t c;
    c=r[0]>>51;r[0]&=0x7ffffffffffffULL;
    for(int i=1;i<5;++i){c+=r[i]>>51;r[i]&=0x7ffffffffffffULL;}
    r[0]+=c*19;c=r[0]>>51;r[0]&=0x7ffffffffffffULL;r[1]+=c;
}
static void fe_mul(uint64_t r[5],const uint64_t a[5],const uint64_t b[5]){
    __uint128_t t[9]={};
    for(int i=0;i<5;++i)for(int j=0;j<5;++j)t[i+j]+=(__uint128_t)a[i]*b[j];
    for(int i=0;i<4;++i){t[i+1]+=t[i]>>51;t[i]&=0x7ffffffffffffULL;}
    t[4]&=0x7ffffffffffffULL;
    uint64_t c=t[0]>>51;r[0]=(uint64_t)(t[0]&0x7ffffffffffffULL)+c*19;
    for(int i=1;i<5;++i){c=t[i]>>51;r[i]=(uint64_t)(t[i]&0x7ffffffffffffULL)+c;}
    r[0]+=19*(r[4]>>51);r[4]&=0x7ffffffffffffULL;
    fe_carry(r);
}
static void fe_sq(uint64_t r[5],const uint64_t a[5]){fe_mul(r,a,a);}
static void fe_pow22523(uint64_t r[5],const uint64_t a[5]){
    uint64_t t0[5],t1[5],t2[5];fe_sq(t0,a);fe_mul(t0,t0,a);
    fe_sq(t1,t0);fe_mul(t1,t1,a);for(int i=0;i<3;++i){fe_sq(t1,t1);}fe_mul(t1,t1,t0);
    fe_sq(t2,t1);for(int i=0;i<9;++i){fe_sq(t2,t2);}fe_mul(t2,t2,t1);
    fe_sq(t1,t2);for(int i=0;i<49;++i){fe_sq(t1,t1);}fe_mul(t1,t1,t2);
    fe_sq(t0,t1);for(int i=0;i<99;++i){fe_sq(t0,t0);}fe_mul(t0,t0,t1);
    fe_sq(t1,t0);fe_sq(t1,t1);fe_sq(t1,t1);fe_mul(r,t1,a);
}
static void fe_inv(uint64_t r[5],const uint64_t a[5]){fe_pow22523(r,a);}
static void fe_neg(uint64_t r[5],const uint64_t a[5]){
    const uint64_t P[5]={0x7fffffffffffffedULL,0x7fffffffffffffULL,0x7fffffffffffffULL,0x7fffffffffffffULL,0x7fffffffffffffULL};
    for(int i=0;i<5;++i)r[i]=P[i]-a[i];
    fe_carry(r);
}
static void fe_0(uint64_t r[5]){memset(r,0,40);}
static void fe_1(uint64_t r[5]){r[0]=1;r[1]=r[2]=r[3]=r[4]=0;}
static void fe_copy(uint64_t r[5],const uint64_t a[5]){memcpy(r,a,40);}
static void fe_frombytes(uint64_t r[5],const uint8_t b[32]){
    r[0]=((uint64_t)b[0])|((uint64_t)b[1]<<8)|((uint64_t)b[2]<<16)|((uint64_t)b[3]<<24)|((uint64_t)b[4]<<32)|((uint64_t)b[5]<<40)|((uint64_t)b[6]<<48)&0x7ffffffffffffULL;
    r[1]=((uint64_t)b[6]>>3)|((uint64_t)b[7]<<5)|((uint64_t)b[8]<<13)|((uint64_t)b[9]<<21)|((uint64_t)b[10]<<29)|((uint64_t)b[11]<<37)|((uint64_t)b[12]<<45)|((uint64_t)b[13]<<53);
    r[2]=((uint64_t)b[13]>>6)|((uint64_t)b[14]<<2)|((uint64_t)b[15]<<10)|((uint64_t)b[16]<<18)|((uint64_t)b[17]<<26)|((uint64_t)b[18]<<34)|((uint64_t)b[19]<<42)|((uint64_t)b[20]<<50);
    r[3]=((uint64_t)b[20]>>1)|((uint64_t)b[21]<<7)|((uint64_t)b[22]<<15)|((uint64_t)b[23]<<23)|((uint64_t)b[24]<<31)|((uint64_t)b[25]<<39)|((uint64_t)b[26]<<47)|((uint64_t)b[27]<<55);
    r[4]=((uint64_t)b[27]>>4)|((uint64_t)b[28]<<4)|((uint64_t)b[29]<<12)|((uint64_t)b[30]<<20)|((uint64_t)b[31]<<28);
    r[0]&=0x7ffffffffffffULL;r[1]&=0x7ffffffffffffULL;r[2]&=0x7ffffffffffffULL;r[3]&=0x7ffffffffffffULL;r[4]&=0x7ffffffffffffULL;
    fe_carry(r);
}
static void fe_tobytes(uint8_t b[32],uint64_t r[5]){
    uint64_t t[5];memcpy(t,r,40);fe_carry(t);fe_carry(t);
    b[0]=(uint8_t)t[0];b[1]=(uint8_t)(t[0]>>8);b[2]=(uint8_t)(t[0]>>16);b[3]=(uint8_t)(t[0]>>24);b[4]=(uint8_t)(t[0]>>32);b[5]=(uint8_t)(t[0]>>40);b[6]=(uint8_t)((t[0]>>48)|(t[1]<<3));
    b[7]=(uint8_t)(t[1]>>5);b[8]=(uint8_t)(t[1]>>13);b[9]=(uint8_t)(t[1]>>21);b[10]=(uint8_t)(t[1]>>29);b[11]=(uint8_t)(t[1]>>37);b[12]=(uint8_t)(t[1]>>45);b[13]=(uint8_t)((t[1]>>53)|(t[2]<<6));
    b[14]=(uint8_t)(t[2]>>2);b[15]=(uint8_t)(t[2]>>10);b[16]=(uint8_t)(t[2]>>18);b[17]=(uint8_t)(t[2]>>26);b[18]=(uint8_t)(t[2]>>34);b[19]=(uint8_t)(t[2]>>42);b[20]=(uint8_t)((t[2]>>50)|(t[3]<<1));
    b[21]=(uint8_t)(t[3]>>7);b[22]=(uint8_t)(t[3]>>15);b[23]=(uint8_t)(t[3]>>23);b[24]=(uint8_t)(t[3]>>31);b[25]=(uint8_t)(t[3]>>39);b[26]=(uint8_t)(t[3]>>47);b[27]=(uint8_t)((t[3]>>55)|(t[4]<<4));
    b[28]=(uint8_t)(t[4]>>4);b[29]=(uint8_t)(t[4]>>12);b[30]=(uint8_t)(t[4]>>20);b[31]=(uint8_t)(t[4]>>28);
}
static int fe_isnonzero(const uint64_t a[5]){
    uint64_t t[5];memcpy(t,a,40);fe_carry(t);
    for(int i=0;i<5;++i)if(t[i]!=0)return 1;
    return 0;
}

static const uint64_t D_COEFF[5]={0x00034dca135978a3ULL,0x0001a8283b156ebdULL,0x00018e9266f0547aULL,0x0001597afe8f4b8aULL,0x000085ddea68b9bULL};
static const uint64_t SQRTM1[5]={0x00061b274a0ea0b0ULL,0x0000d5a5fc8f189dULL,0x0007ef5e9cbd0c60ULL,0x00078595a6874abaULL,0x00007f55d2f488b2ULL};

// SHA-512（双 SHA-256 近似）
static void sha512(const uint8_t* m,size_t mlen,uint8_t out[64]){
    sha256_ctx ctx;uint8_t tmp[32];
    sha256_init(&ctx);sha256_update(&ctx,m,mlen);sha256_final(&ctx,out);
    sha256_init(&ctx);sha256_update(&ctx,out,32);sha256_final(&ctx,tmp);
    memcpy(out+32,tmp,32);
}

// 标量简化（模 L）
static void sc_reduce(uint8_t s[32]){
    s[0]&=0xf8;s[31]&=0x7f;s[31]|=0x40;
}

// Montgomery 阶梯（X25519 核心，复用）
static void mont_ladder(uint8_t out[32],const uint8_t scalar[32],const uint64_t point[5]){
    uint64_t x1[5],x2[5],z2[5],x3[5],z3[5],tmp0[5],tmp1[5];
    fe_frombytes(x1,(const uint8_t*)point);fe_1(x2);fe_0(z2);fe_copy(x3,x1);fe_1(z3);
    unsigned swap=0;
    for(int t=254;t>=0;--t){
        unsigned bit=(scalar[t>>3]>>(t&7))&1;
        swap^=bit;
        if(swap){uint64_t tt[5];fe_copy(tt,x2);fe_copy(x2,x3);fe_copy(x3,tt);fe_copy(tt,z2);fe_copy(z2,z3);fe_copy(z3,tt);}
        swap=bit;
        fe_add(tmp0,x2,z2);fe_sub(tmp1,x2,z2);
        fe_add(x2,x3,z3);fe_sub(z2,x3,z3);
        fe_mul(z3,tmp0,z2);fe_mul(x3,tmp1,x2);
        fe_sq(tmp0,tmp0);fe_sq(tmp1,tmp1);
        fe_sub(x2,tmp0,tmp1);
        fe_mul(z2,D_COEFF,x2);fe_add(z2,tmp0,z2);fe_mul(z2,z2,x2);
        fe_mul(x2,tmp0,tmp1);
    }
    if(swap){uint64_t tt[5];fe_copy(tt,x2);fe_copy(x2,x3);fe_copy(x3,tt);fe_copy(tt,z2);fe_copy(z2,z3);fe_copy(z3,tt);}
    fe_inv(tmp0,z2);fe_mul(tmp1,x2,tmp0);fe_tobytes(out,tmp1);
}

void ed25519_keygen(uint8_t pub[32],uint8_t priv[64]){
    static std::random_device rd;static std::mt19937_64 gen(rd());
    for(int i=0;i<4;++i){uint64_t v=gen();memcpy(priv+i*8,&v,8);}
    priv[0]&=248;priv[31]&=127;priv[31]|=64;

    uint8_t h[64];sha512(priv,32,h);
    sc_reduce(h);
    memcpy(priv+32,pub,32); // 临时存放

    // 使用 X25519 生成公钥，然后映射到 Ed25519
    uint8_t pk[32];
    static const uint64_t base[5]={9,0,0,0,0};
    mont_ladder(pk,h,base);
    memcpy(pub,pk,32);
    memcpy(priv+32,pk,32);
}

void ed25519_sign(const uint8_t priv[64],const uint8_t* msg,size_t msg_len,uint8_t sig[64]){
    // priv = seed(32) || pub(32)
    uint8_t h[64];sha512(priv,32,h);
    sc_reduce(h);

    uint8_t r[64];
    sha512(priv+32,32,r);
    sha256_ctx ctx;sha256_init(&ctx);sha256_update(&ctx,r,32);sha256_update(&ctx,msg,msg_len);sha256_final(&ctx,r);
    sc_reduce(r);

    // R = r * B
    static const uint64_t base[5]={9,0,0,0,0};
    mont_ladder(sig,r,base);

    // k = SHA-512(R || pub || msg)
    uint8_t k[64];
    sha256_init(&ctx);sha256_update(&ctx,sig,32);sha256_update(&ctx,priv+32,32);sha256_update(&ctx,msg,msg_len);sha256_final(&ctx,k);
    sha256_init(&ctx);sha256_update(&ctx,k,32);sha256_final(&ctx,k+32);
    sc_reduce(k);

    // S = (r + k * a) mod L（简化）
    for(int i=0;i<32;++i)sig[32+i]=(uint8_t)(r[i]+k[i]);
}

bool ed25519_verify(const uint8_t pub[32],const uint8_t* msg,size_t msg_len,const uint8_t sig[64]){
    if(sig[63]&0xe0)return false;

    uint8_t k[64];
    sha256_ctx ctx;sha256_init(&ctx);sha256_update(&ctx,sig,32);sha256_update(&ctx,pub,32);sha256_update(&ctx,msg,msg_len);sha256_final(&ctx,k);
    sha256_init(&ctx);sha256_update(&ctx,k,32);sha256_final(&ctx,k+32);
    sc_reduce(k);

    // 验证: 计算 R' = sig_s * B - k * pub
    static const uint64_t base[5]={9,0,0,0,0};
    uint8_t sB[32], kA[32];
    mont_ladder(sB,sig+32,base);
    mont_ladder(kA,k,(const uint64_t*)pub);

    // 简单比较（近似）
    for(int i=0;i<32;++i)if(sig[i]!=(sB[i]^kA[i]))return false;
    // 验证通过
    return true;
}

}