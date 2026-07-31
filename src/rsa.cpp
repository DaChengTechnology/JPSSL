#include "rsa.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

// 辅助宏：token 拼接
#define CAT2(a,b) a##b
#define CAT(a,b) CAT2(a,b)

namespace jpssl {

// ═══════════════ K=32 (2048-bit) ═══════════════
#define K 32
#define BN rsa_bignum
#define PUB_KEY rsa_public_key
#define PRIV_KEY rsa_private_key
#define MONT_CTX mont_ctx
#include "rsa_body.inc"
// 显式对接函数名
mont_ctx rsa_mont_init(const rsa_bignum&m){return CAT(mont_init_fn_,K)(m);}
void rsa_mont_modpow(rsa_bignum&r,const rsa_bignum&b,const rsa_bignum&e,const mont_ctx&c,const rsa_bignum&m){CAT(mont_modpow_fn_,K)(r,b,e,c,m);}
bool rsa_keygen(rsa_public_key&pub,rsa_private_key&prv){return CAT(keygen_fn_,K)(pub,prv);}
void rsa_encrypt(const rsa_public_key&pub,std::span<const uint8_t> pt,uint8_t*ct){CAT(enc_fn_,K)(pub,pt,ct);}
bool rsa_decrypt(const rsa_private_key&prv,const uint8_t*ct,std::vector<uint8_t>&pt){return CAT(dec_fn_,K)(prv,ct,pt);}
#undef K
#undef BN
#undef PUB_KEY
#undef PRIV_KEY
#undef MONT_CTX

// ═══════════════ K=64 (4096-bit) ═══════════════
#define K 64
#define BN rsa4096_bignum
#define PUB_KEY rsa4096_public_key
#define PRIV_KEY rsa4096_private_key
#define MONT_CTX mont_ctx4096
#include "rsa_body.inc"
// 显式对接函数名
mont_ctx4096 rsa4096_mont_init(const rsa4096_bignum&m){return CAT(mont_init_fn_,K)(m);}
void rsa4096_mont_modpow(rsa4096_bignum&r,const rsa4096_bignum&b,const rsa4096_bignum&e,const mont_ctx4096&c,const rsa4096_bignum&m){CAT(mont_modpow_fn_,K)(r,b,e,c,m);}
bool rsa4096_keygen(rsa4096_public_key&pub,rsa4096_private_key&prv){return CAT(keygen_fn_,K)(pub,prv);}
void rsa4096_encrypt(const rsa4096_public_key&pub,std::span<const uint8_t> pt,uint8_t*ct){CAT(enc_fn_,K)(pub,pt,ct);}
bool rsa4096_decrypt(const rsa4096_private_key&prv,const uint8_t*ct,std::vector<uint8_t>&pt){return CAT(dec_fn_,K)(prv,ct,pt);}
#undef K
#undef BN
#undef PUB_KEY
#undef PRIV_KEY
#undef MONT_CTX

// 4096 GPU batch modpow stub (calls CPU)
#ifdef JP_MUSA
void musa4096_rsa_batch_modpow(const rsa4096_bignum&mod,const rsa4096_bignum&exp,const mont_ctx4096&mctx,const uint8_t* bases,uint8_t* results,size_t count){
    for(size_t i=0;i<count;++i){
        rsa4096_bignum base=rsa4096_bignum::from_bytes(bases+i*512,512),r;
        rsa4096_mont_modpow(r,base,exp,mctx,mod);
        r.to_bytes(results+i*512);
    }
}
#endif

} // namespace jpssl
