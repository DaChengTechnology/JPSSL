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

// 4096 GPU batch modpow stub (calls CPU — GPU 仅支持 2048-bit)
void musa4096_rsa_batch_modpow(const rsa4096_bignum&mod,const rsa4096_bignum&exp,const mont_ctx4096&mctx,const uint8_t* bases,uint8_t* results,size_t count){
    for(size_t i=0;i<count;++i){
        rsa4096_bignum base=rsa4096_bignum::from_bytes(bases+i*512,512),r;
        rsa4096_mont_modpow(r,base,exp,mctx,mod);
        r.to_bytes(results+i*512);
    }
}

// ═══════════════ CRT keygen ═══════════════
bool rsa_keygen_crt(rsa_public_key& pub, rsa_crt_key& crt) {
    rsa_bignum p, q, n, phi, e(rsa_bignum::from_uint64(65537)), d, dP, dQ, qInv;
    while (1) {
        p = rsa_bignum::random_odd();
        for (int i = 16; i < 32; ++i) p.d[i] = 0;
        p.d[15] |= (uint64_t)1 << 63;
        p.d[15] &= ~((uint64_t)1 << 62);
        if (bn_is_prime(p, 5)) break;
    }
    while (1) {
        q = rsa_bignum::random_odd();
        for (int i = 16; i < 32; ++i) q.d[i] = 0;
        q.d[15] |= (uint64_t)1 << 63;
        q.d[15] &= ~((uint64_t)1 << 62);
        if (bn_is_prime(q, 5) && !(p == q)) break;
    }
    bn_mul(n, p, q);
    rsa_bignum p1, q1;
    bn_sub(p1, p, rsa_bignum::from_uint64(1));
    bn_sub(q1, q, rsa_bignum::from_uint64(1));
    bn_mul(phi, p1, q1);
    bn_modinv(d, e, phi);
    while (n.bit_length() < 2048) { /* retry */
        p = rsa_bignum::random_odd();
        for (int i = 16; i < 32; ++i) p.d[i] = 0;
        p.d[15] |= (uint64_t)1 << 63; p.d[15] &= ~((uint64_t)1 << 62);
        if (!bn_is_prime(p, 5)) continue;
        q = rsa_bignum::random_odd();
        for (int i = 16; i < 32; ++i) q.d[i] = 0;
        q.d[15] |= (uint64_t)1 << 63; q.d[15] &= ~((uint64_t)1 << 62);
        if (!bn_is_prime(q, 5) || p == q) continue;
        bn_mul(n, p, q);
        bn_sub(p1, p, rsa_bignum::from_uint64(1));
        bn_sub(q1, q, rsa_bignum::from_uint64(1));
        bn_mul(phi, p1, q1);
        bn_modinv(d, e, phi);
    }
    bn_mod(dP, d, p1); bn_mod(dQ, d, q1); bn_modinv(qInv, q, p);
    pub.n = n; pub.e = e;
    crt.n = n; crt.e = e; crt.d = d; crt.p = p; crt.q = q;
    crt.dP = dP; crt.dQ = dQ; crt.qInv = qInv;
    return true;
}

bool rsa4096_keygen_crt(rsa4096_public_key& pub, rsa4096_crt_key& crt) {
    rsa4096_bignum p, q, n, phi, e(rsa4096_bignum::from_uint64(65537)), d, dP, dQ, qInv;
    while (1) {
        p = rsa4096_bignum::random_odd();
        for (int i = 32; i < 64; ++i) p.d[i] = 0;
        p.d[31] |= (uint64_t)1 << 63;
        p.d[31] &= ~((uint64_t)1 << 62);
        if (bn_is_prime(p, 5)) break;
    }
    while (1) {
        q = rsa4096_bignum::random_odd();
        for (int i = 32; i < 64; ++i) q.d[i] = 0;
        q.d[31] |= (uint64_t)1 << 63;
        q.d[31] &= ~((uint64_t)1 << 62);
        if (bn_is_prime(q, 5) && !(p == q)) break;
    }
    bn_mul(n, p, q);
    rsa4096_bignum p1, q1;
    bn_sub(p1, p, rsa4096_bignum::from_uint64(1));
    bn_sub(q1, q, rsa4096_bignum::from_uint64(1));
    bn_mul(phi, p1, q1);
    bn_modinv(d, e, phi);
    while (n.bit_length() < 4096) {
        p = rsa4096_bignum::random_odd();
        for (int i = 32; i < 64; ++i) p.d[i] = 0;
        p.d[31] |= (uint64_t)1 << 63; p.d[31] &= ~((uint64_t)1 << 62);
        if (!bn_is_prime(p, 5)) continue;
        q = rsa4096_bignum::random_odd();
        for (int i = 32; i < 64; ++i) q.d[i] = 0;
        q.d[31] |= (uint64_t)1 << 63; q.d[31] &= ~((uint64_t)1 << 62);
        if (!bn_is_prime(q, 5) || p == q) continue;
        bn_mul(n, p, q);
        bn_sub(p1, p, rsa4096_bignum::from_uint64(1));
        bn_sub(q1, q, rsa4096_bignum::from_uint64(1));
        bn_mul(phi, p1, q1);
        bn_modinv(d, e, phi);
    }
    bn_mod(dP, d, p1); bn_mod(dQ, d, q1); bn_modinv(qInv, q, p);
    pub.n = n; pub.e = e;
    crt.n = n; crt.e = e; crt.d = d; crt.p = p; crt.q = q;
    crt.dP = dP; crt.dQ = dQ; crt.qInv = qInv;
    return true;
}

} // namespace jpssl
