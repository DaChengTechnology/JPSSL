// rsa_prim.cpp — RFC 8017 基础原语
//   §4.1  I2OSP / OS2IP
//   §4.2  MGF1 (Mask Generation Function, 附录 B.2.1)
//   §5.1  RSAEP / §5.2 RSADP / §5.3 RSASP1 / §5.4 RSAVP1
//   §6    CRT keygen helpers
#include "rsa.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  §4.1  I2OSP — Integer-to-Octet-String
//  将非负整数 x 编码为 xLen 字节 big-endian 串
//  要求 x < 256^xLen，否则返回 false
// ═══════════════════════════════════════════════════════════════════════

bool I2OSP(uint64_t x, uint8_t* out, size_t xLen) {
    if (xLen < 1 || xLen > 8) return false;
    for (int i = (int)xLen - 1; i >= 0; --i) {
        out[i] = (uint8_t)(x & 0xFF);
        x >>= 8;
    }
    return x == 0;
}

bool I2OSP(const rsa_bignum& x, uint8_t* out, size_t xLen) {
    size_t bl = (xLen > RSA_2048_BYTES) ? RSA_2048_BYTES : xLen;
    uint8_t tmp[256] = {};
    x.to_bytes(tmp);  // big-endian, 256 bytes
    size_t leading = 0;
    while (leading < RSA_2048_BYTES && tmp[leading] == 0) ++leading;
    size_t actual = RSA_2048_BYTES - leading;
    if (actual > xLen) return false;  // x 太大
    size_t pad = xLen - actual;
    memset(out, 0, pad);
    memcpy(out + pad, tmp + leading, actual);
    return true;
}

bool I2OSP(const rsa4096_bignum& x, uint8_t* out, size_t xLen) {
    uint8_t tmp[512] = {};
    x.to_bytes(tmp);
    size_t leading = 0;
    while (leading < RSA_4096_BYTES && tmp[leading] == 0) ++leading;
    size_t actual = RSA_4096_BYTES - leading;
    if (actual > xLen) return false;
    size_t pad = xLen - actual;
    memset(out, 0, pad);
    memcpy(out + pad, tmp + leading, actual);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  §4.2  OS2IP — Octet-String-to-Integer
// ═══════════════════════════════════════════════════════════════════════

rsa_bignum OS2IP2048(const uint8_t* X, size_t xLen) {
    return rsa_bignum::from_bytes(X, xLen);
}

rsa4096_bignum OS2IP4096(const uint8_t* X, size_t xLen) {
    return rsa4096_bignum::from_bytes(X, xLen);
}

// ═══════════════════════════════════════════════════════════════════════
//  MGF1 — Mask Generation Function (附录 B.2.1)
//  基于选定 hash 函数，从 mgfSeed 生成 maskLen 字节掩码
//
//  使用方式:
//    mgf1_sha256(seed, seed_len, mask, mask_len)
//    mgf1_sha384(seed, seed_len, mask, mask_len)
//    mgf1_sha512(seed, seed_len, mask, mask_len)
// ═══════════════════════════════════════════════════════════════════════

namespace {
void mgf1_impl(
    const uint8_t* mgfSeed, size_t seedLen,
    uint8_t* mask, size_t maskLen,
    void (*hash_init)(sha256_ctx*),
    void (*hash_init384)(sha512_ctx*),
    void (*hash_update256)(sha256_ctx*,const uint8_t*,size_t),
    void (*hash_update512)(sha512_ctx*,const uint8_t*,size_t),
    void (*hash_final256)(sha256_ctx*,uint8_t*),
    void (*hash_final512)(sha512_ctx*,uint8_t*),
    size_t hLen,
    bool is_sha384)
{
    for (size_t counter = 0, pos = 0; pos < maskLen; ++counter) {
        uint8_t C[4];
        C[0] = (uint8_t)(counter >> 24);
        C[1] = (uint8_t)(counter >> 16);
        C[2] = (uint8_t)(counter >> 8);
        C[3] = (uint8_t)(counter);

        uint8_t digest[64];
        if (hLen == 32) {
            sha256_ctx ctx;
            hash_init(&ctx);
            hash_update256(&ctx, mgfSeed, seedLen);
            hash_update256(&ctx, C, 4);
            hash_final256(&ctx, digest);
        } else {
            sha512_ctx ctx;
            if (is_sha384) sha384_init(&ctx); else sha512_init(&ctx);
            hash_update512(&ctx, mgfSeed, seedLen);
            hash_update512(&ctx, C, 4);
            hash_final512(&ctx, digest);
        }
        size_t take = (pos + hLen <= maskLen) ? hLen : (maskLen - pos);
        memcpy(mask + pos, digest, take);
        pos += take;
    }
}
} // anonymous

void mgf1_sha256(const uint8_t* mgfSeed, size_t seedLen,
                 uint8_t* mask, size_t maskLen) {
    mgf1_impl(mgfSeed, seedLen, mask, maskLen,
              [](sha256_ctx* c){ sha256_init(c); },
              nullptr,
              [](sha256_ctx* c, const uint8_t* d, size_t n){ sha256_update(c,d,n); },
              nullptr,
              [](sha256_ctx* c, uint8_t* d){ sha256_final(c,d); },
              nullptr,
              32, false);
}

void mgf1_sha384(const uint8_t* mgfSeed, size_t seedLen,
                 uint8_t* mask, size_t maskLen) {
    mgf1_impl(mgfSeed, seedLen, mask, maskLen,
              nullptr,
              [](sha512_ctx* c){ sha384_init(c); },
              nullptr,
              [](sha512_ctx* c, const uint8_t* d, size_t n){ sha512_update(c,d,n); },
              nullptr,
              [](sha512_ctx* c, uint8_t* d){ sha512_final(c,d); },
              48, true);
}

void mgf1_sha512(const uint8_t* mgfSeed, size_t seedLen,
                 uint8_t* mask, size_t maskLen) {
    mgf1_impl(mgfSeed, seedLen, mask, maskLen,
              nullptr,
              [](sha512_ctx* c){ sha512_init(c); },
              nullptr,
              [](sha512_ctx* c, const uint8_t* d, size_t n){ sha512_update(c,d,n); },
              nullptr,
              [](sha512_ctx* c, uint8_t* d){ sha512_final(c,d); },
              64, false);
}

// ═══════════════════════════════════════════════════════════════════════
//  §5.1  RSAEP — RSA Encryption Primitive (base operation)
//  输入: public key (n, e), message representative m (整数值)
//  输出: ciphertext representative c = m^e mod n
//  条件: 0 ≤ m < n-1
// ═══════════════════════════════════════════════════════════════════════

void RSAEP(const rsa_public_key& pub, const rsa_bignum& m, rsa_bignum& c) {
    auto mctx = rsa_mont_init(pub.n);
    rsa_mont_modpow(c, m, pub.e, mctx, pub.n);
}

void RSAEP4096(const rsa4096_public_key& pub, const rsa4096_bignum& m,
               rsa4096_bignum& c) {
    auto mctx = rsa4096_mont_init(pub.n);
    rsa4096_mont_modpow(c, m, pub.e, mctx, pub.n);
}

// ═══════════════════════════════════════════════════════════════════════
//  §5.2  RSADP — RSA Decryption Primitive (CRT 版本)
//  输入: CRT private key, ciphertext representative c
//  输出: message representative m = c^d mod n
//  条件: 0 ≤ c < n-1
// ═══════════════════════════════════════════════════════════════════════

void RSADP(const rsa_crt_key& k, const rsa_bignum& c, rsa_bignum& m) {
    // m1 = c^(dP) mod p
    auto mctx_p = rsa_mont_init(k.p);
    rsa_bignum m1, m2;
    // m2 = c^(dQ) mod q
    auto mctx_q = rsa_mont_init(k.q);
#ifdef _OPENMP
    // CRT 两路模幂完全独立 → OpenMP 双路并行
#pragma omp parallel sections num_threads(2)
{
#pragma omp section
{ rsa_mont_modpow_half(m1, c, k.dP, mctx_p, k.p); }
#pragma omp section
{ rsa_mont_modpow_half(m2, c, k.dQ, mctx_q, k.q); }
}
#else
    rsa_mont_modpow_half(m1, c, k.dP, mctx_p, k.p);
    rsa_mont_modpow_half(m2, c, k.dQ, mctx_q, k.q);
#endif
    // CRT 合并: m = m2 + q * ((m1 - m2) * qInv mod p)
    // 注意: m2 < q 但 q 可能 > p, 需先归约 m2 mod p 再参与 (m1 - m2) 运算
    rsa_bignum m2p;
    if (m2 < k.p) m2p = m2; else bn_mod(m2p, m2, k.p);
    rsa_bignum h;
    if (m1 < m2p) {
        rsa_bignum tmp;
        bn_sub(tmp, k.p, m2p);
        bn_add(h, m1, tmp);
    } else {
        bn_sub(h, m1, m2p);
    }
    rsa_bignum h2;
    bn_mul(h2, h, k.qInv);
    bn_mod(h, h2, k.p);
    rsa_bignum t;
    bn_mul(t, k.q, h);
    bn_add(m, m2, t);
}

void RSADP4096(const rsa4096_crt_key& k, const rsa4096_bignum& c,
               rsa4096_bignum& m) {
    auto mctx_p = rsa4096_mont_init(k.p);
    rsa4096_bignum m1, m2;
    auto mctx_q = rsa4096_mont_init(k.q);
#ifdef _OPENMP
    // CRT 两路模幂完全独立 → OpenMP 双路并行
#pragma omp parallel sections num_threads(2)
{
#pragma omp section
{ rsa4096_mont_modpow_half(m1, c, k.dP, mctx_p, k.p); }
#pragma omp section
{ rsa4096_mont_modpow_half(m2, c, k.dQ, mctx_q, k.q); }
}
#else
    rsa4096_mont_modpow_half(m1, c, k.dP, mctx_p, k.p);
    rsa4096_mont_modpow_half(m2, c, k.dQ, mctx_q, k.q);
#endif
    // CRT 合并: m = m2 + q * ((m1 - m2) * qInv mod p)
    // 注意: m2 < q 但 q 可能 > p, 需先归约 m2 mod p 再参与 (m1 - m2) 运算
    rsa4096_bignum m2p;
    if (m2 < k.p) m2p = m2; else bn_mod(m2p, m2, k.p);
    rsa4096_bignum h;
    if (m1 < m2p) {
        rsa4096_bignum tmp;
        bn_sub(tmp, k.p, m2p);
        bn_add(h, m1, tmp);
    } else {
        bn_sub(h, m1, m2p);
    }
    rsa4096_bignum h2;
    bn_mul(h2, h, k.qInv);
    bn_mod(h, h2, k.p);
    rsa4096_bignum t;
    bn_mul(t, k.q, h);
    bn_add(m, m2, t);
}

// ═══════════════════════════════════════════════════════════════════════
//  §5.3  RSASP1 — RSA Signature Primitive
//  输入: CRT private key, message representative m
//  输出: signature representative s = m^d mod n (CRT)
// ═══════════════════════════════════════════════════════════════════════

void RSASP1(const rsa_crt_key& k, const rsa_bignum& m, rsa_bignum& s) {
    RSADP(k, m, s);  // identical operation
}

void RSASP14096(const rsa4096_crt_key& k, const rsa4096_bignum& m,
                rsa4096_bignum& s) {
    RSADP4096(k, m, s);
}

// ═══════════════════════════════════════════════════════════════════════
//  §5.4  RSAVP1 — RSA Verification Primitive
//  输入: public key (n, e), signature representative s
//  输出: message representative m = s^e mod n
// ═══════════════════════════════════════════════════════════════════════

void RSAVP1(const rsa_public_key& pub, const rsa_bignum& s, rsa_bignum& m) {
    RSAEP(pub, s, m);  // identical operation
}

void RSAVP14096(const rsa4096_public_key& pub, const rsa4096_bignum& s,
                rsa4096_bignum& m) {
    RSAEP4096(pub, s, m);
}

// ═══════════════════════════════════════════════════════════════════════
//  §6    CRT 参数计算 (p, q, dP, dQ, qInv)
//  由 p, q, d 推导, 用于 keygen 后填充 CRT key
// ═══════════════════════════════════════════════════════════════════════

void compute_crt_params(const rsa_bignum& p, const rsa_bignum& q,
                               const rsa_bignum& d,
                               rsa_bignum& dP, rsa_bignum& dQ,
                               rsa_bignum& qInv) {
    rsa_bignum p1, q1;
    bn_sub(p1, p, rsa_bignum::from_uint64(1));
    bn_sub(q1, q, rsa_bignum::from_uint64(1));
    bn_mod(dP, d, p1);
    bn_mod(dQ, d, q1);
    // qInv = q^{-1} mod p: 费马小定理 q^{p-2} mod p (半宽模幂, 比除法欧几里得快)
    { rsa_bignum p2; bn_sub(p2, p, rsa_bignum::from_uint64(2));
      mont_ctx mcp = rsa_mont_init(p); rsa_mont_modpow_half(qInv, q, p2, mcp, p); }
}

void compute_crt_params4096(const rsa4096_bignum& p,
                                    const rsa4096_bignum& q,
                                    const rsa4096_bignum& d,
                                    rsa4096_bignum& dP,
                                    rsa4096_bignum& dQ,
                                    rsa4096_bignum& qInv) {
    rsa4096_bignum p1, q1;
    bn_sub(p1, p, rsa4096_bignum::from_uint64(1));
    bn_sub(q1, q, rsa4096_bignum::from_uint64(1));
    bn_mod(dP, d, p1);
    bn_mod(dQ, d, q1);
    // qInv = q^{-1} mod p: 费马小定理 q^{p-2} mod p (半宽模幂, 比除法欧几里得快)
    { rsa4096_bignum p2; bn_sub(p2, p, rsa4096_bignum::from_uint64(2));
      mont_ctx4096 mcp = rsa4096_mont_init(p); rsa4096_mont_modpow_half(qInv, q, p2, mcp, p); }
}

void rsa_fill_crt(const rsa_private_key& prv, rsa_crt_key& crt) {
    crt.n = prv.n; crt.e = prv.e; crt.d = prv.d;
    // p, q 需要从外部提供 (keygen 时已知)
    // 此处为占位——完整实现在 keygen 中直接填充
    (void)crt;
}

bool rsa_crt_decrypt(const rsa_crt_key& k, const uint8_t* ct,
                     std::vector<uint8_t>& pt) {
    size_t bl = RSA_2048_BYTES;
    rsa_bignum c = rsa_bignum::from_bytes(ct, bl), m;
    RSADP(k, c, m);
    uint8_t pad[256];
    m.to_bytes(pad);
    if (pad[0] != 0 || pad[1] != 2) return false;
    size_t sep = 2;
    while (sep < bl && pad[sep] != 0) ++sep;
    if (sep >= bl - 1) return false;
    pt.assign(pad + sep + 1, pad + bl);
    return true;
}

bool rsa4096_crt_decrypt(const rsa4096_crt_key& k, const uint8_t* ct,
                         std::vector<uint8_t>& pt) {
    size_t bl = RSA_4096_BYTES;
    rsa4096_bignum c = rsa4096_bignum::from_bytes(ct, bl), m;
    RSADP4096(k, c, m);
    uint8_t pad[512];
    m.to_bytes(pad);
    if (pad[0] != 0 || pad[1] != 2) return false;
    size_t sep = 2;
    while (sep < bl && pad[sep] != 0) ++sep;
    if (sep >= bl - 1) return false;
    pt.assign(pad + sep + 1, pad + bl);
    return true;
}

} // namespace jpssl
