#pragma once
/**
 * rsa.hpp — RSA 公钥加密（2048-bit + 4096-bit 完整支持）
 */
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace jpssl {

inline constexpr size_t RSA_2048_BITS=2048, RSA_2048_WORDS=32, RSA_2048_BYTES=256;
inline constexpr size_t RSA_4096_BITS=4096, RSA_4096_WORDS=64, RSA_4096_BYTES=512;

// ── 大整数（2048-bit） ────────────────────────────────────────────────
struct alignas(64) rsa_bignum { uint64_t d[32];
    rsa_bignum();
    void zero(); bool is_zero() const; bool is_one() const; int bit_length() const;
    bool operator==(const rsa_bignum&) const; bool operator<(const rsa_bignum&) const;
    bool bit(int) const; void set_bit(int);
    static rsa_bignum from_uint64(uint64_t);
    static rsa_bignum from_bytes(const uint8_t*, size_t len=256);
    void to_bytes(uint8_t*) const;
    static rsa_bignum random_odd();
};

// ── 4096-bit 类型 ─────────────────────────────────────────────────────
struct alignas(64) rsa4096_bignum { uint64_t d[64];
    rsa4096_bignum();
    void zero(); bool is_zero() const; bool is_one() const; int bit_length() const;
    bool operator==(const rsa4096_bignum&) const; bool operator<(const rsa4096_bignum&) const;
    bool bit(int) const; void set_bit(int);
    static rsa4096_bignum from_uint64(uint64_t);
    static rsa4096_bignum from_bytes(const uint8_t*, size_t len=512);
    void to_bytes(uint8_t*) const;
    static rsa4096_bignum random_odd();
};

// ── 运算（2048-bit） ──────────────────────────────────────────────────
void bn_add(rsa_bignum&,const rsa_bignum&,const rsa_bignum&);
void bn_sub(rsa_bignum&,const rsa_bignum&,const rsa_bignum&);
void bn_mul(rsa_bignum&,const rsa_bignum&,const rsa_bignum&);
void bn_divmod(rsa_bignum&,rsa_bignum&,const rsa_bignum&,const rsa_bignum&);
void bn_mod(rsa_bignum&,const rsa_bignum&,const rsa_bignum&);
void bn_modpow(rsa_bignum&,const rsa_bignum&,const rsa_bignum&,const rsa_bignum&);
void bn_rshift(rsa_bignum&,const rsa_bignum&,int);
void bn_lshift(rsa_bignum&,const rsa_bignum&,int);
bool bn_is_prime(const rsa_bignum&,int=5);
void bn_modinv(rsa_bignum&,const rsa_bignum&,const rsa_bignum&);

// ── 运算（4096-bit 重载） ─────────────────────────────────────────────
void bn_add(rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&);
void bn_sub(rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&);
void bn_mul(rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&);
void bn_divmod(rsa4096_bignum&,rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&);
void bn_mod(rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&);
void bn_modpow(rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&);
void bn_rshift(rsa4096_bignum&,const rsa4096_bignum&,int);
void bn_lshift(rsa4096_bignum&,const rsa4096_bignum&,int);
bool bn_is_prime(const rsa4096_bignum&,int=5);
void bn_modinv(rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&);

// ── RSA 密钥 ──────────────────────────────────────────────────────────
struct rsa_public_key { rsa_bignum n,e; };
struct rsa_private_key { rsa_bignum n,d,e; };
struct rsa4096_public_key { rsa4096_bignum n,e; };
struct rsa4096_private_key { rsa4096_bignum n,d,e; };

/// @brief CRT 私钥 (RFC 8017 §3.2 RSAPrivateKey)
struct rsa_crt_key {
    rsa_bignum n, e, d;   // modulus, publicExponent, privateExponent
    rsa_bignum p, q;      // prime1, prime2
    rsa_bignum dP, dQ;    // exponent1 = d mod (p-1), exponent2 = d mod (q-1)
    rsa_bignum qInv;      // coefficient = q^(-1) mod p
};
struct rsa4096_crt_key {
    rsa4096_bignum n, e, d;
    rsa4096_bignum p, q;
    rsa4096_bignum dP, dQ;
    rsa4096_bignum qInv;
};

bool rsa_keygen(rsa_public_key&,rsa_private_key&);
void rsa_encrypt(const rsa_public_key&,std::span<const uint8_t>,uint8_t*);
bool rsa_decrypt(const rsa_private_key&,const uint8_t*,std::vector<uint8_t>&);

bool rsa4096_keygen(rsa4096_public_key&,rsa4096_private_key&);
void rsa4096_encrypt(const rsa4096_public_key&,std::span<const uint8_t>,uint8_t*);
bool rsa4096_decrypt(const rsa4096_private_key&,const uint8_t*,std::vector<uint8_t>&);

// ── Montgomery 上下文 ─────────────────────────────────────────────────
struct mont_ctx { rsa_bignum R_mod_m, R2_mod_m; uint64_t m_prime; };
struct mont_ctx4096 { rsa4096_bignum R_mod_m, R2_mod_m; uint64_t m_prime; };

mont_ctx rsa_mont_init(const rsa_bignum&);
mont_ctx4096 rsa4096_mont_init(const rsa4096_bignum&);
void rsa_mont_modpow(rsa_bignum&,const rsa_bignum&,const rsa_bignum&,const mont_ctx&,const rsa_bignum&);
void rsa4096_mont_modpow(rsa4096_bignum&,const rsa4096_bignum&,const rsa4096_bignum&,const mont_ctx4096&,const rsa4096_bignum&);

// ── 批量 CPU 解密（AVX2/AVX-512 加速）─────────────────────────────────
/// 批量 RSA-2048 解密：使用同一私钥解密 count 个密文
/// count 不必是 4/8 的倍数（会自动处理剩余部分）
/// cts/pts: count × 256 字节（big-endian, PKCS#1 v1.5）
/// 返回实际解密的个数（PKCS#1 格式不正确的跳过）
size_t rsa_batch_decrypt(const rsa_private_key&,const uint8_t* cts,uint8_t* pts,size_t count);

/// 批量 RSA-4096 解密
size_t rsa4096_batch_decrypt(const rsa4096_private_key&,const uint8_t* cts,uint8_t* pts,size_t count);

/// 批量模幂（低层 API，用于 benchmark/debug）
void rsa_batch_modpow(const rsa_bignum& base,const rsa_bignum& exp,const mont_ctx& mctx,const uint8_t* bases,uint8_t* results,size_t count);
void rsa4096_batch_modpow(const rsa4096_bignum& mod,const rsa4096_bignum& exp,const mont_ctx4096& mctx,const uint8_t* bases,uint8_t* results,size_t count);

// ── GPU ───────────────────────────────────────────────────────────────
struct musa_rsa_pool;
musa_rsa_pool* musa_rsa_pool_create(const rsa_private_key&,size_t=1024);
void musa_rsa_pool_destroy(musa_rsa_pool*);
void musa_rsa_batch_decrypt(musa_rsa_pool*,const uint8_t*,uint8_t*,size_t);
void musa_rsa_batch_modpow(const rsa_bignum&,const rsa_bignum&,const mont_ctx&,const uint8_t*,uint8_t*,size_t);
void musa4096_rsa_batch_modpow(const rsa4096_bignum&,const rsa4096_bignum&,const mont_ctx4096&,const uint8_t*,uint8_t*,size_t);

// ───────────────────────────────────────────────────────────────────────
//  RFC 8017 扩展: I2OSP/OS2IP, MGF1, 原语, CRT, OAEP, PSS
// ───────────────────────────────────────────────────────────────────────

/// §4.1/4.2  I2OSP / OS2IP
bool I2OSP(uint64_t x, uint8_t* out, size_t xLen);
bool I2OSP(const rsa_bignum& x, uint8_t* out, size_t xLen);
bool I2OSP(const rsa4096_bignum& x, uint8_t* out, size_t xLen);
rsa_bignum     OS2IP2048(const uint8_t*, size_t);
rsa4096_bignum OS2IP4096(const uint8_t*, size_t);

/// §B.2.1  MGF1
void mgf1_sha256(const uint8_t* seed, size_t seedLen, uint8_t* mask, size_t maskLen);
void mgf1_sha384(const uint8_t* seed, size_t seedLen, uint8_t* mask, size_t maskLen);
void mgf1_sha512(const uint8_t* seed, size_t seedLen, uint8_t* mask, size_t maskLen);

/// §5  RSA 原语
void RSAEP(const rsa_public_key&, const rsa_bignum& m, rsa_bignum& c);
void RSAEP4096(const rsa4096_public_key&, const rsa4096_bignum& m, rsa4096_bignum& c);
void RSADP(const rsa_crt_key&, const rsa_bignum& c, rsa_bignum& m);
void RSADP4096(const rsa4096_crt_key&, const rsa4096_bignum& c, rsa4096_bignum& m);
void RSASP1(const rsa_crt_key&, const rsa_bignum& m, rsa_bignum& s);
void RSASP14096(const rsa4096_crt_key&, const rsa4096_bignum& m, rsa4096_bignum& s);
void RSAVP1(const rsa_public_key&, const rsa_bignum& s, rsa_bignum& m);
void RSAVP14096(const rsa4096_public_key&, const rsa4096_bignum& s, rsa4096_bignum& m);

/// §6  CRT 参数计算 + 升级版 keygen（强制 n 位宽 + CRT 输出）
bool rsa_keygen_crt(rsa_public_key&, rsa_crt_key&);
bool rsa4096_keygen_crt(rsa4096_public_key&, rsa4096_crt_key&);
void compute_crt_params(const rsa_bignum& p, const rsa_bignum& q, const rsa_bignum& d,
                        rsa_bignum& dP, rsa_bignum& dQ, rsa_bignum& qInv);
void compute_crt_params4096(const rsa4096_bignum& p, const rsa4096_bignum& q,
                            const rsa4096_bignum& d,
                            rsa4096_bignum& dP, rsa4096_bignum& dQ,
                            rsa4096_bignum& qInv);
bool rsa_crt_decrypt(const rsa_crt_key&, const uint8_t* ct, std::vector<uint8_t>& pt);
bool rsa4096_crt_decrypt(const rsa4096_crt_key&, const uint8_t* ct, std::vector<uint8_t>& pt);

/// §7.1  RSAES-OAEP (SHA-256)
bool rsaes_oaep_encrypt(const rsa_public_key&, std::span<const uint8_t> msg,
                        const uint8_t* label, size_t labelLen, uint8_t ct[256]);
bool rsaes_oaep_decrypt(const rsa_crt_key&, const uint8_t ct[256],
                        const uint8_t* label, size_t labelLen,
                        std::vector<uint8_t>& msg);

/// §8.1  RSASSA-PSS (SHA-256, saltLen 默认 32)
bool rsassa_pss_sign(const rsa_crt_key&, const uint8_t* msg, size_t msgLen,
                     uint8_t sig[256], size_t saltLen=32);
bool rsassa_pss_verify(const rsa_public_key&, const uint8_t* msg, size_t msgLen,
                       const uint8_t sig[256], size_t saltLen=32);

/// §8.2  RSASSA-PKCS1-v1_5 签名/验证
/// digestPrefix: DER 编码的 DigestInfo 前缀 (如 SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20)
bool rsassa_pkcs1v15_sign(const rsa_crt_key&, const uint8_t* msg, size_t msgLen,
                          const uint8_t* digestPrefix, size_t prefixLen,
                          uint8_t sig[256]);
bool rsassa_pkcs1v15_verify(const rsa_public_key&, const uint8_t* msg, size_t msgLen,
                            const uint8_t* digestPrefix, size_t prefixLen,
                            const uint8_t sig[256]);
}
