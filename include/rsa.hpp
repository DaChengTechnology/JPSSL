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

// ── GPU ───────────────────────────────────────────────────────────────
struct musa_rsa_pool;
musa_rsa_pool* musa_rsa_pool_create(const rsa_private_key&,size_t=1024);
void musa_rsa_pool_destroy(musa_rsa_pool*);
void musa_rsa_batch_decrypt(musa_rsa_pool*,const uint8_t*,uint8_t*,size_t);
void musa_rsa_batch_modpow(const rsa_bignum&,const rsa_bignum&,const mont_ctx&,const uint8_t*,uint8_t*,size_t);
void musa4096_rsa_batch_modpow(const rsa4096_bignum&,const rsa4096_bignum&,const mont_ctx4096&,const uint8_t*,uint8_t*,size_t);
}
