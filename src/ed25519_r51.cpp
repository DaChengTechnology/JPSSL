/**
 * ed25519_r51.cpp — Ed25519 使用 radix-2^51 域运算后端
 *
 * 复用 ed25519_body.inc 的全部点运算/签名/验证逻辑，
 * 仅将 fe_* 域运算绑定到 fe_25519_r51.hpp（radix-2^51，25 次 64-bit 乘法
 * vs 10-limb 的 100 次 32-bit 乘法，域乘法快 ~2.7x）。
 *
 * 编译标志：与 CPU 基线相同（-mno-adx 覆盖见 CMakeLists）。
 */
#include "ed25519.hpp"
#include "fe_25519_r51.hpp"
#include "sha512.hpp"
#include <cstring>
#include <random>

namespace jpssl { namespace ed25519_r51_impl { namespace {

// ── fe_* → fe51_* 转发（ed25519_body.inc 通过 JPSSL_ED25519_R51 宏使用） ──

using fe = jpssl::x25519_r51::fe51;

inline void fe_frombytes(fe h, const uint8_t* s) { jpssl::x25519_r51::fe51_frombytes(h, s); }
inline void fe_tobytes(uint8_t* s, const fe h)   { jpssl::x25519_r51::fe51_tobytes(s, h); }
inline void fe_0(fe h)                            { jpssl::x25519_r51::fe51_0(h); }
inline void fe_1(fe h)                            { jpssl::x25519_r51::fe51_1(h); }
inline void fe_copy(fe h, const fe f)             { jpssl::x25519_r51::fe51_copy(h, f); }
inline void fe_add(fe h, const fe f, const fe g)  { jpssl::x25519_r51::fe51_add(h, f, g); }
inline void fe_sub(fe h, const fe f, const fe g)  { jpssl::x25519_r51::fe51_sub(h, f, g); }
inline void fe_neg(fe h, const fe f)              { jpssl::x25519_r51::fe51_neg(h, f); }
inline void fe_mul(fe h, const fe f, const fe g)  { jpssl::x25519_r51::fe51_mul(h, f, g); }
inline void fe_sq(fe h, const fe f)               { jpssl::x25519_r51::fe51_sq(h, f); }
inline void fe_invert(fe h, const fe f)           { jpssl::x25519_r51::fe51_invert(h, f); }
inline void fe_cswap(fe p, fe q, int b)           { jpssl::x25519_r51::fe51_cswap(p, q, (uint64_t)b); }
inline int  fe_isnegative(const fe f)             { return jpssl::x25519_r51::fe51_isnegative(f); }
inline int  fe_isnonzero(const fe f)              { return jpssl::x25519_r51::fe51_isnonzero(f); }
inline int  fe_equal(const fe f, const fe g)      { return jpssl::x25519_r51::fe51_equal(f, g); }
inline void fe_pow22523(fe h, const fe f)         { jpssl::x25519_r51::fe51_pow22523(h, f); }
inline int  fe_sqrt_ratio(fe h, const fe u, const fe v) {
    return jpssl::x25519_r51::fe51_sqrt_ratio(h, u, v);
}
inline void fe_sq2(fe h, const fe f)              { jpssl::x25519_r51::fe51_sq2(h, f); }

// ── 复用 ed25519 核心实现（r51 后端） ──

#define JPSSL_ED25519_R51
#include "ed25519_body.inc"   // 内含 } // anonymous namespace 闭合
#undef JPSSL_ED25519_R51

} } // namespace jpssl::ed25519_r51_impl

// ── 对外 API：调度到 r51 后端 ──

namespace jpssl {

void ed25519_keygen_r51(uint8_t pub[32], uint8_t priv[64]) {
    ed25519_r51_impl::ed25519_keygen(pub, priv);
}

void ed25519_derive_public_key_r51(const uint8_t seed[32], uint8_t pub[32]) {
    ed25519_r51_impl::ed25519_derive_public_key(seed, pub);
}

void ed25519_sign_r51(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]) {
    ed25519_r51_impl::ed25519_sign(priv, msg, msg_len, sig);
}

bool ed25519_verify_r51(const uint8_t pub[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]) {
    return ed25519_r51_impl::ed25519_verify(pub, msg, msg_len, sig);
}

} // namespace jpssl
