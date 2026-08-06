/**
 * ed25519.cpp — Ed25519 调度层
 *
 * Public API 转发到 radix-2^51 后端（ed25519_r51.cpp，域乘法快 ~2.7x）。
 * ref10 (10-limb) 实现保留在 ed25519_ref10_impl 命名空间供对照/回退。
 */
#include "ed25519.hpp"
#include "fe_25519.hpp"
#include "sha512.hpp"
#include <cstring>
#include <random>

namespace jpssl { namespace ed25519_ref10_impl { namespace {
// ref10 后端：ed25519_body.inc 默认分支（fe_impl 绑定）
// body.inc 内含 } // anonymous namespace，Public API 落在 ed25519_ref10_impl
#include "ed25519_body.inc"
} } // namespace jpssl::ed25519_ref10_impl

namespace jpssl {

void ed25519_keygen(uint8_t pub[32], uint8_t priv[64]) {
    ed25519_keygen_r51(pub, priv);
}

void ed25519_derive_public_key(const uint8_t seed[32], uint8_t pub[32]) {
    ed25519_derive_public_key_r51(seed, pub);
}

void ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]) {
    ed25519_sign_r51(priv, msg, msg_len, sig);
}

bool ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]) {
    return ed25519_verify_r51(pub, msg, msg_len, sig);
}

} // namespace jpssl
