#include "x25519.hpp"
#include <cstring>
#include <random>
#include <openssl/evp.h>
#include <openssl/core_names.h>

namespace jpssl {

void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    // If point is nullptr, use the X25519 base point (u=9)
    static const uint8_t base_point[32] = {9, 0};
    const uint8_t* pub = point ? point : base_point;

    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub, 32);
    if (!peer_key) { memset(out, 0, 32); return; }

    EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, scalar, 32);
    if (!priv_key) { EVP_PKEY_free(peer_key); memset(out, 0, 32); return; }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) { EVP_PKEY_free(peer_key); EVP_PKEY_free(priv_key); memset(out, 0, 32); return; }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(priv_key);
        memset(out, 0, 32);
        return;
    }

    size_t outlen = 32;
    EVP_PKEY_derive(ctx, out, &outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(priv_key);
}

void x25519_generate_keypair(uint8_t pub[32], uint8_t priv[32]) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (int i = 0; i < 4; ++i) {
        uint64_t v = gen();
        memcpy(priv + i*8, &v, 8);
    }
    // Clamp per RFC 7748
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    x25519_scalar_mult(pub, priv, nullptr);
}

} // namespace jpssl
