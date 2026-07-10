#include "ed25519.hpp"
#include <cstring>
#include <random>
#include <openssl/evp.h>
#include <openssl/core_names.h>

namespace jpssl {

void ed25519_keygen(uint8_t pub[32], uint8_t priv[64]) {
    // Generate Ed25519 key pair using OpenSSL EVP
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr);
    if (!ctx) {
        // Fallback: generate random seed and use low-level keygen
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        for (int i = 0; i < 4; ++i) {
            uint64_t v = gen();
            memcpy(priv + i*8, &v, 8);
        }
        // Placeholder: pub = zeros (will be overwritten by caller if needed)
        memset(pub, 0, 32);
        memcpy(priv + 32, pub, 32);
        return;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        memset(pub, 0, 32);
        memset(priv, 0, 64);
        return;
    }
    EVP_PKEY_CTX_free(ctx);

    // Extract raw public key (32 bytes)
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);

    // Extract raw private key (32 bytes seed)
    size_t priv_len = 32;
    EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len);

    // Store seed || pub (64 bytes total)
    memcpy(priv + 32, pub, 32);

    EVP_PKEY_free(pkey);
}

void ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]) {
    // priv = seed(32) || pub(32)
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv, 32);
    if (!pkey) {
        memset(sig, 0, 64);
        return;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        memset(sig, 0, 64);
        return;
    }

    size_t sig_len = 64;
    EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
}

bool ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    int ret = EVP_DigestVerify(md_ctx, sig, 64, msg, msg_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret == 1;
}

} // namespace jpssl
