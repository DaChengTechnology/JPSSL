/*
 * jpssl_bridge.cpp — jpssl 库的 extern "C" Swift 桥接实现
 *
 * 编译为 ios/bridge 内目标（iOS 构建时自动编入 libjpssl_cpu_static），
 * 头文件 jpssl.h + module.modulemap 暴露为 Clang 模块 `JPSslC`。
 *
 * 所有入口用 try/catch 包裹：C++ 异常不跨 C ABI 边界泄漏，
 * 失败统一返回 0 / nullptr。
 */
#include "jpssl.h"

#include "rand_os.hpp"
#include "sha1.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "sha3.hpp"
#include "sm3.hpp"
#include "hmac.hpp"
#include "hkdf.hpp"
#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sm4.hpp"
#include "sm4_gcm.hpp"
#include "sm4_ccm.hpp"
#include "x25519.hpp"
#include "x448.hpp"
#include "ed25519.hpp"
#include "ed448.hpp"
#include "ecdsa.hpp"
#include "sm2.hpp"
#include "rsa.hpp"
#include "base64.hpp"
#include "x509.hpp"
#include "tls_socket.hpp"

#include <cstdlib>
#include <cstring>
#include "jpssl_span.hpp"
#include <string>
#include <vector>
#include <memory>

using namespace jpssl;

/* ─────────────────────────────────────────────────────────────────────
 *  辅助
 * ───────────────────────────────────────────────────────────────────── */

static char* dup_str(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (!p) return nullptr;
    std::memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

extern "C" void jp_free(void* p) { std::free(p); }

extern "C" const char* jp_version(void) {
    return "jpssl 1.0.0 (iOS arm64 / ARMv8, Swift bridge)";
}

extern "C" int jp_secure_rand(uint8_t* out, size_t len) {
    try { return os_rand_bytes(out, len) ? 1 : 0; }
    catch (...) { return 0; }
}

/* ─────────────────────────────────────────────────────────────────────
 *  哈希
 * ───────────────────────────────────────────────────────────────────── */

extern "C" void jp_sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    jpssl::sha1_ctx c; sha1_init(&c);
    if (len) sha1_update(&c, data, len);
    sha1_final(&c, out);
}
struct jp_sha1_ctx { sha1_ctx c; };
extern "C" jp_sha1_ctx* jp_sha1_ctx_new(void) { return new jp_sha1_ctx(); }
extern "C" void jp_sha1_update(jp_sha1_ctx* c, const uint8_t* data, size_t len) { sha1_update(&c->c, data, len); }
extern "C" void jp_sha1_final(jp_sha1_ctx* c, uint8_t out[20]) { sha1_final(&c->c, out); }
extern "C" void jp_sha1_ctx_free(jp_sha1_ctx* c) { delete c; }

extern "C" void jp_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    jpssl::sha256_ctx c; sha256_init(&c);
    if (len) sha256_update(&c, data, len);
    sha256_final(&c, out);
}
struct jp_sha256_ctx { sha256_ctx c; };
extern "C" jp_sha256_ctx* jp_sha256_ctx_new(void) { return new jp_sha256_ctx(); }
extern "C" void jp_sha256_update(jp_sha256_ctx* c, const uint8_t* data, size_t len) { sha256_update(&c->c, data, len); }
extern "C" void jp_sha256_final(jp_sha256_ctx* c, uint8_t out[32]) { sha256_final(&c->c, out); }
extern "C" void jp_sha256_ctx_free(jp_sha256_ctx* c) { delete c; }

extern "C" void jp_sha384(const uint8_t* data, size_t len, uint8_t out[48]) {
    jpssl::sha512_ctx c; sha384_init(&c);
    if (len) sha512_update(&c, data, len);
    sha512_final(&c, out);
}
extern "C" void jp_sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
    jpssl::sha512_ctx c; sha512_init(&c);
    if (len) sha512_update(&c, data, len);
    sha512_final(&c, out);
}
struct jp_sha512_ctx { sha512_ctx c; };
extern "C" jp_sha512_ctx* jp_sha512_ctx_new(int is384) {
    auto* c = new jp_sha512_ctx();
    if (is384) sha384_init(&c->c); else sha512_init(&c->c);
    return c;
}
extern "C" void jp_sha512_update(jp_sha512_ctx* c, const uint8_t* data, size_t len) { sha512_update(&c->c, data, len); }
extern "C" void jp_sha512_final(jp_sha512_ctx* c, uint8_t* out) { sha512_final(&c->c, out); }
extern "C" void jp_sha512_ctx_free(jp_sha512_ctx* c) { delete c; }

extern "C" void jp_sha3_256(const uint8_t* data, size_t len, uint8_t out[32]) {
    jpssl::sha3_ctx c; sha3_256_init(&c);
    if (len) sha3_update(&c, data, len);
    sha3_final(&c, out);
}
extern "C" void jp_sha3_384(const uint8_t* data, size_t len, uint8_t out[48]) {
    jpssl::sha3_ctx c; sha3_384_init(&c);
    if (len) sha3_update(&c, data, len);
    sha3_final(&c, out);
}
extern "C" void jp_sha3_512(const uint8_t* data, size_t len, uint8_t out[64]) {
    jpssl::sha3_ctx c; sha3_512_init(&c);
    if (len) sha3_update(&c, data, len);
    sha3_final(&c, out);
}
struct jp_sha3_ctx { sha3_ctx c; };
extern "C" jp_sha3_ctx* jp_sha3_ctx_new(int variant) {
    auto* c = new jp_sha3_ctx();
    if (variant == 0) sha3_256_init(&c->c);
    else if (variant == 1) sha3_384_init(&c->c);
    else sha3_512_init(&c->c);
    return c;
}
extern "C" void jp_sha3_update(jp_sha3_ctx* c, const uint8_t* data, size_t len) { sha3_update(&c->c, data, len); }
extern "C" void jp_sha3_final(jp_sha3_ctx* c, uint8_t* out) { sha3_final(&c->c, out); }
extern "C" void jp_sha3_ctx_free(jp_sha3_ctx* c) { delete c; }

extern "C" void jp_shake128(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    shake128(in, in_len, out, out_len);
}
extern "C" void jp_shake256(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    shake256(in, in_len, out, out_len);
}
struct jp_shake_ctx { sha3_ctx c; };
extern "C" jp_shake_ctx* jp_shake_ctx_new(int is256) {
    auto* c = new jp_shake_ctx();
    if (is256) shake256_init(&c->c); else shake128_init(&c->c);
    return c;
}
extern "C" void jp_shake_update(jp_shake_ctx* c, const uint8_t* data, size_t len) { shake_update(&c->c, data, len); }
extern "C" void jp_shake_squeeze(jp_shake_ctx* c, uint8_t* out, size_t out_len) { shake_squeeze(&c->c, out, out_len); }
extern "C" void jp_shake_ctx_free(jp_shake_ctx* c) { delete c; }

extern "C" void jp_sm3(const uint8_t* data, size_t len, uint8_t out[32]) {
    jpssl::sm3_ctx c; sm3_init(&c);
    if (len) sm3_update(&c, data, len);
    sm3_final(&c, out);
}
struct jp_sm3_ctx { sm3_ctx c; };
extern "C" jp_sm3_ctx* jp_sm3_ctx_new(void) { auto* c = new jp_sm3_ctx(); sm3_init(&c->c); return c; }
extern "C" void jp_sm3_update(jp_sm3_ctx* c, const uint8_t* data, size_t len) { sm3_update(&c->c, data, len); }
extern "C" void jp_sm3_final(jp_sm3_ctx* c, uint8_t out[32]) { sm3_final(&c->c, out); }
extern "C" void jp_sm3_ctx_free(jp_sm3_ctx* c) { delete c; }

/* ─────────────────────────────────────────────────────────────────────
 *  HMAC / HKDF
 * ───────────────────────────────────────────────────────────────────── */

extern "C" void jp_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t mac[32]) {
    hmac_sha256(key, key_len, msg, msg_len, mac);
}
extern "C" void jp_hmac_sha384(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t mac[48]) {
    hmac_sha384(key, key_len, msg, msg_len, mac);
}
extern "C" void jp_hmac_sm3(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t mac[32]) {
    hmac_sm3(key, key_len, msg, msg_len, mac);
}

extern "C" void jp_hkdf_extract_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]) {
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
}
extern "C" void jp_hkdf_expand_sha256(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len) {
    hkdf_expand(prk, info, info_len, out, out_len);
}
extern "C" void jp_hkdf_extract_sha384(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[48]) {
    hkdf_extract_sha384(salt, salt_len, ikm, ikm_len, prk);
}
extern "C" void jp_hkdf_expand_sha384(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len) {
    hkdf_expand_sha384(prk, info, info_len, out, out_len);
}
extern "C" void jp_hkdf_extract_sm3(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]) {
    hkdf_extract_sm3(salt, salt_len, ikm, ikm_len, prk);
}
extern "C" void jp_hkdf_expand_sm3(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len) {
    hkdf_expand_sm3(prk, info, info_len, out, out_len);
}

/* ─────────────────────────────────────────────────────────────────────
 *  AES
 * ───────────────────────────────────────────────────────────────────── */

struct jp_aes_ctx { aes_context c; };
extern "C" jp_aes_ctx* jp_aes_init(const uint8_t* key, size_t key_len) {
    try {
        auto* c = new jp_aes_ctx();
        if (key_len == 16) c->c.init(jpssl::span<const uint8_t, 16>(key, 16));
        else if (key_len == 24) c->c.init(jpssl::span<const uint8_t, 24>(key, 24));
        else if (key_len == 32) c->c.init(jpssl::span<const uint8_t, 32>(key, 32));
        else { delete c; return nullptr; }
        return c;
    } catch (...) { return nullptr; }
}
extern "C" void jp_aes_free(jp_aes_ctx* c) { delete c; }
extern "C" void jp_aes_encrypt_block(jp_aes_ctx* c, const uint8_t in[16], uint8_t out[16]) { aes_encrypt_block(c->c, in, out); }
extern "C" void jp_aes_decrypt_block(jp_aes_ctx* c, const uint8_t in[16], uint8_t out[16]) { aes_decrypt_block(c->c, in, out); }
extern "C" int jp_aes_ecb_encrypt(jp_aes_ctx* c, const uint8_t* in, uint8_t* out, size_t len) {
    try { if (len % 16) return 0; aes_encrypt_ecb(c->c, jpssl::span<const uint8_t>(in, len), jpssl::span<uint8_t>(out, len)); return 1; }
    catch (...) { return 0; }
}
extern "C" int jp_aes_ecb_decrypt(jp_aes_ctx* c, const uint8_t* in, uint8_t* out, size_t len) {
    try { if (len % 16) return 0; aes_decrypt_ecb(c->c, jpssl::span<const uint8_t>(in, len), jpssl::span<uint8_t>(out, len)); return 1; }
    catch (...) { return 0; }
}
extern "C" int jp_aes_cbc_encrypt(jp_aes_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                                  uint8_t** out, size_t* out_len) {
    try {
        std::vector<uint8_t> ct;
        aes_cbc_encrypt(c->c, iv, jpssl::span<const uint8_t>(in, in_len), ct);
        uint8_t* p = static_cast<uint8_t*>(std::malloc(ct.size() ? ct.size() : 1));
        if (!p) return 0;
        std::memcpy(p, ct.data(), ct.size());
        *out = p; *out_len = ct.size();
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_aes_cbc_decrypt(jp_aes_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                                  uint8_t** out, size_t* out_len) {
    try {
        std::vector<uint8_t> pt;
        if (!aes_cbc_decrypt(c->c, iv, jpssl::span<const uint8_t>(in, in_len), pt)) return 0;
        uint8_t* p = static_cast<uint8_t*>(std::malloc(pt.size() ? pt.size() : 1));
        if (!p) return 0;
        std::memcpy(p, pt.data(), pt.size());
        *out = p; *out_len = pt.size();
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_aes_gcm_encrypt(jp_aes_ctx* c, const uint8_t* iv, size_t iv_len,
                                  const uint8_t* pt, size_t pt_len,
                                  const uint8_t* aad, size_t aad_len,
                                  uint8_t* ct, uint8_t* tag, size_t tag_len) {
    try {
        std::vector<uint8_t> ctv;
        aes_gcm_encrypt_auto(c->c, iv, iv_len,
                             jpssl::span<const uint8_t>(pt, pt_len),
                             jpssl::span<const uint8_t>(aad, aad_len),
                             ctv, tag, tag_len);
        std::memcpy(ct, ctv.data(), pt_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_aes_gcm_decrypt(jp_aes_ctx* c, const uint8_t* iv, size_t iv_len,
                                  const uint8_t* ct, size_t ct_len,
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* tag, size_t tag_len,
                                  uint8_t* pt) {
    try {
        std::vector<uint8_t> ptv;
        if (!aes_gcm_decrypt_auto(c->c, iv, iv_len,
                                  jpssl::span<const uint8_t>(ct, ct_len),
                                  jpssl::span<const uint8_t>(aad, aad_len),
                                  tag, tag_len, ptv)) return 0;
        std::memcpy(pt, ptv.data(), ct_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_aes_ccm_encrypt(jp_aes_ctx* c, const uint8_t* nonce, size_t nonce_len,
                                  const uint8_t* pt, size_t pt_len,
                                  const uint8_t* aad, size_t aad_len,
                                  uint8_t* ct, uint8_t* tag, size_t tag_len) {
    try {
        std::vector<uint8_t> ctv;
        aes_ccm_encrypt(c->c, nonce, nonce_len,
                        jpssl::span<const uint8_t>(pt, pt_len),
                        jpssl::span<const uint8_t>(aad, aad_len),
                        ctv, tag, tag_len);
        std::memcpy(ct, ctv.data(), pt_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_aes_ccm_decrypt(jp_aes_ctx* c, const uint8_t* nonce, size_t nonce_len,
                                  const uint8_t* ct, size_t ct_len,
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* tag, size_t tag_len,
                                  uint8_t* pt) {
    try {
        std::vector<uint8_t> ptv;
        if (!aes_ccm_decrypt(c->c, nonce, nonce_len,
                             jpssl::span<const uint8_t>(ct, ct_len),
                             jpssl::span<const uint8_t>(aad, aad_len),
                             tag, tag_len, ptv)) return 0;
        std::memcpy(pt, ptv.data(), ct_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" void jp_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) { gf128_mul(x, y, out); }
extern "C" void jp_ghash(const uint8_t H[16], const uint8_t* data, size_t len, uint8_t out[16]) {
    ghash(H, jpssl::span<const uint8_t>(data, len), out);
}
extern "C" void jp_gcm_ghash(const uint8_t H[16], const uint8_t* aad, size_t aad_len,
                             const uint8_t* data, size_t data_len, uint8_t out[16]) {
    gcm_ghash(H, jpssl::span<const uint8_t>(aad, aad_len), jpssl::span<const uint8_t>(data, data_len), out);
}

/* ─────────────────────────────────────────────────────────────────────
 *  ChaCha20-Poly1305
 * ───────────────────────────────────────────────────────────────────── */

extern "C" void jp_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t keystream[64]) {
    chacha20_block(key, counter, nonce, keystream);
}
extern "C" void jp_chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                                const uint8_t* in, uint8_t* out, size_t len) {
    chacha20_crypt(key, counter, nonce, jpssl::span<const uint8_t>(in, len), jpssl::span<uint8_t>(out, len));
}
extern "C" void jp_poly1305_mac(const uint8_t key[32], const uint8_t* msg, size_t msg_len, uint8_t tag[16]) {
    poly1305_mac(key, jpssl::span<const uint8_t>(msg, msg_len), tag);
}
extern "C" int jp_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                            const uint8_t* pt, size_t pt_len,
                                            const uint8_t* aad, size_t aad_len,
                                            uint8_t* ct, uint8_t tag[16]) {
    try {
        std::vector<uint8_t> ctv;
        chacha20_poly1305_encrypt(key, nonce,
                                  jpssl::span<const uint8_t>(pt, pt_len),
                                  jpssl::span<const uint8_t>(aad, aad_len),
                                  ctv, tag);
        std::memcpy(ct, ctv.data(), pt_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                            const uint8_t* ct, size_t ct_len,
                                            const uint8_t* aad, size_t aad_len,
                                            const uint8_t tag[16], uint8_t* pt) {
    try {
        std::vector<uint8_t> ptv;
        if (!chacha20_poly1305_decrypt(key, nonce,
                                       jpssl::span<const uint8_t>(ct, ct_len),
                                       jpssl::span<const uint8_t>(aad, aad_len),
                                       tag, ptv)) return 0;
        std::memcpy(pt, ptv.data(), ct_len);
        return 1;
    } catch (...) { return 0; }
}

/* ─────────────────────────────────────────────────────────────────────
 *  SM4
 * ───────────────────────────────────────────────────────────────────── */

struct jp_sm4_ctx { sm4_ctx c; };
extern "C" jp_sm4_ctx* jp_sm4_init(const uint8_t key[16]) {
    try { auto* c = new jp_sm4_ctx(); sm4_init(&c->c, key); return c; }
    catch (...) { return nullptr; }
}
extern "C" void jp_sm4_free(jp_sm4_ctx* c) { delete c; }
extern "C" void jp_sm4_encrypt_block(const jp_sm4_ctx* c, const uint8_t in[16], uint8_t out[16]) {
    sm4_encrypt_block(&c->c, in, out);
}
extern "C" void jp_sm4_decrypt_block(const jp_sm4_ctx* c, const uint8_t in[16], uint8_t out[16]) {
    sm4_decrypt_block(&c->c, in, out);
}
extern "C" int jp_sm4_cbc_encrypt(const jp_sm4_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                                  uint8_t** out, size_t* out_len) {
    try {
        auto ct = sm4_cbc_encrypt(&c->c, iv, jpssl::span<const uint8_t>(in, in_len));
        uint8_t* p = static_cast<uint8_t*>(std::malloc(ct.size() ? ct.size() : 1));
        if (!p) return 0;
        std::memcpy(p, ct.data(), ct.size());
        *out = p; *out_len = ct.size();
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_sm4_cbc_decrypt(const jp_sm4_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                                  uint8_t** out, size_t* out_len) {
    try {
        auto pt = sm4_cbc_decrypt(&c->c, iv, jpssl::span<const uint8_t>(in, in_len));
        uint8_t* p = static_cast<uint8_t*>(std::malloc(pt.size() ? pt.size() : 1));
        if (!p) return 0;
        std::memcpy(p, pt.data(), pt.size());
        *out = p; *out_len = pt.size();
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_sm4_gcm_encrypt(const jp_sm4_ctx* c, const uint8_t* iv, size_t iv_len,
                                  const uint8_t* pt, size_t pt_len,
                                  const uint8_t* aad, size_t aad_len,
                                  uint8_t* ct, uint8_t* tag, size_t tag_len) {
    try {
        std::vector<uint8_t> ctv;
        sm4_gcm_encrypt_auto(&c->c, iv, iv_len,
                             jpssl::span<const uint8_t>(pt, pt_len),
                             jpssl::span<const uint8_t>(aad, aad_len),
                             ctv, tag, tag_len);
        std::memcpy(ct, ctv.data(), pt_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_sm4_gcm_decrypt(const jp_sm4_ctx* c, const uint8_t* iv, size_t iv_len,
                                  const uint8_t* ct, size_t ct_len,
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* tag, size_t tag_len, uint8_t* pt) {
    try {
        std::vector<uint8_t> ptv;
        if (!sm4_gcm_decrypt_auto(&c->c, iv, iv_len,
                                  jpssl::span<const uint8_t>(ct, ct_len),
                                  jpssl::span<const uint8_t>(aad, aad_len),
                                  tag, tag_len, ptv)) return 0;
        std::memcpy(pt, ptv.data(), ct_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_sm4_ccm_encrypt(const jp_sm4_ctx* c, const uint8_t* nonce, size_t nonce_len,
                                  const uint8_t* pt, size_t pt_len,
                                  const uint8_t* aad, size_t aad_len,
                                  uint8_t* ct, uint8_t* tag, size_t tag_len) {
    try {
        std::vector<uint8_t> ctv;
        sm4_ccm_encrypt(&c->c, nonce, nonce_len,
                        jpssl::span<const uint8_t>(pt, pt_len),
                        jpssl::span<const uint8_t>(aad, aad_len),
                        ctv, tag, tag_len);
        std::memcpy(ct, ctv.data(), pt_len);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_sm4_ccm_decrypt(const jp_sm4_ctx* c, const uint8_t* nonce, size_t nonce_len,
                                  const uint8_t* ct, size_t ct_len,
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* tag, size_t tag_len, uint8_t* pt) {
    try {
        std::vector<uint8_t> ptv;
        if (!sm4_ccm_decrypt(&c->c, nonce, nonce_len,
                             jpssl::span<const uint8_t>(ct, ct_len),
                             jpssl::span<const uint8_t>(aad, aad_len),
                             tag, tag_len, ptv)) return 0;
        std::memcpy(pt, ptv.data(), ct_len);
        return 1;
    } catch (...) { return 0; }
}

/* ─────────────────────────────────────────────────────────────────────
 *  X25519 / X448
 * ───────────────────────────────────────────────────────────────────── */

extern "C" void jp_x25519_generate_keypair(uint8_t pub[32], uint8_t priv[32]) { x25519_generate_keypair(pub, priv); }
extern "C" void jp_x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) { x25519_scalar_mult(out, scalar, point); }
extern "C" void jp_x448_generate_keypair(uint8_t pub[56], uint8_t priv[56]) { x448_generate_keypair(pub, priv); }
extern "C" void jp_x448_scalar_mult(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]) { x448_scalar_mult(out, scalar, point); }

/* ─────────────────────────────────────────────────────────────────────
 *  Ed25519 / Ed448
 * ───────────────────────────────────────────────────────────────────── */

extern "C" void jp_ed25519_keygen(uint8_t pub[32], uint8_t priv[64]) { ed25519_keygen(pub, priv); }
extern "C" void jp_ed25519_derive_public_key(const uint8_t seed[32], uint8_t pub[32]) { ed25519_derive_public_key(seed, pub); }
extern "C" void jp_ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]) {
    ed25519_sign(priv, msg, msg_len, sig);
}
extern "C" int jp_ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]) {
    return ed25519_verify(pub, msg, msg_len, sig) ? 1 : 0;
}
extern "C" void jp_ed448_keygen(uint8_t pub[57], uint8_t priv[114]) { ed448_generate_keypair(pub, priv); }
extern "C" void jp_ed448_sign(const uint8_t priv[114], const uint8_t* msg, size_t msg_len, uint8_t sig[114]) {
    ed448_sign(priv, msg, msg_len, sig);
}
extern "C" int jp_ed448_verify(const uint8_t pub[57], const uint8_t* msg, size_t msg_len, const uint8_t sig[114]) {
    return ed448_verify(pub, msg, msg_len, sig) ? 1 : 0;
}

/* ─────────────────────────────────────────────────────────────────────
 *  ECDSA P-256 / P-384 / P-521
 * ───────────────────────────────────────────────────────────────────── */

extern "C" void jp_ecdsa_p256_keygen(uint8_t pub[64], uint8_t priv[32]) { ecdsa_p256_keygen(pub, priv); }
extern "C" void jp_ecdsa_p256_sign(const uint8_t priv[32], const uint8_t* msg, size_t msg_len, uint8_t sig[64]) {
    ecdsa_p256_sign(priv, msg, msg_len, sig);
}
extern "C" int jp_ecdsa_p256_verify(const uint8_t pub[64], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]) {
    return ecdsa_p256_verify(pub, msg, msg_len, sig) ? 1 : 0;
}
extern "C" int jp_ecdsa_p256_ecdh(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[64]) {
    return ecdsa_p256_ecdh(shared, priv, pub) ? 1 : 0;
}
extern "C" void jp_ecdsa_p384_keygen(uint8_t pub[96], uint8_t priv[48]) { ecdsa_p384_keygen(pub, priv); }
extern "C" void jp_ecdsa_p384_sign(const uint8_t priv[48], const uint8_t* msg, size_t msg_len, uint8_t sig[96]) {
    ecdsa_p384_sign(priv, msg, msg_len, sig);
}
extern "C" int jp_ecdsa_p384_verify(const uint8_t pub[96], const uint8_t* msg, size_t msg_len, const uint8_t sig[96]) {
    return ecdsa_p384_verify(pub, msg, msg_len, sig) ? 1 : 0;
}
extern "C" int jp_ecdsa_p384_ecdh(uint8_t shared[48], const uint8_t priv[48], const uint8_t pub[96]) {
    return ecdsa_p384_ecdh(shared, priv, pub) ? 1 : 0;
}
extern "C" void jp_ecdsa_p521_keygen(uint8_t pub[132], uint8_t priv[66]) { ecdsa_p521_keygen(pub, priv); }
extern "C" void jp_ecdsa_p521_sign(const uint8_t priv[66], const uint8_t* msg, size_t msg_len, uint8_t sig[132]) {
    ecdsa_p521_sign(priv, msg, msg_len, sig);
}
extern "C" int jp_ecdsa_p521_verify(const uint8_t pub[132], const uint8_t* msg, size_t msg_len, const uint8_t sig[132]) {
    return ecdsa_p521_verify(pub, msg, msg_len, sig) ? 1 : 0;
}

/* ─────────────────────────────────────────────────────────────────────
 *  SM2
 * ───────────────────────────────────────────────────────────────────── */

extern "C" void jp_sm2_keygen(uint8_t pub[64], uint8_t priv[32]) { sm2_keygen(pub, priv); }
extern "C" void jp_sm2_pub_from_priv(const uint8_t priv[32], uint8_t pub[64]) { sm2_pub_from_priv(priv, pub); }
extern "C" void jp_sm2_sign(const uint8_t priv[32], const uint8_t* msg, size_t msg_len,
                            const uint8_t za[32], uint8_t sig[64]) {
    sm2_sign(priv, msg, msg_len, sig, za);
}
extern "C" int jp_sm2_verify(const uint8_t pub[64], const uint8_t* msg, size_t msg_len,
                             const uint8_t za[32], const uint8_t sig[64]) {
    return sm2_verify(pub, msg, msg_len, sig, za) ? 1 : 0;
}
extern "C" void jp_sm2_compute_za(const uint8_t* id, size_t id_len,
                                  const uint8_t pub_x[32], const uint8_t pub_y[32], uint8_t za[32]) {
    sm2_compute_za(id, id_len, pub_x, pub_y, za);
}
extern "C" int jp_sm2_ecdh(uint8_t shared[32], const uint8_t priv[32], const uint8_t* peer_pub, size_t peer_pub_len) {
    return sm2_ecdh(shared, priv, peer_pub, peer_pub_len) ? 1 : 0;
}

/* ─────────────────────────────────────────────────────────────────────
 *  RSA-2048 / RSA-4096
 * ───────────────────────────────────────────────────────────────────── */

static jpssl::rsa_bignum bn(const uint8_t* buf) { return jpssl::rsa_bignum::from_bytes(buf, 256); }
static jpssl::rsa4096_bignum bn4096(const uint8_t* buf) { return jpssl::rsa4096_bignum::from_bytes(buf, 512); }
static void put_bn(const jpssl::rsa_bignum& b, uint8_t* buf) { b.to_bytes(buf); }
static void put_bn4096(const jpssl::rsa4096_bignum& b, uint8_t* buf) { b.to_bytes(buf); }

static jpssl::rsa_public_key to_pub(const jp_rsa_pub* p) {
    jpssl::rsa_public_key k;
    k.n = bn(p->n); k.e = bn(p->e);
    return k;
}
static jpssl::rsa_private_key to_priv(const jp_rsa_priv* p) {
    jpssl::rsa_private_key k;
    k.n = bn(p->n); k.d = bn(p->d); k.e = bn(p->e);
    k.p = bn(p->p); k.q = bn(p->q);
    k.dP = bn(p->dP); k.dQ = bn(p->dQ); k.qInv = bn(p->qInv);
    return k;
}
static jpssl::rsa_crt_key to_crt(const jp_rsa_priv* p) {
    jpssl::rsa_crt_key k;
    k.n = bn(p->n); k.e = bn(p->e); k.d = bn(p->d);
    k.p = bn(p->p); k.q = bn(p->q);
    k.dP = bn(p->dP); k.dQ = bn(p->dQ); k.qInv = bn(p->qInv);
    return k;
}
static jpssl::rsa4096_public_key to_pub4096(const jp_rsa4096_pub* p) {
    jpssl::rsa4096_public_key k;
    k.n = bn4096(p->n); k.e = bn4096(p->e);
    return k;
}
static jpssl::rsa4096_private_key to_priv4096(const jp_rsa4096_priv* p) {
    jpssl::rsa4096_private_key k;
    k.n = bn4096(p->n); k.d = bn4096(p->d); k.e = bn4096(p->e);
    k.p = bn4096(p->p); k.q = bn4096(p->q);
    k.dP = bn4096(p->dP); k.dQ = bn4096(p->dQ); k.qInv = bn4096(p->qInv);
    return k;
}
static jpssl::rsa4096_crt_key to_crt4096(const jp_rsa4096_priv* p) {
    jpssl::rsa4096_crt_key k;
    k.n = bn4096(p->n); k.e = bn4096(p->e); k.d = bn4096(p->d);
    k.p = bn4096(p->p); k.q = bn4096(p->q);
    k.dP = bn4096(p->dP); k.dQ = bn4096(p->dQ); k.qInv = bn4096(p->qInv);
    return k;
}

extern "C" int jp_rsa2048_keygen(jp_rsa_pub* pub, jp_rsa_priv* priv) {
    try {
        jpssl::rsa_public_key p; jpssl::rsa_private_key q;
        if (!rsa_keygen(p, q)) return 0;
        put_bn(p.n, pub->n); put_bn(p.e, pub->e);
        put_bn(q.n, priv->n); put_bn(q.d, priv->d); put_bn(q.e, priv->e);
        put_bn(q.p, priv->p); put_bn(q.q, priv->q);
        put_bn(q.dP, priv->dP); put_bn(q.dQ, priv->dQ); put_bn(q.qInv, priv->qInv);
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_rsa4096_keygen(jp_rsa4096_pub* pub, jp_rsa4096_priv* priv) {
    try {
        jpssl::rsa4096_public_key p; jpssl::rsa4096_private_key q;
        if (!rsa4096_keygen(p, q)) return 0;
        put_bn4096(p.n, pub->n); put_bn4096(p.e, pub->e);
        put_bn4096(q.n, priv->n); put_bn4096(q.d, priv->d); put_bn4096(q.e, priv->e);
        put_bn4096(q.p, priv->p); put_bn4096(q.q, priv->q);
        put_bn4096(q.dP, priv->dP); put_bn4096(q.dQ, priv->dQ); put_bn4096(q.qInv, priv->qInv);
        return 1;
    } catch (...) { return 0; }
}

/* 左补零大端导入：小整数（如 e=65537）无需补足 256/512 字节 */
static int store_bn(const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_len) {
    if (src_len > dst_len) return 0;
    std::memset(dst, 0, dst_len);
    std::memcpy(dst + (dst_len - src_len), src, src_len);
    return 1;
}
extern "C" int jp_rsa2048_pub_from_bytes(jp_rsa_pub* pub, const uint8_t* n, size_t n_len,
                                         const uint8_t* e, size_t e_len) {
    return store_bn(n, n_len, pub->n, 256) && store_bn(e, e_len, pub->e, 256);
}
extern "C" int jp_rsa2048_priv_from_bytes(jp_rsa_priv* priv, const uint8_t* n, size_t n_len,
                                          const uint8_t* d, size_t d_len) {
    return store_bn(n, n_len, priv->n, 256) && store_bn(d, d_len, priv->d, 256);
}
extern "C" int jp_rsa4096_pub_from_bytes(jp_rsa4096_pub* pub, const uint8_t* n, size_t n_len,
                                         const uint8_t* e, size_t e_len) {
    return store_bn(n, n_len, pub->n, 512) && store_bn(e, e_len, pub->e, 512);
}
extern "C" int jp_rsa4096_priv_from_bytes(jp_rsa4096_priv* priv, const uint8_t* n, size_t n_len,
                                          const uint8_t* d, size_t d_len) {
    return store_bn(n, n_len, priv->n, 512) && store_bn(d, d_len, priv->d, 512);
}

extern "C" int jp_rsa2048_encrypt(const jp_rsa_pub* pub, const uint8_t* msg, size_t msg_len, uint8_t ct[256]) {
    try { rsa_encrypt(to_pub(pub), jpssl::span<const uint8_t>(msg, msg_len), ct); return 1; }
    catch (...) { return 0; }
}
extern "C" int jp_rsa2048_decrypt(const jp_rsa_priv* priv, const uint8_t ct[256], uint8_t** out, size_t* out_len) {
    try {
        std::vector<uint8_t> pt;
        if (!rsa_decrypt(to_priv(priv), ct, pt)) return 0;
        uint8_t* p = static_cast<uint8_t*>(std::malloc(pt.size() ? pt.size() : 1));
        if (!p) return 0;
        std::memcpy(p, pt.data(), pt.size());
        *out = p; *out_len = pt.size();
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_rsa4096_encrypt(const jp_rsa4096_pub* pub, const uint8_t* msg, size_t msg_len, uint8_t ct[512]) {
    try { rsa4096_encrypt(to_pub4096(pub), jpssl::span<const uint8_t>(msg, msg_len), ct); return 1; }
    catch (...) { return 0; }
}
extern "C" int jp_rsa4096_decrypt(const jp_rsa4096_priv* priv, const uint8_t ct[512], uint8_t** out, size_t* out_len) {
    try {
        std::vector<uint8_t> pt;
        if (!rsa4096_decrypt(to_priv4096(priv), ct, pt)) return 0;
        uint8_t* p = static_cast<uint8_t*>(std::malloc(pt.size() ? pt.size() : 1));
        if (!p) return 0;
        std::memcpy(p, pt.data(), pt.size());
        *out = p; *out_len = pt.size();
        return 1;
    } catch (...) { return 0; }
}

extern "C" int jp_rsa2048_oaep_encrypt(const jp_rsa_pub* pub, const uint8_t* msg, size_t msg_len, uint8_t ct[256]) {
    try { return rsaes_oaep_encrypt(to_pub(pub), jpssl::span<const uint8_t>(msg, msg_len), nullptr, 0, ct) ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_rsa2048_oaep_decrypt(const jp_rsa_priv* priv, const uint8_t ct[256], uint8_t** out, size_t* out_len) {
    try {
        std::vector<uint8_t> pt;
        if (!rsaes_oaep_decrypt(to_crt(priv), ct, nullptr, 0, pt)) return 0;
        uint8_t* p = static_cast<uint8_t*>(std::malloc(pt.size() ? pt.size() : 1));
        if (!p) return 0;
        std::memcpy(p, pt.data(), pt.size());
        *out = p; *out_len = pt.size();
        return 1;
    } catch (...) { return 0; }
}

static jpssl::PssHash to_hash(int h) {
    return h == 1 ? jpssl::PssHash::SHA384 : (h == 2 ? jpssl::PssHash::SHA512 : jpssl::PssHash::SHA256);
}
extern "C" int jp_rsa2048_pss_sign(const jp_rsa_priv* priv, const uint8_t* msg, size_t msg_len, int hash, uint8_t sig[256]) {
    try { return rsassa_pss_sign(to_crt(priv), msg, msg_len, sig, 0, to_hash(hash)) ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_rsa2048_pss_verify(const jp_rsa_pub* pub, const uint8_t* msg, size_t msg_len, int hash, const uint8_t sig[256]) {
    try { return rsassa_pss_verify(to_pub(pub), msg, msg_len, sig, 0, to_hash(hash)) ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_rsa4096_pss_sign(const jp_rsa4096_priv* priv, const uint8_t* msg, size_t msg_len, int hash, uint8_t sig[512]) {
    try { return rsassa_pss_sign4096(to_crt4096(priv), msg, msg_len, sig, 0, to_hash(hash)) ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_rsa4096_pss_verify(const jp_rsa4096_pub* pub, const uint8_t* msg, size_t msg_len, int hash, const uint8_t sig[512]) {
    try { return rsassa_pss_verify4096(to_pub4096(pub), msg, msg_len, sig, 0, to_hash(hash)) ? 1 : 0; }
    catch (...) { return 0; }
}

extern "C" int jp_rsa2048_pkcs1_sign(const jp_rsa_priv* priv, const uint8_t* digest, size_t digest_len,
                                     const uint8_t* digest_prefix, size_t prefix_len, uint8_t sig[256]) {
    try { return rsassa_pkcs1v15_sign(to_crt(priv), digest, digest_len, digest_prefix, prefix_len, sig) ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_rsa2048_pkcs1_verify(const jp_rsa_pub* pub, const uint8_t* digest, size_t digest_len,
                                       const uint8_t* digest_prefix, size_t prefix_len, const uint8_t sig[256]) {
    try { return rsassa_pkcs1v15_verify(to_pub(pub), digest, digest_len, digest_prefix, prefix_len, sig) ? 1 : 0; }
    catch (...) { return 0; }
}

/* ─────────────────────────────────────────────────────────────────────
 *  X.509
 * ───────────────────────────────────────────────────────────────────── */

struct jp_x509_cert { x509::x509_cert c; };

extern "C" jp_x509_cert* jp_x509_cert_from_der(const uint8_t* der, size_t len) {
    try {
        auto cert = x509::x509_cert::from_der(der, len);
        if (!cert) return nullptr;
        auto* c = new jp_x509_cert();
        c->c = std::move(*cert);
        return c;
    } catch (...) { return nullptr; }
}
extern "C" jp_x509_cert* jp_x509_cert_from_pem(const char* pem, size_t len) {
    try {
        auto cert = x509::x509_cert::from_pem(pem, len);
        if (!cert) return nullptr;
        auto* c = new jp_x509_cert();
        c->c = std::move(*cert);
        return c;
    } catch (...) { return nullptr; }
}
extern "C" int jp_x509_cert_to_der(const jp_x509_cert* c, uint8_t** out, size_t* out_len) {
    try {
        auto der = c->c.to_der();
        uint8_t* p = static_cast<uint8_t*>(std::malloc(der.size() ? der.size() : 1));
        if (!p) return 0;
        std::memcpy(p, der.data(), der.size());
        *out = p; *out_len = der.size();
        return 1;
    } catch (...) { return 0; }
}
extern "C" char* jp_x509_cert_to_pem(const jp_x509_cert* c) {
    try { return dup_str(c->c.to_pem()); }
    catch (...) { return nullptr; }
}
extern "C" char* jp_x509_common_name(const jp_x509_cert* c) {
    try { return dup_str(c->c.common_name()); }
    catch (...) { return nullptr; }
}
extern "C" char* jp_x509_issuer_name(const jp_x509_cert* c) {
    try { return dup_str(c->c.issuer_name()); }
    catch (...) { return nullptr; }
}
extern "C" int jp_x509_is_valid_now(const jp_x509_cert* c) {
    try { return c->c.is_valid_now() ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_x509_is_valid_at(const jp_x509_cert* c, uint64_t now_unix) {
    try { return c->c.is_valid_at(now_unix) ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_x509_is_ca(const jp_x509_cert* c) {
    try { return c->c.is_ca() ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" int jp_x509_verify_signature(const jp_x509_cert* c, const jp_x509_cert* issuer) {
    try { return c->c.verify_signature(issuer->c) ? 1 : 0; }
    catch (...) { return 0; }
}
extern "C" void jp_x509_cert_free(jp_x509_cert* c) { delete c; }

extern "C" int jp_x509_parse_private_key(const char* pem, size_t len,
                                         uint8_t** priv, size_t* priv_len,
                                         uint8_t** pub, size_t* pub_len) {
    try {
        auto k = x509::private_key::from_pem(pem, len);
        if (!k) return JP_KEY_UNKNOWN;
        uint8_t* p = static_cast<uint8_t*>(std::malloc(k->priv.size() ? k->priv.size() : 1));
        if (!p) return JP_KEY_UNKNOWN;
        std::memcpy(p, k->priv.data(), k->priv.size());
        *priv = p; *priv_len = k->priv.size();
        if (pub && pub_len) {
            uint8_t* q = static_cast<uint8_t*>(std::malloc(k->pub.size() ? k->pub.size() : 1));
            if (q) { std::memcpy(q, k->pub.data(), k->pub.size()); *pub = q; *pub_len = k->pub.size(); }
            else { *pub = nullptr; *pub_len = 0; }
        }
        return static_cast<int>(k->key_type);
    } catch (...) { return JP_KEY_UNKNOWN; }
}

/* ─────────────────────────────────────────────────────────────────────
 *  TLS 1.3（高层连接封装）
 * ───────────────────────────────────────────────────────────────────── */

struct jp_tls_conn { jpssl::tls::tls_connection conn; };

extern "C" jp_tls_conn* jp_tls_conn_new(void) {
    try { return new jp_tls_conn(); }
    catch (...) { return nullptr; }
}
extern "C" int jp_tls_client_connect(jp_tls_conn* c, const char* host, uint16_t port, char** err) {
    try {
        std::string errs;
        if (!c->conn.connect(host, port, nullptr, &errs)) {
            if (err) *err = dup_str(errs);
            return 0;
        }
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_tls_send(jp_tls_conn* c, const uint8_t* data, size_t len, char** err) {
    try {
        std::string errs;
        if (!c->conn.send(data, len, &errs)) {
            if (err) *err = dup_str(errs);
            return 0;
        }
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_tls_recv(jp_tls_conn* c, uint8_t** data, size_t* len, char** err) {
    try {
        std::vector<uint8_t> out;
        std::string errs;
        if (!c->conn.recv(out, &errs)) {
            if (err) *err = dup_str(errs);
            return 0;
        }
        uint8_t* p = static_cast<uint8_t*>(std::malloc(out.size() ? out.size() : 1));
        if (!p) return 0;
        std::memcpy(p, out.data(), out.size());
        *data = p; *len = out.size();
        return 1;
    } catch (...) { return 0; }
}
extern "C" void jp_tls_close(jp_tls_conn* c) {
    try { c->conn.close(); } catch (...) {}
}
extern "C" void jp_tls_conn_free(jp_tls_conn* c) { delete c; }

/* ─────────────────────────────────────────────────────────────────────
 *  Base64
 * ───────────────────────────────────────────────────────────────────── */

extern "C" int jp_base64_encode(const uint8_t* data, size_t len, char** out) {
    try {
        auto s = base64_encode(data, len);
        char* p = static_cast<char*>(std::malloc(s.size() + 1));
        if (!p) return 0;
        std::memcpy(p, s.c_str(), s.size() + 1);
        *out = p;
        return 1;
    } catch (...) { return 0; }
}
extern "C" int jp_base64_decode(const char* b64, size_t len, uint8_t** out, size_t* out_len) {
    try {
        auto dec = base64_decode(std::string(b64, len));
        if (!dec) return 0;
        uint8_t* p = static_cast<uint8_t*>(std::malloc(dec->size() ? dec->size() : 1));
        if (!p) return 0;
        std::memcpy(p, dec->data(), dec->size());
        *out = p; *out_len = dec->size();
        return 1;
    } catch (...) { return 0; }
}
