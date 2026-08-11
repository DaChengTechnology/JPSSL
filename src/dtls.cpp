/**
 * dtls.cpp - DTLS 1.2 (RFC 6347) / DTLS 1.3 (RFC 9147) implementation.
 *
 * Reuses the library crypto primitives (AES-GCM / ChaCha20 / HKDF / HMAC /
 * X25519 / P-256 / X448 / x509) to implement standard DTLS without OpenSSL.
 */
#include "jpssl_memory.hpp"
#include "dtls.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "hmac.hpp"
#include "hkdf.hpp"
#include "rand_os.hpp"
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdio>
#include <mutex>
#include <functional>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#endif

namespace jpssl {
namespace dtls {

using jpssl::tls::CipherSuite;
using jpssl::tls::NamedGroup;
using jpssl::tls::SignatureAlgorithm;
using jpssl::tls::tls_certificate;
using jpssl::tls::tls_certificate_manager;
using jpssl::tls::tls_trust_store;
using jpssl::x509::KeyType;

// ---- basic helpers -------------------------------------------------------
static void rand_bytes(uint8_t* buf, size_t n) {
    if (!jpssl::os_rand_bytes(buf, n)) std::memset(buf, 0, n);
}

static void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)x);
}
static void put24(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((uint8_t)(x >> 16)); v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)x);
}
static void put64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 7; i >= 0; --i) v.push_back((uint8_t)(x >> (8 * i)));
}
static uint16_t get16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get24(const uint8_t* p) { return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2]; }
static uint64_t get48(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 6; ++i) v = (v << 8) | p[i]; return v; }

static size_t suite_hash_len(CipherSuite cs) { return jpssl::tls::tls_use_sha384(cs) ? 48 : 32; }
static bool suite_use_sha384(CipherSuite cs) { return jpssl::tls::tls_use_sha384(cs); }
static size_t suite_key_len(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_256_GCM_SHA384:
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return 32;
        default:
            return 16;
    }
}
static size_t dtls12_iv_len(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return 12;
        default:
            return 4;
    }
}
static bool suite_is_chacha20(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return true;
        default:
            return false;
    }
}

static CipherSuite select_cipher_suite(uint16_t id) {
    switch (id) {
        case 0x1301: return CipherSuite::TLS_AES_128_GCM_SHA256;
        case 0x1302: return CipherSuite::TLS_AES_256_GCM_SHA384;
        case 0x1303: return CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        case 0xC02B: return CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        case 0xC02F: return CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        case 0xCCA9: return CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
        case 0xCCA8: return CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
        default: return CipherSuite::TLS_AES_128_GCM_SHA256;
    }
}

// ---- key derivation -----------------------------------------------------
// TLS 1.2 PRF (P_SHA256 / P_SHA384) used by the DTLS 1.2 key schedule.
static void prf12(const uint8_t* secret, size_t secret_len, const char* label,
                  const uint8_t* seed, size_t seed_len,
                  uint8_t* out, size_t out_len, bool sha384) {
    std::vector<uint8_t> lseed;
    lseed.insert(lseed.end(), label, label + strlen(label));
    lseed.insert(lseed.end(), seed, seed + seed_len);
    if (sha384) {
        uint8_t a[48];
        hmac_sha384(secret, secret_len, lseed.data(), lseed.size(), a);
        size_t pos = 0;
        while (pos < out_len) {
            std::vector<uint8_t> in;
            in.insert(in.end(), a, a + 48);
            in.insert(in.end(), lseed.begin(), lseed.end());
            uint8_t b[48];
            hmac_sha384(secret, secret_len, in.data(), in.size(), b);
            size_t n = std::min<size_t>(48, out_len - pos);
            memcpy(out + pos, b, n); pos += n;
            hmac_sha384(secret, secret_len, a, 48, a);
        }
    } else {
        uint8_t a[32];
        hmac_sha256(secret, secret_len, lseed.data(), lseed.size(), a);
        size_t pos = 0;
        while (pos < out_len) {
            std::vector<uint8_t> in;
            in.insert(in.end(), a, a + 32);
            in.insert(in.end(), lseed.begin(), lseed.end());
            uint8_t b[32];
            hmac_sha256(secret, secret_len, in.data(), in.size(), b);
            size_t n = std::min<size_t>(32, out_len - pos);
            memcpy(out + pos, b, n); pos += n;
            hmac_sha256(secret, secret_len, a, 32, a);
        }
    }
}

// DTLS 1.3 HKDF-Expand-Label: label prefix "dtls13" (no trailing space, RFC 9147 5.9)
static void expand_label13(const uint8_t* secret, const char* label,
                           const uint8_t* ctx, size_t ctx_len,
                           uint8_t* out, size_t out_len, bool sha384) {
    uint8_t info[256]; size_t pos = 0;
    info[pos++] = (uint8_t)(out_len >> 8); info[pos++] = (uint8_t)out_len;
    const char* prefix = "dtls13";
    size_t pl = strlen(prefix) + strlen(label);
    info[pos++] = (uint8_t)pl;
    memcpy(info + pos, prefix, strlen(prefix)); pos += strlen(prefix);
    memcpy(info + pos, label, strlen(label)); pos += strlen(label);
    info[pos++] = (uint8_t)ctx_len;
    if (ctx_len) { memcpy(info + pos, ctx, ctx_len); pos += ctx_len; }
    if (sha384) hkdf_expand_sha384(secret, info, pos, out, out_len);
    else hkdf_expand(secret, info, pos, out, out_len);
}

// transcript
static void transcript_reset(dtls_session& s) { s.transcript_buf.clear(); s.transcript_valid = false; }
static void transcript_add(dtls_session& s, const uint8_t* msg, size_t len) {
    s.transcript_buf.insert(s.transcript_buf.end(), msg, msg + len);
}
static void transcript_add(dtls_session& s, const std::vector<uint8_t>& v) {
    transcript_add(s, v.data(), v.size());
}
static void transcript_compute(dtls_session& s) {
    if (suite_use_sha384(s.cipher_suite)) {
        sha512_ctx ctx; sha384_init(&ctx);
        sha512_update(&ctx, s.transcript_buf.data(), s.transcript_buf.size());
        sha512_final(&ctx, s.transcript_hash);
    } else {
        sha256_ctx ctx; sha256_init(&ctx);
        sha256_update(&ctx, s.transcript_buf.data(), s.transcript_buf.size());
        sha256_final(&ctx, s.transcript_hash);
    }
    s.transcript_valid = true;
}

static void dtls12_derive_keys(dtls_session& s, const uint8_t* premaster, size_t pm_len) {
    bool sha384 = suite_use_sha384(s.cipher_suite);
    uint8_t seed[64];
    memcpy(seed, s.client_random, 32);
    memcpy(seed + 32, s.server_random, 32);
    prf12(premaster, pm_len, "master secret", seed, 64, s.master_secret, 48, sha384);
    uint8_t seed2[64];
    memcpy(seed2, s.server_random, 32);
    memcpy(seed2 + 32, s.client_random, 32);
    size_t kl = suite_key_len(s.cipher_suite);
    size_t il = dtls12_iv_len(s.cipher_suite);
    s.key_len = kl; s.iv_len = il;
    std::vector<uint8_t> kb(2 * kl + 2 * il);
    prf12(s.master_secret, 48, "key expansion", seed2, 64, kb.data(), kb.size(), sha384);
    memcpy(s.client_write_key, kb.data(), kl);
    memcpy(s.server_write_key, kb.data() + kl, kl);
    memcpy(s.client_write_iv, kb.data() + 2 * kl, il);
    memcpy(s.server_write_iv, kb.data() + 2 * kl + il, il);
}

// DTLS 1.3 handshake traffic secrets (transcript must contain CH + SH)
static void dtls13_derive_handshake(dtls_session& s, const uint8_t* shared_secret, size_t shared_len) {
    bool sha384 = suite_use_sha384(s.cipher_suite);
    size_t hl = suite_hash_len(s.cipher_suite);
    uint8_t zero[48] = {}, early_secret[48], empty_hash[48];
    if (sha384) {
        sha512_ctx ctx; sha384_init(&ctx); sha512_final(&ctx, empty_hash);
        hkdf_extract_sha384(zero, 48, zero, 48, early_secret);
        // RFC 8446 7.1（RFC 9147 5.9 沿用）：Handshake Secret =
        // HKDF-Extract(Derive-Secret(Early Secret, "derived", Hash("")), ECDHE)
        uint8_t derived[48];
        expand_label13(early_secret, "derived", empty_hash, hl, derived, hl, true);
        hkdf_extract_sha384(derived, 48, shared_secret, shared_len, s.handshake_secret);
    } else {
        sha256_ctx ctx; sha256_init(&ctx); sha256_final(&ctx, empty_hash);
        hkdf_extract(zero, 32, zero, 32, early_secret);
        uint8_t derived[32];
        expand_label13(early_secret, "derived", empty_hash, hl, derived, hl, false);
        hkdf_extract(derived, 32, shared_secret, shared_len, s.handshake_secret);
    }
    transcript_compute(s);
    if (sha384) {
        expand_label13(s.handshake_secret, "c hs traffic", s.transcript_hash, hl, s.client_hs_traffic, hl, true);
        expand_label13(s.handshake_secret, "s hs traffic", s.transcript_hash, hl, s.server_hs_traffic, hl, true);
    } else {
        expand_label13(s.handshake_secret, "c hs traffic", s.transcript_hash, hl, s.client_hs_traffic, hl, false);
        expand_label13(s.handshake_secret, "s hs traffic", s.transcript_hash, hl, s.server_hs_traffic, hl, false);
    }
}

// DTLS 1.3 application traffic secrets (transcript must contain up to server Finished)
static void dtls13_derive_application(dtls_session& s) {
    bool sha384 = suite_use_sha384(s.cipher_suite);
    size_t hl = suite_hash_len(s.cipher_suite);
    uint8_t zero[48] = {}, empty_hash[48];
    if (sha384) {
        sha512_ctx ctx; sha384_init(&ctx); sha512_final(&ctx, empty_hash);
        uint8_t derived[48];
        expand_label13(s.handshake_secret, "derived", empty_hash, hl, derived, hl, true);
        hkdf_extract_sha384(derived, 48, zero, 48, s.master_secret);
    } else {
        sha256_ctx ctx; sha256_init(&ctx); sha256_final(&ctx, empty_hash);
        uint8_t derived[32];
        expand_label13(s.handshake_secret, "derived", empty_hash, hl, derived, hl, false);
        hkdf_extract(derived, 32, zero, 32, s.master_secret);
    }
    transcript_compute(s);
    if (sha384) {
        expand_label13(s.master_secret, "c ap traffic", s.transcript_hash, hl, s.client_app_traffic, hl, true);
        expand_label13(s.master_secret, "s ap traffic", s.transcript_hash, hl, s.server_app_traffic, hl, true);
    } else {
        expand_label13(s.master_secret, "c ap traffic", s.transcript_hash, hl, s.client_app_traffic, hl, false);
        expand_label13(s.master_secret, "s ap traffic", s.transcript_hash, hl, s.server_app_traffic, hl, false);
    }
}

static void dtls13_record_keys(CipherSuite cs, const uint8_t* traffic, bool sha384,
                               uint8_t key[32], size_t& key_len, uint8_t iv[12],
                               uint8_t sn[32]) {
    key_len = suite_key_len(cs);
    if (sha384) {
        expand_label13(traffic, "key", nullptr, 0, key, key_len, true);
        expand_label13(traffic, "iv", nullptr, 0, iv, 12, true);
        expand_label13(traffic, "sn", nullptr, 0, sn, key_len, true);
    } else {
        expand_label13(traffic, "key", nullptr, 0, key, key_len, false);
        expand_label13(traffic, "iv", nullptr, 0, iv, 12, false);
        expand_label13(traffic, "sn", nullptr, 0, sn, key_len, false);
    }
}

// ---- AEAD ----------------------------------------------------------------
static bool aead_encrypt(CipherSuite cs, const uint8_t* key, size_t key_len,
                         const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                         const uint8_t* pt, size_t pt_len,
                         std::vector<uint8_t>& ct, uint8_t tag[16]) {
    if (suite_is_chacha20(cs)) {
        chacha20_poly1305_encrypt(key, nonce, jpssl::span<const uint8_t>(pt, pt_len),
                                  jpssl::span<const uint8_t>(aad, aad_len), ct, tag);
        return true;
    }
    aes_context ctx;
    if (key_len == 32) ctx.init(jpssl::span<const uint8_t, 32>(key, 32));
    else ctx.init(jpssl::span<const uint8_t, 16>(key, 16));
    aes_gcm_encrypt_auto(ctx, nonce, 12, jpssl::span<const uint8_t>(pt, pt_len),
                         jpssl::span<const uint8_t>(aad, aad_len), ct, tag, 16);
    return true;
}
static bool aead_decrypt(CipherSuite cs, const uint8_t* key, size_t key_len,
                         const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                         const uint8_t* ct, size_t ct_len, const uint8_t tag[16],
                         std::vector<uint8_t>& pt) {
    if (suite_is_chacha20(cs)) {
        return chacha20_poly1305_decrypt(key, nonce, jpssl::span<const uint8_t>(ct, ct_len),
                                         jpssl::span<const uint8_t>(aad, aad_len), tag, pt);
    }
    aes_context ctx;
    if (key_len == 32) ctx.init(jpssl::span<const uint8_t, 32>(key, 32));
    else ctx.init(jpssl::span<const uint8_t, 16>(key, 16));
    return aes_gcm_decrypt_auto(ctx, nonce, 12, jpssl::span<const uint8_t>(ct, ct_len),
                                jpssl::span<const uint8_t>(aad, aad_len), tag, 16, pt);
}

// ---- DTLS 1.2 record layer (RFC 6347 4.1) --------------------------------
static void dtls12_header(uint8_t hdr[13], uint8_t type, uint16_t epoch,
                          uint64_t seq, uint16_t len) {
    hdr[0] = type;
    hdr[1] = 0xfe; hdr[2] = 0xfd;
    hdr[3] = (uint8_t)(epoch >> 8); hdr[4] = (uint8_t)epoch;
    for (int i = 0; i < 6; ++i) hdr[5 + i] = (uint8_t)(seq >> (40 - 8 * i));
    hdr[11] = (uint8_t)(len >> 8); hdr[12] = (uint8_t)len;
}

// RFC 6347 §4.1.2.1：AEAD additional_data =
//   seq_num_epoch(2) || seq_num(6) || type(1) || version(2) || length(2)
static void dtls12_ad(uint8_t ad[13], uint8_t type, uint16_t epoch, uint64_t seq,
                      uint16_t len) {
    ad[0] = (uint8_t)(epoch >> 8); ad[1] = (uint8_t)epoch;
    for (int i = 0; i < 6; ++i) ad[2 + i] = (uint8_t)(seq >> (40 - 8 * i));
    ad[8] = type;
    ad[9] = 0xfe; ad[10] = 0xfd;
    ad[11] = (uint8_t)(len >> 8); ad[12] = (uint8_t)len;
}

static std::vector<uint8_t> plaintext_record(uint8_t type, uint16_t epoch,
                                             uint64_t seq, const uint8_t* payload, size_t len) {
    std::vector<uint8_t> rec;
    rec.reserve(13 + len);
    uint8_t hdr[13];
    dtls12_header(hdr, type, epoch, seq, (uint16_t)len);
    rec.insert(rec.end(), hdr, hdr + 13);
    rec.insert(rec.end(), payload, payload + len);
    return rec;
}

static void dtls12_nonce(const uint8_t* iv, size_t iv_len, uint16_t epoch, uint64_t seq,
                         uint8_t nonce[12]) {
    if (iv_len == 12) {
        memcpy(nonce, iv, 12);
        for (int i = 0; i < 8; ++i)
            nonce[4 + i] ^= (uint8_t)((i < 2) ? (epoch >> (8 * (1 - i))) : (seq >> (8 * (7 - i))));
    }
}

static std::vector<uint8_t> dtls12_protect(dtls_session& s, uint8_t type,
                                           const uint8_t* data, size_t len) {
    uint16_t epoch = s.send_epoch;
    uint64_t seq = s.send_seq++;
    const uint8_t* iv = s.is_server ? s.server_write_iv : s.client_write_iv;
    const uint8_t* key = s.is_server ? s.server_write_key : s.client_write_key;
    // AES-GCM (RFC 5288，DTLS "exactly as TLS 1.2" per RFC 6347 4.1.2.4):
    // record = explicit_nonce(8) || ciphertext || tag，nonce = fixed_iv(4) || explicit(8)。
    // ChaCha20-Poly1305 (RFC 7905)：无显式 nonce，nonce = fixed_iv(12) XOR epoch||seq。
    bool gcm = (s.iv_len == 4);
    uint8_t nonce[12];
    uint8_t explicit_nonce[8] = {};
    if (gcm) {
        rand_bytes(explicit_nonce, 8);
        memcpy(nonce, iv, 4);
        memcpy(nonce + 4, explicit_nonce, 8);
    } else {
        dtls12_nonce(iv, s.iv_len, epoch, seq, nonce);
    }
    uint8_t ad[13];
    dtls12_ad(ad, type, epoch, seq, (uint16_t)len);  // AAD length = plaintext length
    std::vector<uint8_t> ct; uint8_t tag[16];
    aead_encrypt(s.cipher_suite, key, s.key_len, nonce, ad, 13, data, len, ct, tag);
    uint16_t wire_len = (uint16_t)((gcm ? 8 : 0) + len + 16);
    uint8_t hdr[13];
    dtls12_header(hdr, type, epoch, seq, wire_len);
    std::vector<uint8_t> rec;
    rec.insert(rec.end(), hdr, hdr + 13);
    if (gcm) rec.insert(rec.end(), explicit_nonce, explicit_nonce + 8);
    rec.insert(rec.end(), ct.begin(), ct.end());
    rec.insert(rec.end(), tag, tag + 16);
    return rec;
}

static bool dtls12_parse_header(const uint8_t* rec, size_t len,
                                uint8_t& type, uint16_t& epoch, uint64_t& seq,
                                const uint8_t*& payload, size_t& payload_len) {
    if (len < 13) return false;
    type = rec[0];
    epoch = get16(rec + 3);
    seq = get48(rec + 5);
    size_t plen = get16(rec + 11);
    if (13 + plen > len) return false;
    payload = rec + 13;
    payload_len = plen;
    return true;
}

static bool dtls12_unprotect_record(dtls_session& s, uint8_t type, uint16_t epoch, uint64_t seq,
                                    const uint8_t* payload, size_t payload_len,
                                    std::vector<uint8_t>& out) {
    bool gcm = (s.iv_len == 4);
    if (payload_len < 16 + (gcm ? 8 : 0)) return false;
    size_t ct_len = payload_len - 16 - (gcm ? 8 : 0);
    const uint8_t* ct = payload + (gcm ? 8 : 0);
    const uint8_t* tag = ct + ct_len;
    const uint8_t* iv = s.is_server ? s.client_write_iv : s.server_write_iv;
    uint8_t nonce[12];
    if (gcm) {
        memcpy(nonce, iv, 4);
        memcpy(nonce + 4, payload, 8);
    } else {
        dtls12_nonce(iv, s.iv_len, epoch, seq, nonce);
    }
    uint8_t ad[13];
    dtls12_ad(ad, type, epoch, seq, (uint16_t)ct_len);  // AAD length = plaintext length
    const uint8_t* key = s.is_server ? s.client_write_key : s.server_write_key;
    bool ok = aead_decrypt(s.cipher_suite, key, s.key_len, nonce, ad, 13, ct, ct_len, tag, out);
    return ok;
}

// ---- DTLS 1.3 record layer (RFC 9147 4.1) --------------------------------
static const uint8_t* dtls13_send_secret(const dtls_session& s, int& ok) {
    uint8_t e = (uint8_t)(s.send_epoch & 3);
    if (e == 2) { ok = 1; return s.is_server ? s.server_hs_traffic : s.client_hs_traffic; }
    if (e == 3) { ok = 1; return s.is_server ? s.server_app_traffic : s.client_app_traffic; }
    ok = 0;
    return nullptr;
}
static const uint8_t* dtls13_recv_traffic(const dtls_session& s, uint8_t epoch_bits, int& ok) {
    if (epoch_bits == 2) { ok = 1; return s.is_server ? s.client_hs_traffic : s.server_hs_traffic; }
    if (epoch_bits == 3) { ok = 1; return s.is_server ? s.client_app_traffic : s.server_app_traffic; }
    ok = 0;
    return nullptr;
}

static void dtls13_sn_mask(CipherSuite cs, const uint8_t* sn_key, size_t sn_key_len,
                           const uint8_t* ct, uint8_t mask[16]) {
    memset(mask, 0, 16);
    if (suite_is_chacha20(cs)) {
        uint8_t nonce[12];
        memcpy(nonce, ct + 4, 12);
        uint32_t counter = (uint32_t)ct[0] | ((uint32_t)ct[1] << 8) |
                           ((uint32_t)ct[2] << 16) | ((uint32_t)ct[3] << 24);
        uint8_t block[64];
        chacha20_block(sn_key, counter, nonce, block);
        memcpy(mask, block, 16);
    } else {
        aes_context ctx;
        if (sn_key_len == 32) ctx.init(jpssl::span<const uint8_t, 32>(sn_key, 32));
        else ctx.init(jpssl::span<const uint8_t, 16>(sn_key, 16));
        aes_encrypt_block(ctx, ct, mask);
    }
}

static std::vector<uint8_t> dtls13_protect(dtls_session& s, uint8_t type,
                                           const uint8_t* data, size_t len) {
    uint8_t epoch_bits = (uint8_t)(s.send_epoch & 3);
    uint64_t seq = s.send_seq++;

    std::vector<uint8_t> inner;
    inner.insert(inner.end(), data, data + len);
    inner.push_back(type);
    while (inner.size() < 16) inner.push_back(0);

    int ok = 0;
    const uint8_t* traffic = dtls13_send_secret(s, ok);
    if (!ok || !traffic) return {};
    uint8_t key[32], iv[12], sn[32]; size_t kl = 0;
    bool sha384 = suite_use_sha384(s.cipher_suite);
    dtls13_record_keys(s.cipher_suite, traffic, sha384, key, kl, iv, sn);

    uint8_t byte0 = (uint8_t)(0x20 | 0x08 | 0x04 | epoch_bits);
    uint16_t wire_seq = (uint16_t)(seq & 0xffff);
    // Length 字段 = 密文长度（含 16 字节 tag），与 TLS 1.3 record 一致
    uint16_t wire_len = (uint16_t)(inner.size() + 16);

    uint8_t nonce[12]; memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; ++i) nonce[4 + i] ^= (uint8_t)(seq >> (56 - 8 * i));

    uint8_t ad[5] = { byte0, (uint8_t)(wire_seq >> 8), (uint8_t)wire_seq,
                      (uint8_t)(wire_len >> 8), (uint8_t)wire_len };

    std::vector<uint8_t> ct; uint8_t tag[16];
    aead_encrypt(s.cipher_suite, key, kl, nonce, ad, 5, inner.data(), inner.size(), ct, tag);

    uint8_t mask[16];
    dtls13_sn_mask(s.cipher_suite, sn, kl, ct.data(), mask);
    uint8_t seq_enc_hi = (uint8_t)(wire_seq >> 8) ^ mask[0];
    uint8_t seq_enc_lo = (uint8_t)wire_seq ^ mask[1];

    std::vector<uint8_t> rec;
    rec.push_back(byte0);
    rec.push_back(seq_enc_hi); rec.push_back(seq_enc_lo);
    rec.push_back((uint8_t)(wire_len >> 8)); rec.push_back((uint8_t)wire_len);
    rec.insert(rec.end(), ct.begin(), ct.end());
    rec.insert(rec.end(), tag, tag + 16);
    return rec;
}

static bool dtls13_unprotect(dtls_session& s, const uint8_t* rec, size_t len,
                             uint8_t& type, std::vector<uint8_t>& out,
                             uint64_t* out_seq = nullptr) {
    if (len < 5 + 16 + 1) return false;
    uint8_t byte0 = rec[0];
    if ((byte0 & 0xe0) != 0x20) return false;
    if (byte0 & 0x10) return false;
    bool seq16 = (byte0 & 0x08) != 0;
    bool has_len = (byte0 & 0x04) != 0;
    uint8_t epoch_bits = byte0 & 0x03;

    size_t off = 1;
    size_t seq_bytes = seq16 ? 2 : 1;
    if (off + seq_bytes > len) return false;
    uint8_t seq_enc[2] = {0, 0};
    memcpy(seq_enc, rec + off, seq_bytes); off += seq_bytes;

    uint16_t wire_len = 0;
    if (has_len) {
        if (off + 2 > len) return false;
        wire_len = get16(rec + off); off += 2;
    } else {
        wire_len = (uint16_t)(len - off);
    }
    if (off + wire_len > len || wire_len < 16) return false;

    const uint8_t* ct = rec + off;
    size_t ct_len = (size_t)wire_len - 16;
    const uint8_t* tag = ct + ct_len;
    // RFC 9147 只要求 wire_len >= tag 长度（16）；wolfSSL 不强制把明文填充到 16 字节，
    // 因此密文（不含 tag）可以小于 16。
    if (ct_len == 0) return false;

    int ok = 0;
    const uint8_t* traffic = dtls13_recv_traffic(s, epoch_bits, ok);
    if (!ok || !traffic) return false;
    uint8_t key[32], iv[12], sn[32]; size_t kl = 0;
    bool sha384 = suite_use_sha384(s.cipher_suite);
    dtls13_record_keys(s.cipher_suite, traffic, sha384, key, kl, iv, sn);

    uint8_t mask[16];
    dtls13_sn_mask(s.cipher_suite, sn, kl, ct, mask);
    uint16_t wire_seq;
    if (seq16) wire_seq = (uint16_t)(((uint16_t)(seq_enc[0] ^ mask[0]) << 8) | (seq_enc[1] ^ mask[1]));
    else wire_seq = (uint16_t)(seq_enc[0] ^ mask[0]);

    uint64_t full_seq;
    {
        uint64_t base = s.recv_seq & ~0xffffULL;
        uint64_t cand = base | (uint64_t)wire_seq;
        if (cand + 0x8000 < s.recv_seq) cand += 0x10000;
        else if (cand > s.recv_seq + 0x8000) cand -= 0x10000;
        full_seq = cand;
    }

    uint8_t nonce[12]; memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; ++i) nonce[4 + i] ^= (uint8_t)(full_seq >> (56 - 8 * i));

    uint8_t ad[5] = { byte0, (uint8_t)(full_seq >> 8), (uint8_t)full_seq,
                      (uint8_t)(wire_len >> 8), (uint8_t)wire_len };

    std::vector<uint8_t> inner;
    if (!aead_decrypt(s.cipher_suite, key, kl, nonce, ad, 5, ct, ct_len, tag, inner))
        return false;

    size_t inner_len = inner.size();
    while (inner_len > 0 && inner[inner_len - 1] == 0) --inner_len;
    if (inner_len == 0) return false;
    type = inner[inner_len - 1];
    out.assign(inner.begin(), inner.begin() + inner_len - 1);

    if (epoch_bits != (s.recv_epoch & 3)) {
        s.recv_epoch = epoch_bits;
        s.recv_seq = full_seq + 1;
    } else if (full_seq + 1 > s.recv_seq) {
        s.recv_seq = full_seq + 1;
    }
    if (out_seq) *out_seq = full_seq;
    return true;
}

// ---- handshake message framing -------------------------------------------
static std::vector<uint8_t> frame_handshake(dtls_session& s, uint8_t type,
                                            const std::vector<uint8_t>& body,
                                            uint32_t frag_offset, uint32_t frag_len) {
    std::vector<uint8_t> m;
    m.push_back(type);
    put24(m, (uint32_t)body.size());
    put16(m, s.send_msg_seq);
    put24(m, frag_offset);
    put24(m, frag_len);
    m.insert(m.end(), body.begin() + frag_offset, body.begin() + frag_offset + frag_len);
    return m;
}

static std::vector<uint8_t> inner_handshake(uint8_t type, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> m;
    m.push_back(type);
    put24(m, (uint32_t)body.size());
    m.insert(m.end(), body.begin(), body.end());
    return m;
}

static std::vector<uint8_t> frame_inner(dtls_session& s, const std::vector<uint8_t>& inner,
                                        uint32_t frag_offset, uint32_t frag_len) {
    std::vector<uint8_t> m;
    m.push_back(inner[0]);
    put24(m, (uint32_t)(inner.size() - 4));
    put16(m, s.send_msg_seq);
    put24(m, frag_offset);
    put24(m, frag_len);
    m.insert(m.end(), inner.begin() + 4 + frag_offset, inner.begin() + 4 + frag_offset + frag_len);
    return m;
}

static bool find_extension(const uint8_t* ext, size_t ext_total, uint16_t want,
                           const uint8_t*& data, size_t& dlen) {
    size_t off = 0;
    while (off + 4 <= ext_total) {
        uint16_t type = get16(ext + off);
        size_t elen = get16(ext + off + 2);
        if (off + 4 + elen > ext_total) return false;
        if (type == want) { data = ext + off + 4; dlen = elen; return true; }
        off += 4 + elen;
    }
    return false;
}

// ---- ClientHello / ServerHello ------------------------------------------
static std::vector<uint8_t> build_ch12_body(dtls_session& s, const std::vector<uint16_t>& suites) {
    std::vector<uint8_t> b;
    put16(b, (uint16_t)DTLSVersion::V12);
    b.insert(b.end(), s.client_random, s.client_random + 32);
    b.push_back(0);
    b.push_back((uint8_t)s.cookie.size());
    b.insert(b.end(), s.cookie.begin(), s.cookie.end());
    put16(b, (uint16_t)(suites.size() * 2));
    for (uint16_t cs : suites) put16(b, cs);
    b.push_back(1); b.push_back(0);

    std::vector<uint8_t> ext;
    if (!s.server_name.empty()) {
        ext.push_back(0x00); ext.push_back(0x00);
        put16(ext, (uint16_t)(5 + s.server_name.size()));
        put16(ext, (uint16_t)(3 + s.server_name.size()));
        ext.push_back(0);
        put16(ext, (uint16_t)s.server_name.size());
        ext.insert(ext.end(), s.server_name.begin(), s.server_name.end());
    }
    {
        ext.push_back(0x00); ext.push_back(0x0a);
        std::vector<uint16_t> groups;
        if (s.ks_group == NamedGroup::secp256r1) {
            groups.push_back((uint16_t)NamedGroup::secp256r1);
            groups.push_back((uint16_t)NamedGroup::X25519);
        } else {
            groups.push_back((uint16_t)NamedGroup::X25519);
            groups.push_back((uint16_t)NamedGroup::secp256r1);
        }
        put16(ext, (uint16_t)(2 + groups.size() * 2));
        put16(ext, (uint16_t)(groups.size() * 2));
        for (uint16_t g : groups) put16(ext, g);
        ext.push_back(0x00); ext.push_back(0x0b);
        ext.push_back(0x00); ext.push_back(0x02);
        ext.push_back(0x01); ext.push_back(0x00);
    }
    {
        // renegotiation_info (RFC 5746)：初次握手 renegotiated_connection 为空
        ext.push_back(0xff); ext.push_back(0x01);
        ext.push_back(0x00); ext.push_back(0x01);
        ext.push_back(0x00);
    }
    {
        std::vector<uint16_t> algs = s.sig_algs.empty() ? jpssl::tls::tls_default_signature_algorithms() : s.sig_algs;
        // SM2-SM3 (RFC 8998) 是 TLS 1.3 的签名方案；DTLS 1.2 客户端不应发送，
        // OpenSSL 4.0 不认识该 code point 时会跳过整个交集。
        algs.erase(std::remove_if(algs.begin(), algs.end(),
                    [](uint16_t a) { return a == (uint16_t)SignatureAlgorithm::SM2_SM3; }),
                   algs.end());
        ext.push_back(0x00); ext.push_back(0x0d);
        put16(ext, (uint16_t)(2 + algs.size() * 2));
        put16(ext, (uint16_t)(algs.size() * 2));
        for (uint16_t a : algs) put16(ext, a);
    }
    put16(b, (uint16_t)ext.size());
    b.insert(b.end(), ext.begin(), ext.end());
    return b;
}

static std::vector<uint8_t> build_ch13_body(dtls_session& s, const std::vector<uint16_t>& suites) {
    std::vector<uint8_t> b;
    put16(b, 0xfefd);
    b.insert(b.end(), s.client_random, s.client_random + 32);
    b.push_back(0);
    b.push_back(0);
    put16(b, (uint16_t)(suites.size() * 2));
    for (uint16_t cs : suites) put16(b, cs);
    b.push_back(1); b.push_back(0);

    std::vector<uint8_t> ext;
    if (!s.server_name.empty()) {
        ext.push_back(0x00); ext.push_back(0x00);
        put16(ext, (uint16_t)(5 + s.server_name.size()));
        put16(ext, (uint16_t)(3 + s.server_name.size()));
        ext.push_back(0);
        put16(ext, (uint16_t)s.server_name.size());
        ext.insert(ext.end(), s.server_name.begin(), s.server_name.end());
    }
    {
        ext.push_back(0x00); ext.push_back(0x2b);
        ext.push_back(0x00); ext.push_back(0x03);
        ext.push_back(0x02); ext.push_back(0xfe); ext.push_back(0xfc);
    }
    {
        std::vector<uint16_t> groups;
        if (s.ks_group == NamedGroup::X448) { groups.push_back((uint16_t)NamedGroup::X448); groups.push_back((uint16_t)NamedGroup::X25519); }
        else if (s.ks_group == NamedGroup::secp256r1) { groups.push_back((uint16_t)NamedGroup::secp256r1); groups.push_back((uint16_t)NamedGroup::X25519); }
        else groups.push_back((uint16_t)NamedGroup::X25519);
        ext.push_back(0x00); ext.push_back(0x0a);
        put16(ext, (uint16_t)(2 + groups.size() * 2));
        put16(ext, (uint16_t)(groups.size() * 2));
        for (uint16_t g : groups) put16(ext, g);
    }
    {
        std::vector<uint16_t> algs = s.sig_algs.empty() ? jpssl::tls::tls_default_signature_algorithms() : s.sig_algs;
        ext.push_back(0x00); ext.push_back(0x0d);
        put16(ext, (uint16_t)(2 + algs.size() * 2));
        put16(ext, (uint16_t)(algs.size() * 2));
        for (uint16_t a : algs) put16(ext, a);
    }
    {
        ext.push_back(0x00); ext.push_back(0x33);
        std::vector<uint8_t> shares;
        if (s.ks_group == NamedGroup::X448) {
            put16(shares, (uint16_t)NamedGroup::X448); put16(shares, 56);
            shares.insert(shares.end(), s.ks_pub, s.ks_pub + 56);
        } else if (s.ks_group == NamedGroup::secp256r1) {
            // RFC 8446 4.2.8.2: secp256r1 key_exchange 是 65 字节未压缩点 (0x04 || X || Y)
            put16(shares, (uint16_t)NamedGroup::secp256r1); put16(shares, 65);
            shares.push_back(0x04);
            shares.insert(shares.end(), s.ks_pub, s.ks_pub + 64);
        } else {
            put16(shares, (uint16_t)NamedGroup::X25519); put16(shares, 32);
            shares.insert(shares.end(), s.ks_pub, s.ks_pub + 32);
        }
        put16(ext, (uint16_t)(2 + shares.size()));
        put16(ext, (uint16_t)shares.size());
        ext.insert(ext.end(), shares.begin(), shares.end());
    }
    put16(b, (uint16_t)ext.size());
    b.insert(b.end(), ext.begin(), ext.end());
    return b;
}

static std::vector<uint8_t> build_sh_body(dtls_session& s, bool dtls13) {
    std::vector<uint8_t> b;
    put16(b, 0xfefd);
    b.insert(b.end(), s.server_random, s.server_random + 32);
    b.push_back(0);
    put16(b, (uint16_t)s.cipher_suite);
    b.push_back(0);
    if (dtls13) {
        std::vector<uint8_t> ext;
        ext.push_back(0x00); ext.push_back(0x2b);
        // RFC 8446 4.2.1: ServerHello 中 supported_versions 是单个 ProtocolVersion（2 字节），
        // 不带客户端向量格式的长度字节。
        ext.push_back(0x00); ext.push_back(0x02);
        ext.push_back(0xfe); ext.push_back(0xfc);
        ext.push_back(0x00); ext.push_back(0x33);
        std::vector<uint8_t> ks;
        if (s.ks_group == NamedGroup::X448) {
            put16(ks, (uint16_t)NamedGroup::X448); put16(ks, 56);
            ks.insert(ks.end(), s.ks_pub, s.ks_pub + 56);
        } else if (s.ks_group == NamedGroup::secp256r1) {
            // RFC 8446 4.2.8.2: secp256r1 key_exchange 是 65 字节未压缩点 (0x04 || X || Y)
            put16(ks, (uint16_t)NamedGroup::secp256r1); put16(ks, 65);
            ks.push_back(0x04);
            ks.insert(ks.end(), s.ks_pub, s.ks_pub + 64);
        } else {
            put16(ks, (uint16_t)NamedGroup::X25519); put16(ks, 32);
            ks.insert(ks.end(), s.ks_pub, s.ks_pub + 32);
        }
        // ServerHello key_share = 单个 KeyShareEntry（无向量长度）
        put16(ext, (uint16_t)ks.size());
        ext.insert(ext.end(), ks.begin(), ks.end());
        put16(b, (uint16_t)ext.size());
        b.insert(b.end(), ext.begin(), ext.end());
    } else {
        // DTLS 1.2 ServerHello 扩展：renegotiation_info (RFC 5746 / RFC 6347)，
        // renegotiated_connection 长度为 0（本次握手未重协商）。
        // OpenSSL 客户端默认拒绝无此扩展的 DTLS 1.2 ServerHello。
        std::vector<uint8_t> ext;
        ext.push_back(0xff); ext.push_back(0x01);   // renegotiation_info
        ext.push_back(0x00); ext.push_back(0x01);   // 扩展长度
        ext.push_back(0x00);                        // renegotiated_connection len=0
        put16(b, (uint16_t)ext.size());
        b.insert(b.end(), ext.begin(), ext.end());
    }
    return b;
}

struct ch_info {
    uint16_t legacy_version = 0;
    std::string sni;
    std::vector<uint16_t> suites;
    std::vector<uint8_t> cookie_field;
    const uint8_t* ext = nullptr; size_t ext_total = 0;
    bool has_key_share = false;
    uint16_t ks_group = 0;
    std::vector<uint8_t> ks_pub;
    std::vector<uint16_t> sig_algs;
};

static bool parse_client_hello(const uint8_t* body, size_t len, ch_info& out) {
    if (len < 2 + 32) return false;
    size_t off = 0;
    out.legacy_version = get16(body + off); off += 2;
    off += 32;
    if (off + 1 > len) return false;
    size_t sid_len = body[off]; off += 1 + sid_len;
    if (off + 1 > len) return false;
    size_t cookie_len = body[off];
    if (off + 1 + cookie_len > len) return false;
    out.cookie_field.assign(body + off, body + off + 1 + cookie_len);
    off += 1 + cookie_len;
    if (off + 2 > len) return false;
    size_t cs_len = get16(body + off); off += 2;
    if (off + cs_len > len || (cs_len & 1)) return false;
    for (size_t i = 0; i + 1 < cs_len; i += 2) out.suites.push_back(get16(body + off + i));
    off += cs_len;
    if (off + 1 > len) return false;
    size_t cm_len = body[off]; off += 1 + cm_len;
    if (off + 2 > len) return false;
    out.ext_total = get16(body + off); off += 2;
    if (off + out.ext_total > len) return false;
    out.ext = body + off;

    const uint8_t* d = nullptr; size_t dl = 0;
    if (find_extension(out.ext, out.ext_total, 0x0000, d, dl) && dl >= 5) {
        size_t nl = get16(d + 3);
        if (5 + nl <= dl) out.sni.assign((const char*)d + 5, nl);
    }
    if (find_extension(out.ext, out.ext_total, 0x000d, d, dl) && dl >= 2) {
        size_t ll = get16(d);
        if (2 + ll <= dl && !(ll & 1))
            for (size_t i = 0; i + 1 < ll; i += 2) out.sig_algs.push_back(get16(d + 2 + i));
    }
    if (find_extension(out.ext, out.ext_total, 0x0033, d, dl) && dl >= 6) {
        size_t list_len = get16(d);
        size_t p = 2, end = std::min<size_t>(2 + list_len, dl);
        while (p + 4 <= end) {
            uint16_t g = get16(d + p);
            uint16_t klen = get16(d + p + 2);
            if (p + 4 + klen <= end) {
                out.ks_group = g;
                out.ks_pub.assign(d + p + 4, d + p + 4 + klen);
                out.has_key_share = true;
                break;
            }
            p += 4 + klen;
        }
    }
    return true;
}

static std::vector<uint8_t> build_hvr_body(uint16_t version, const std::vector<uint8_t>& cookie) {
    std::vector<uint8_t> b;
    put16(b, version);
    b.push_back((uint8_t)cookie.size());
    b.insert(b.end(), cookie.begin(), cookie.end());
    return b;
}

static std::vector<uint8_t> build_cert_body12(const tls_certificate& cert) {
    std::vector<uint8_t> der = cert.cert_data.empty() ? jpssl::tls::tls_make_x509_self_signed(cert) : cert.cert_data;
    std::vector<uint8_t> b;
    put24(b, (uint32_t)(3 + der.size()));
    put24(b, (uint32_t)der.size());
    b.insert(b.end(), der.begin(), der.end());
    return b;
}

static std::vector<uint8_t> build_cert_body13(const tls_certificate& cert) {
    std::vector<uint8_t> der = cert.cert_data.empty() ? jpssl::tls::tls_make_x509_self_signed(cert) : cert.cert_data;
    std::vector<uint8_t> b;
    b.push_back(0);
    put24(b, (uint32_t)(3 + der.size() + 2));
    put24(b, (uint32_t)der.size());
    b.insert(b.end(), der.begin(), der.end());
    put16(b, 0);
    return b;
}

static std::vector<uint8_t> build_skx_body(dtls_session& s, const tls_certificate& cert) {
    std::vector<uint8_t> params;
    params.push_back(3);
    put16(params, (uint16_t)s.ks_group);
    if (s.ks_group == NamedGroup::secp256r1) {
        params.push_back(65);
        params.push_back(0x04);
        params.insert(params.end(), s.ks_pub, s.ks_pub + 64);
    } else {
        params.push_back(32);
        params.insert(params.end(), s.ks_pub, s.ks_pub + 32);
    }
    std::vector<uint8_t> to_sign;
    to_sign.insert(to_sign.end(), s.client_random, s.client_random + 32);
    to_sign.insert(to_sign.end(), s.server_random, s.server_random + 32);
    to_sign.insert(to_sign.end(), params.begin(), params.end());

    uint16_t scheme = (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256;
    if (cert.sig_alg == SignatureAlgorithm::ECDSA_SECP256R1_SHA256)
        scheme = (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    else if (cert.sig_alg == SignatureAlgorithm::ED25519)
        scheme = (uint16_t)SignatureAlgorithm::ED25519;
    else if (cert.sig_alg == SignatureAlgorithm::RSA_PSS_RSAE_SHA256)
        scheme = (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256;

    uint8_t sig[512]; size_t sig_len = 0;
    if (!cert.sign_scheme(scheme, to_sign.data(), to_sign.size(), sig, sig_len))
        return {};

    std::vector<uint8_t> b = params;
    put16(b, scheme);
    put16(b, (uint16_t)sig_len);
    b.insert(b.end(), sig, sig + sig_len);
    return b;
}

static std::vector<uint8_t> build_cke_body(dtls_session& s) {
    std::vector<uint8_t> b;
    if (s.ks_group == NamedGroup::secp256r1) {
        b.push_back(65);
        b.push_back(0x04);
        b.insert(b.end(), s.ks_pub, s.ks_pub + 64);
    } else {
        b.push_back(32);
        b.insert(b.end(), s.ks_pub, s.ks_pub + 32);
    }
    return b;
}

static std::vector<uint8_t> build_ee_body(dtls_session& s) {
    std::vector<uint8_t> b;
    put16(b, 0);
    (void)s;
    return b;
}

static std::vector<uint8_t> build_cv_body13(dtls_session& s, const tls_certificate& cert) {
    std::vector<uint8_t> content;
    const char* ctx = s.is_server ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify";
    // RFC 8446 4.4.3: 64×0x20 || context string || 0x00 || transcript_hash
    content.insert(content.end(), 64, 0x20);
    content.insert(content.end(), ctx, ctx + strlen(ctx));
    content.push_back(0x00);
    transcript_compute(s);
    content.insert(content.end(), s.transcript_hash, s.transcript_hash + suite_hash_len(s.cipher_suite));

    uint16_t scheme = s.selected_sig_alg;
    uint8_t sig[512]; size_t sig_len = 0;
    const uint8_t* za = nullptr;
    uint8_t za_buf[32];
    if (scheme == (uint16_t)SignatureAlgorithm::SM2_SM3) {
        static const char id[] = "TLSv1.3+GM+Cipher+Suite";
        sm2_compute_za((const uint8_t*)id, sizeof(id) - 1, cert.pub.sm2, cert.pub.sm2 + 32, za_buf);
        za = za_buf;
    }
    // wolfSSL 的 TLS 1.3 ECDSA 验签路径期望 DER（wc_ecc_verify_hash），与 RFC 8446
    // 的 raw 要求有偏差；为与其互通使用 DER 编码。
    if (!cert.sign_scheme(scheme, content.data(), content.size(), sig, sig_len, za))
        return {};

    std::vector<uint8_t> b;
    put16(b, scheme);
    put16(b, (uint16_t)sig_len);
    b.insert(b.end(), sig, sig + sig_len);
    return b;
}

static std::vector<uint8_t> build_finished12(dtls_session& s, bool for_server) {
    bool sha384 = suite_use_sha384(s.cipher_suite);
    size_t hl = suite_hash_len(s.cipher_suite);
    transcript_compute(s);
    std::vector<uint8_t> hash_buf(s.transcript_hash, s.transcript_hash + hl);
    uint8_t out[12];
    prf12(s.master_secret, 48, for_server ? "server finished" : "client finished",
          hash_buf.data(), hash_buf.size(), out, 12, sha384);
    return std::vector<uint8_t>(out, out + 12);
}

static std::vector<uint8_t> build_finished13(dtls_session& s, bool for_server) {
    bool sha384 = suite_use_sha384(s.cipher_suite);
    size_t hl = suite_hash_len(s.cipher_suite);
    uint8_t finished_key[48];
    // RFC 8446 4.4.4: finished_key = HKDF-Expand-Label(BaseKey, "finished", "", len)，
    // BaseKey 是对应的 handshake traffic secret（server Finished 用 server 侧）。
    const uint8_t* base_key = for_server ? s.server_hs_traffic : s.client_hs_traffic;
    expand_label13(base_key, "finished", nullptr, 0, finished_key, hl, sha384);
    transcript_compute(s);
    uint8_t mac[48];
    if (sha384) hmac_sha384(finished_key, hl, s.transcript_hash, hl, mac);
    else hmac_sha256(finished_key, hl, s.transcript_hash, hl, mac);
    return std::vector<uint8_t>(mac, mac + hl);
}

// ---- datagram parsing ----------------------------------------------------
struct dtls_event {
    uint8_t type;
    uint16_t epoch;
    uint64_t seq;
    std::vector<uint8_t> payload;
};

static bool parse_dtls12_datagram(dtls_session& s, const uint8_t* dg, size_t len,
                                  std::vector<dtls_event>& events,
                                  std::vector<uint8_t>& pending) {
    size_t off = 0;
    while (off < len) {
        uint8_t type; uint16_t epoch; uint64_t seq;
        const uint8_t* payload; size_t plen;
        if (!dtls12_parse_header(dg + off, len - off, type, epoch, seq, payload, plen))
            return false;
        size_t rec_start = off;
        off += 13 + plen;
        if (epoch > s.recv_epoch || epoch < s.recv_epoch) continue;
        if (type == 20) {
            s.recv_epoch = epoch + 1;
            events.push_back({type, epoch, seq, {payload, payload + plen}});
        } else if (epoch == 0) {
            events.push_back({type, epoch, seq, {payload, payload + plen}});
        } else {
            std::vector<uint8_t> pt;
            if (dtls12_unprotect_record(s, type, epoch, seq, payload, plen, pt)) {
                events.push_back({type, epoch, seq, std::move(pt)});
            } else {
                pending.insert(pending.end(), dg + rec_start, dg + off);
            }
        }
    }
    return true;
}

static bool parse_dtls13_datagram(dtls_session& s, const uint8_t* dg, size_t len,
                                  std::vector<dtls_event>& events,
                                  std::vector<uint8_t>& pending) {
    size_t off = 0;
    while (off < len) {
        uint8_t b0 = dg[off];
        if (b0 == 22 || b0 == 26 || b0 == 20 || b0 == 21) {
            uint8_t type; uint16_t epoch; uint64_t seq;
            const uint8_t* payload; size_t plen;
            if (!dtls12_parse_header(dg + off, len - off, type, epoch, seq, payload, plen))
                return false;
            off += 13 + plen;
            if (epoch == 0)
                events.push_back({type, epoch, seq, {payload, payload + plen}});
        } else if ((b0 & 0xe0) == 0x20) {
            bool seq16 = (b0 & 0x08) != 0;
            bool has_len = (b0 & 0x04) != 0;
            size_t hdr = 1 + (seq16 ? 2 : 1) + (has_len ? 2 : 0);
            if (off + hdr > len) return false;
            uint16_t wire_len;
            if (has_len) wire_len = get16(dg + off + hdr - 2);
            else wire_len = (uint16_t)(len - off - hdr);
            if (off + hdr + wire_len > len) return false;
            size_t rec_start = off;
            uint8_t type; std::vector<uint8_t> pt; uint64_t seq = 0;
            if (dtls13_unprotect(s, dg + off, hdr + wire_len, type, pt, &seq))
                events.push_back({type, (uint16_t)(b0 & 3), seq, std::move(pt)});
            else
                pending.insert(pending.end(), dg + rec_start, dg + rec_start + hdr + wire_len);
            off += hdr + wire_len;
        } else {
            return false;
        }
    }
    return true;
}

// ---- handshake helpers ---------------------------------------------------
static std::vector<uint8_t> build_ack_body(dtls_session& s) {
    std::vector<uint8_t> b;
    std::vector<std::pair<uint64_t, uint64_t>> recs = s.received_records;
    std::sort(recs.begin(), recs.end());
    recs.erase(std::unique(recs.begin(), recs.end()), recs.end());
    if (recs.size() > 64) recs.resize(64);
    put16(b, (uint16_t)(recs.size() * 16));
    for (auto& p : recs) { put64(b, p.first); put64(b, p.second); }
    return b;
}

static void generate_ecdh_keypair(dtls_session& s) {
    if (s.ks_group == NamedGroup::X448) {
        uint8_t pub[56], priv[56];
        x448_generate_keypair(pub, priv);
        memcpy(s.ks_priv, priv, 56); memcpy(s.ks_pub, pub, 56); s.ks_pub_len = 56;
    } else if (s.ks_group == NamedGroup::secp256r1) {
        uint8_t pub[64], priv[32];
        ecdsa_p256_keygen(pub, priv);
        memcpy(s.ks_priv, priv, 32); memcpy(s.ks_pub, pub, 64); s.ks_pub_len = 64;
    } else {
        uint8_t pub[32], priv[32];
        x25519_generate_keypair(pub, priv);
        memcpy(s.ks_priv, priv, 32); memcpy(s.ks_pub, pub, 32); s.ks_pub_len = 32;
    }
}

static bool ecdh_derive(dtls_session& s, const uint8_t* peer_pub, size_t peer_len) {
    uint8_t shared[56];
    size_t shared_len;
    if (s.ks_group == NamedGroup::X448) {
        if (peer_len < 56) return false;
        x448_scalar_mult(shared, s.ks_priv, peer_pub);
        shared_len = 56;
    } else if (s.ks_group == NamedGroup::secp256r1) {
        const uint8_t* pp = peer_pub;
        if (peer_len == 65 && peer_pub[0] == 0x04) pp = peer_pub + 1;
        if (peer_len < 64) return false;
        if (!ecdsa_p256_ecdh(shared, s.ks_priv, pp)) return false;
        shared_len = 32;
    } else {
        if (peer_len < 32) return false;
        x25519_scalar_mult(shared, s.ks_priv, peer_pub);
        shared_len = 32;
    }
    if (s.ver == DTLSVersion::V12) dtls12_derive_keys(s, shared, shared_len);
    else dtls13_derive_handshake(s, shared, shared_len);
    return true;
}

static std::unique_ptr<tls_certificate> cert_from_x509(const x509::x509_cert& leaf) {
    auto out = jpssl::make_unique<tls_certificate>();
    out->subject_name = leaf.common_name();
    out->sig_alg = jpssl::tls::tls_key_type_to_sig_alg(leaf.key_type);
    switch (leaf.key_type) {
        case KeyType::RSA_2048:
            if (leaf.public_key.size() < 259) return nullptr;
            out->pub.rsa.n = jpssl::rsa_bignum::from_bytes(leaf.public_key.data(), 256);
            out->pub.rsa.e = jpssl::rsa_bignum::from_bytes(leaf.public_key.data() + 256, 3);
            break;
        case KeyType::Ed25519:
            if (leaf.public_key.size() < 32) return nullptr;
            memcpy(out->pub.ed25519, leaf.public_key.data(), 32);
            break;
        case KeyType::Ed448:
            if (leaf.public_key.size() < 57) return nullptr;
            memcpy(out->pub.ed448, leaf.public_key.data(), 57);
            break;
        case KeyType::ECDSA_P256:
            if (leaf.public_key.size() < 64) return nullptr;
            memcpy(out->pub.ecdsa_p256, leaf.public_key.data(), 64);
            break;
        case KeyType::ECDSA_P384:
            if (leaf.public_key.size() < 96) return nullptr;
            memcpy(out->pub.ecdsa_p384, leaf.public_key.data(), 96);
            break;
        case KeyType::ECDSA_P521:
            if (leaf.public_key.size() < 132) return nullptr;
            memcpy(out->pub.ecdsa_p521, leaf.public_key.data(), 132);
            break;
        case KeyType::SM2:
            if (leaf.public_key.size() < 64) return nullptr;
            memcpy(out->pub.sm2, leaf.public_key.data(), 64);
            break;
        default:
            return nullptr;
    }
    return out;
}

static bool hostname_matches(const x509::x509_cert& leaf, const std::string& host) {
    if (host.empty()) return true;
    for (const auto& dns : leaf.dns_names()) {
        if (dns == host) return true;
        if (dns.size() > 2 && dns[0] == '*' && dns[1] == '.') {
            std::string suffix = dns.substr(1);
            if (host.size() > suffix.size() &&
                host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0)
                return true;
        }
    }
    if (leaf.common_name() == host) return true;
    return false;
}

static bool verify_server_chain(const std::vector<x509::x509_cert>& chain,
                                const tls_trust_store& trust, const std::string& host) {
    if (chain.empty()) return false;
    auto r = x509::x509_verify_chain(chain);
    if (!r.success) {
        for (const auto& root : trust.ca_roots) {
            std::vector<x509::x509_cert> full = chain;
            full.push_back(root);
            r = x509::x509_verify_chain(full);
            if (r.success) break;
        }
    }
    if (!r.success) return false;
    return hostname_matches(chain.front(), host);
}

static bool parse_cert_list(const uint8_t* body, size_t len, std::vector<x509::x509_cert>& chain) {
    if (len < 3) return false;
    size_t list_len = get24(body);
    size_t off = 3, end = std::min<size_t>(3 + list_len, len);
    while (off + 3 <= end) {
        size_t clen = get24(body + off);
        off += 3;
        if (off + clen > end) return false;
        auto cert = x509::x509_cert::from_der(body + off, clen);
        if (!cert) return false;
        chain.push_back(std::move(*cert));
        off += clen;
        if (off + 2 <= end) {
            size_t ext_len = get16(body + off);
            off += 2 + ext_len;
        }
    }
    return !chain.empty();
}

static std::vector<uint8_t> make_cookie(dtls_session& s, const uint8_t* client_random) {
    if (s.cookie_secret.empty()) { s.cookie_secret.resize(32); rand_bytes(s.cookie_secret.data(), 32); }
    std::vector<uint8_t> mac(32);
    hmac_sha256(s.cookie_secret.data(), 32, client_random, 32, mac.data());
    return mac;
}

static std::vector<uint8_t> extract_cookie(const ch_info& ch) {
    if (ch.cookie_field.size() < 2) return {};
    size_t cl = ch.cookie_field[0];
    if (1 + cl > ch.cookie_field.size()) return {};
    return std::vector<uint8_t>(ch.cookie_field.begin() + 1, ch.cookie_field.begin() + 1 + cl);
}

static bool collect_handshake(dtls_session& s, const std::vector<uint8_t>& bytes,
                              std::function<bool(dtls_session&, uint8_t, uint16_t, const std::vector<uint8_t>&)> process) {
    size_t off = 0;
    while (off + 12 <= bytes.size()) {
        uint8_t mtype = bytes[off];
        uint32_t total = get24(bytes.data() + off + 1);
        uint16_t mseq = get16(bytes.data() + off + 4);
        uint32_t foff = get24(bytes.data() + off + 6);
        uint32_t flen = get24(bytes.data() + off + 9);
        if (off + 12 + flen > bytes.size()) return false;
        const uint8_t* frag = bytes.data() + off + 12;

        if (mseq < s.recv_msg_seq) {
            s.retransmit_requested = true;
            off += 12 + flen;
            continue;
        }
        if (mseq > s.recv_msg_seq) {
            off += 12 + flen;
            continue;
        }
        if (foff == 0 && flen == total && s.reassembly_buf.empty()) {
            std::vector<uint8_t> body(bytes.begin() + off + 12, bytes.begin() + off + 12 + flen);
            if (!process(s, mtype, mseq, body)) return false;
            s.recv_msg_seq++;
            off += 12 + flen;
        } else {
            if (s.reassembly_buf.empty()) {
                s.reassembly_msg_seq = mseq;
                s.reassembly_total_len = total;
                s.reassembly_buf.assign(total, 0);
                s.reassembly_received.assign(total, 0);
                s.reassembly_remaining = total;
            }
            if (s.reassembly_msg_seq == mseq && s.reassembly_total_len == total &&
                foff + flen <= total) {
                for (uint32_t i = 0; i < flen; ++i) {
                    if (!s.reassembly_received[foff + i]) {
                        s.reassembly_buf[foff + i] = frag[i];
                        s.reassembly_received[foff + i] = 1;
                        --s.reassembly_remaining;
                    }
                }
                if (s.reassembly_remaining == 0) {
                    if (!process(s, mtype, mseq, s.reassembly_buf)) return false;
                    s.recv_msg_seq++;
                    s.reassembly_buf.clear();
                    s.reassembly_received.clear();
                    s.reassembly_remaining = 0;
                }
            }
            off += 12 + flen;
        }
    }
    return true;
}

static void transcript_add_msg(dtls_session& s, uint8_t mtype, uint16_t msg_seq,
                               const std::vector<uint8_t>& body, bool dtls13) {
    if (dtls13) {
        transcript_add(s, inner_handshake(mtype, body));
    } else {
        std::vector<uint8_t> m;
        m.push_back(mtype);
        put24(m, (uint32_t)body.size());
        put16(m, msg_seq);
        put24(m, 0);
        put24(m, (uint32_t)body.size());
        m.insert(m.end(), body.begin(), body.end());
        transcript_add(s, m);
    }
}

static uint16_t select_sig_scheme(const std::vector<uint16_t>& peer, const tls_certificate& cert,
                                  bool dtls13) {
    std::vector<uint16_t> cand;
    switch (cert.sig_alg) {
        case SignatureAlgorithm::ED25519: cand = {(uint16_t)SignatureAlgorithm::ED25519}; break;
        case SignatureAlgorithm::ED448: cand = {(uint16_t)SignatureAlgorithm::ED448}; break;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256: cand = {(uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256}; break;
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384: cand = {(uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384}; break;
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512: cand = {(uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512}; break;
        case SignatureAlgorithm::SM2_SM3: cand = {(uint16_t)SignatureAlgorithm::SM2_SM3}; break;
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
            if (dtls13)
                cand = {(uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512};
            else
                cand = {(uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256,
                        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA384,
                        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA512,
                        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256};
            break;
        default: return 0;
    }
    for (uint16_t a : peer)
        for (uint16_t c : cand)
            if (a == c) return a;
    return 0;
}

static std::vector<uint8_t> client_flight12(dtls_session& s) {
    std::vector<uint8_t> flight;
    auto cke_body = build_cke_body(s);
    auto cke_framed = frame_handshake(s, 16, cke_body, 0, (uint32_t)cke_body.size());
    s.send_msg_seq++;
    transcript_add(s, cke_framed);
    auto cke_rec = plaintext_record(22, 0, s.send_seq++, cke_framed.data(), cke_framed.size());
    flight.insert(flight.end(), cke_rec.begin(), cke_rec.end());

    uint8_t one = 1;
    auto ccs_rec = plaintext_record(20, 0, s.send_seq++, &one, 1);
    flight.insert(flight.end(), ccs_rec.begin(), ccs_rec.end());
    s.send_epoch = 1; s.send_seq = 0;

    auto fin_body = build_finished12(s, false);
    auto fin_framed = frame_handshake(s, 20, fin_body, 0, (uint32_t)fin_body.size());
    s.send_msg_seq++;
    transcript_add(s, fin_framed);
    auto fin_rec = dtls12_protect(s, 22, fin_framed.data(), fin_framed.size());
    flight.insert(flight.end(), fin_rec.begin(), fin_rec.end());
    return flight;
}

static std::vector<uint8_t> client_flight13(dtls_session& s) {
    auto fin_inner = inner_handshake(20, build_finished13(s, false));
    transcript_add(s, fin_inner);
    std::vector<uint8_t> flight;
    auto fin_framed = frame_inner(s, fin_inner, 0, (uint32_t)(fin_inner.size() - 4));
    s.send_msg_seq++;
    auto fin_rec = dtls13_protect(s, 22, fin_framed.data(), fin_framed.size());
    flight.insert(flight.end(), fin_rec.begin(), fin_rec.end());
    auto ack_body = build_ack_body(s);
    auto ack_rec = dtls13_protect(s, 26, ack_body.data(), ack_body.size());
    flight.insert(flight.end(), ack_rec.begin(), ack_rec.end());
    return flight;
}

// ---- client state machine ------------------------------------------------
static dtls_step_result client_step(dtls_session& s, const dtls_handshake_input& in) {
    dtls_step_result r;
    r.ok = true;
    bool dtls13 = (s.ver == DTLSVersion::V13);

    if (!s.ch_sent) {
        rand_bytes(s.client_random, 32);
        generate_ecdh_keypair(s);
        std::vector<uint16_t> suites;
        if (dtls13) {
            if (s.cipher_suite == CipherSuite::TLS_AES_256_GCM_SHA384) suites = {0x1302, 0x1301, 0x1303};
            else if (s.cipher_suite == CipherSuite::TLS_CHACHA20_POLY1305_SHA256) suites = {0x1303, 0x1301, 0x1302};
            else suites = {0x1301, 0x1302, 0x1303};
        } else {
            if (s.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) suites = {0xC02F, 0xC02B, 0xCCA8, 0xCCA9};
            else if (s.cipher_suite == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) suites = {0xCCA9, 0xCCA8, 0xC02B};
            else if (s.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) suites = {0xCCA8, 0xCCA9, 0xC02F};
            else suites = {0xC02B, 0xC02F, 0xCCA9, 0xCCA8};
        }
        std::vector<uint8_t> body = dtls13 ? build_ch13_body(s, suites) : build_ch12_body(s, suites);
        s.ch_sent = true;
        if (dtls13) {
            auto inner = inner_handshake(1, body);
            transcript_add(s, inner);
            auto framed = frame_inner(s, inner, 0, (uint32_t)body.size());
            s.send_msg_seq++;
            r.out = plaintext_record(22, 0, s.send_seq++, framed.data(), framed.size());
        } else {
            auto framed = frame_handshake(s, 1, body, 0, (uint32_t)body.size());
            s.send_msg_seq++;
            transcript_add(s, framed);
            r.out = plaintext_record(22, 0, s.send_seq++, framed.data(), framed.size());
        }
        s.last_sent = r.out;
        return r;
    }

    if (!in.datagram || in.datagram_len == 0) { r.ok = false; r.error = "empty datagram"; return r; }

    std::vector<dtls_event> events;
    std::vector<uint8_t> pending;
    bool parsed = dtls13 ? parse_dtls13_datagram(s, in.datagram, in.datagram_len, events, pending)
                         : parse_dtls12_datagram(s, in.datagram, in.datagram_len, events, pending);
    if (!parsed) { r.ok = false; r.error = "malformed datagram"; return r; }

    std::vector<uint8_t> response;
    bool build_response = false;
    bool done = false;
    tls_certificate* server_cert = s.have_server_cert ? &s.server_cert_parsed : nullptr;
    bool got_shd = false;

    auto process = [&](dtls_session& st, uint8_t mtype, uint16_t mseq,
                       const std::vector<uint8_t>& body) -> bool {
        switch ((DTLShandshakeType)mtype) {
            case DTLShandshakeType::HELLO_VERIFY_REQUEST: {
                if (dtls13) return false;
                // body = server_version(2) || cookie_len(1) || cookie
                if (body.size() < 3) return false;
                size_t cl = body[2];
                if (body.size() < 3 + cl) return false;
                s.cookie.assign(body.begin() + 3, body.begin() + 3 + cl);
                s.hvr_received = true;
                transcript_reset(s);
                std::vector<uint16_t> suites = {0xC02B, 0xC02F, 0xCCA9, 0xCCA8};
                std::vector<uint8_t> chb = build_ch12_body(s, suites);
                auto framed = frame_handshake(s, 1, chb, 0, (uint32_t)chb.size());
                s.send_msg_seq++;
                transcript_add(s, framed);
                response = plaintext_record(22, 0, s.send_seq++, framed.data(), framed.size());
                build_response = true;
                return true;
            }
            case DTLShandshakeType::SERVER_HELLO: {
                if (body.size() < 2 + 32 + 1 + 2 + 1) return false;
                memcpy(s.server_random, body.data() + 2, 32);
                size_t off = 2 + 32;
                size_t sid_len = body[off]; off += 1 + sid_len;
                if (off + 3 > body.size()) return false;
                s.cipher_suite = select_cipher_suite(get16(body.data() + off));
                off += 2 + 1;
                transcript_add_msg(s, mtype, mseq, body, dtls13);
                if (dtls13) {
                    if (off + 2 > body.size()) return false;
                    size_t ext_total = get16(body.data() + off); off += 2;
                    if (off + ext_total > body.size()) return false;
                    const uint8_t* d = nullptr; size_t dl = 0;
                    if (find_extension(body.data() + off, ext_total, 0x0033, d, dl) && dl >= 4) {
                        uint16_t group = get16(d);
                        uint16_t klen = get16(d + 2);
                        if (4 + klen <= dl) {
                            s.ks_group = (NamedGroup)group;
                            if (!ecdh_derive(s, d + 4, klen)) return false;
                            s.send_epoch = 2; s.send_seq = 0;
                        }
                    }
                }
                return true;
            }
            case DTLShandshakeType::CERTIFICATE: {
                transcript_add_msg(s, mtype, mseq, body, dtls13);
                // DTLS 1.3 Certificate 含 1 字节 certificate_request_context 前缀
                size_t cskip = dtls13 ? 1 : 0;
                if (body.size() <= cskip) return false;
                s.server_chain.clear();
                if (!parse_cert_list(body.data() + cskip, body.size() - cskip, s.server_chain)) return false;
                if (!s.server_chain.empty()) {
                    auto sc = cert_from_x509(s.server_chain[0]);
                    if (!sc) return false;
                    s.server_cert_parsed = std::move(*sc);
                    s.have_server_cert = true;
                    server_cert = &s.server_cert_parsed;
                }
                if (in.trust_store) {
                    if (!verify_server_chain(s.server_chain, *in.trust_store, s.server_name)) {
                        r.ok = false; r.error = "cert chain verify failed";
                        return false;
                    }
                }
                return true;
            }
            case DTLShandshakeType::SERVER_KEY_EXCHANGE: {
                if (dtls13) return false;
                if (body.size() < 4) return false;
                if (body[0] != 3) return false;
                uint16_t group = get16(body.data() + 1);
                size_t pub_len = body[3];
                if (4 + pub_len + 4 > body.size()) return false;
                uint16_t scheme = get16(body.data() + 4 + pub_len);
                uint16_t sig_len = get16(body.data() + 4 + pub_len + 2);
                if (4 + pub_len + 4 + sig_len > body.size()) return false;
                const uint8_t* sig = body.data() + 4 + pub_len + 4;
                std::vector<uint8_t> to_sign;
                to_sign.insert(to_sign.end(), s.client_random, s.client_random + 32);
                to_sign.insert(to_sign.end(), s.server_random, s.server_random + 32);
                to_sign.insert(to_sign.end(), body.begin(), body.begin() + 4 + pub_len);
                if (!server_cert) return false;
                if (!server_cert->verify_scheme(scheme, to_sign.data(), to_sign.size(), sig, sig_len))
                    return false;
                s.ks_group = (NamedGroup)group;
                // 服务器可能选择与客户端预生成不同的曲线（如客户端默认 X25519、
                // 服务器选 P-256），必须按服务器曲线重新生成 ECDHE 密钥对。
                generate_ecdh_keypair(s);
                if (!ecdh_derive(s, body.data() + 4, pub_len)) return false;
                transcript_add_msg(s, mtype, mseq, body, false);
                return true;
            }
            case DTLShandshakeType::SERVER_HELLO_DONE: {
                if (dtls13) return false;
                transcript_add_msg(s, mtype, mseq, body, false);
                got_shd = true;
                return true;
            }
            case DTLShandshakeType::ENCRYPTED_EXTENSIONS: {
                if (!dtls13) return false;
                transcript_add_msg(s, mtype, mseq, body, true);
                return true;
            }
            case DTLShandshakeType::CERTIFICATE_VERIFY: {
                if (!dtls13) return false;
                if (!server_cert) return false;
                if (body.size() < 4) return false;
                uint16_t scheme = get16(body.data());
                uint16_t sig_len = get16(body.data() + 2);
                if (4 + sig_len > body.size()) return false;
                std::vector<uint8_t> content;
                const char* ctx = "TLS 1.3, server CertificateVerify";
                // RFC 8446 4.4.3: 64×0x20 || context string || 0x00 || transcript_hash
                content.insert(content.end(), 64, 0x20);
                content.insert(content.end(), ctx, ctx + strlen(ctx));
                content.push_back(0x00);
                transcript_compute(s);
                content.insert(content.end(), s.transcript_hash, s.transcript_hash + suite_hash_len(s.cipher_suite));
                if (!server_cert->verify_scheme(scheme, content.data(), content.size(),
                                                body.data() + 4, sig_len))
                    return false;
                transcript_add_msg(s, mtype, mseq, body, true);
                return true;
            }
            case DTLShandshakeType::FINISHED: {
                bool sha384 = suite_use_sha384(s.cipher_suite);
                size_t hl = suite_hash_len(s.cipher_suite);
                if (dtls13) {
                    if (body.size() != hl) return false;
                    uint8_t fk[48];
                    // RFC 8446 4.4.4: finished_key 基于 server handshake traffic secret
                    expand_label13(s.server_hs_traffic, "finished", nullptr, 0, fk, hl, sha384);
                    transcript_compute(s);
                    uint8_t mac[48];
                    if (sha384) hmac_sha384(fk, hl, s.transcript_hash, hl, mac);
                    else hmac_sha256(fk, hl, s.transcript_hash, hl, mac);
                    if (memcmp(mac, body.data(), hl) != 0) return false;
                    transcript_add_msg(s, mtype, mseq, body, true);
                    dtls13_derive_application(s);
                    response = client_flight13(s);
                    build_response = true;
                    s.server_finished_received = true;
                    s.handshake_done = true;
                    s.send_epoch = 3; s.send_seq = 0;
                    done = true;
                } else {
                    if (body.size() != 12) return false;
                    transcript_compute(s);
                    std::vector<uint8_t> hbuf(s.transcript_hash, s.transcript_hash + hl);
                    uint8_t expected[12];
                    prf12(s.master_secret, 48, "server finished", hbuf.data(), hbuf.size(), expected, 12, sha384);
                    if (memcmp(expected, body.data(), 12) != 0) return false;
                    transcript_add_msg(s, mtype, mseq, body, false);
                    s.server_finished_received = true;
                    s.handshake_done = true;
                    done = true;
                }
                return true;
            }
            default:
                return true;
        }
    };

    auto feed = [&](const std::vector<dtls_event>& evs) -> bool {
        std::vector<uint8_t> hb;
        for (auto& ev : evs) {
            if (ev.type == 22) {
                hb.insert(hb.end(), ev.payload.begin(), ev.payload.end());
                if (dtls13) s.received_records.push_back({ev.epoch, ev.seq});
            }
        }
        return collect_handshake(s, hb, process);
    };

    if (!feed(events)) {
        r.ok = false;
        if (r.error.empty()) r.error = "handshake message error";
        return r;
    }
    // retry pending encrypted records (keys derived by handshake messages above)
    for (int pg = 0; !pending.empty() && pg < 10; ++pg) {
        std::vector<uint8_t> pending2;
        std::vector<dtls_event> more;
        bool okp = dtls13 ? parse_dtls13_datagram(s, pending.data(), pending.size(), more, pending2)
                          : parse_dtls12_datagram(s, pending.data(), pending.size(), more, pending2);
        if (!okp) break;
        pending = std::move(pending2);
        if (!feed(more)) {
            r.ok = false;
            if (r.error.empty()) r.error = "handshake message error";
            return r;
        }
    }

    if (!build_response && got_shd && !dtls13) {
        response = client_flight12(s);
        build_response = true;
    }

    if (build_response) {
        r.out = std::move(response);
        s.last_sent = r.out;
    } else if (s.retransmit_requested && !s.last_sent.empty()) {
        r.out = s.last_sent;
    }
    s.retransmit_requested = false;
    r.done = done;
    return r;
}

// ---- server state machine ------------------------------------------------
static dtls_step_result server_step(dtls_session& s, const dtls_handshake_input& in) {
    dtls_step_result r;
    r.ok = true;
    bool dtls13 = (s.ver == DTLSVersion::V13);

    if (!in.datagram || in.datagram_len == 0) { r.ok = false; r.error = "empty datagram"; return r; }
    if (!in.cert_manager) { r.ok = false; r.error = "no cert manager"; return r; }

    std::vector<dtls_event> events;
    std::vector<uint8_t> pending;
    bool parsed = dtls13 ? parse_dtls13_datagram(s, in.datagram, in.datagram_len, events, pending)
                         : parse_dtls12_datagram(s, in.datagram, in.datagram_len, events, pending);
    if (!parsed) { r.ok = false; r.error = "malformed datagram"; return r; }

    std::vector<uint8_t> response;
    bool build_response = false;
    bool done = false;

    auto process = [&](dtls_session& st, uint8_t mtype, uint16_t mseq,
                       const std::vector<uint8_t>& body) -> bool {
        switch ((DTLShandshakeType)mtype) {
            case DTLShandshakeType::CLIENT_HELLO: {
                ch_info ch;
                if (!parse_client_hello(body.data(), body.size(), ch)) return false;
                s.server_name = ch.sni;

                bool cookie_ok = true;
                if (s.ver == DTLSVersion::V12 && s.require_cookie) {
                    std::vector<uint8_t> cookie = extract_cookie(ch);
                    std::vector<uint8_t> expect = make_cookie(s, body.data() + 2);
                    if (cookie.empty() || cookie != expect) cookie_ok = false;
                }
                if (!cookie_ok) {
                    std::vector<uint8_t> expect = make_cookie(s, body.data() + 2);
                    // RFC 6347 4.2.1：HelloVerifyRequest 的 server_version 用 DTLS 1.0 (0xfeff)
                    std::vector<uint8_t> hvr_body = build_hvr_body(0xfeff, expect);
                    auto framed = frame_handshake(s, 3, hvr_body, 0, (uint32_t)hvr_body.size());
                    s.send_msg_seq++;
                    response = plaintext_record(22, 0, s.send_seq++, framed.data(), framed.size());
                    build_response = true;
                    return true;
                }

                transcript_add_msg(s, mtype, mseq, body, dtls13);
                s.client_hello_ok = true;
                if (body.size() >= 2 + 32) memcpy(s.client_random, body.data() + 2, 32);

                if (!ch.suites.empty()) {
                    uint16_t want = (uint16_t)s.cipher_suite;
                    bool found = false;
                    for (uint16_t cs : ch.suites) if (cs == want) { found = true; break; }
                    if (!found) s.cipher_suite = select_cipher_suite(ch.suites[0]);
                }
                const tls_certificate* cert = in.cert_manager->get_certificate(s.server_name);
                if (!cert) { r.ok = false; r.error = "no cert for SNI: " + s.server_name; return false; }
                std::vector<uint16_t> peer_algs = ch.sig_algs.empty()
                    ? jpssl::tls::tls_default_signature_algorithms() : ch.sig_algs;
                s.selected_sig_alg = select_sig_scheme(peer_algs, *cert, dtls13);
                if (s.selected_sig_alg == 0) return false;

                rand_bytes(s.server_random, 32);

                if (dtls13) {
                    if (!ch.has_key_share) return false;
                    s.ks_group = (NamedGroup)ch.ks_group;
                    generate_ecdh_keypair(s);
                    auto sh_body = build_sh_body(s, true);
                    auto sh_inner = inner_handshake(2, sh_body);
                    transcript_add(s, sh_inner);
                    if (!ecdh_derive(s, ch.ks_pub.data(), ch.ks_pub.size())) return false;
                    s.send_epoch = 2; s.send_seq = 0;
                    auto ee_body = build_ee_body(s);
                    auto ee_inner = inner_handshake(8, ee_body);
                    transcript_add(s, ee_inner);
                    auto cert_body = build_cert_body13(*cert);
                    auto cert_inner = inner_handshake(11, cert_body);
                    transcript_add(s, cert_inner);
                    auto cv_body = build_cv_body13(s, *cert);
                    auto cv_inner = inner_handshake(15, cv_body);
                    transcript_add(s, cv_inner);
                    auto sf_body = build_finished13(s, true);
                    auto sf_inner = inner_handshake(20, sf_body);
                    transcript_add(s, sf_inner);
                    dtls13_derive_application(s);

                    std::vector<uint8_t> flight;
                    auto sh_framed = frame_inner(s, sh_inner, 0, (uint32_t)(sh_inner.size() - 4));
                    s.send_msg_seq++;
                    auto sh_rec = plaintext_record(22, 0, s.send_seq++, sh_framed.data(), sh_framed.size());
                    flight.insert(flight.end(), sh_rec.begin(), sh_rec.end());
                    auto wrap = [&](const std::vector<uint8_t>& inner) {
                        auto framed = frame_inner(s, inner, 0, (uint32_t)(inner.size() - 4));
                        s.send_msg_seq++;
                        auto rec = dtls13_protect(s, 22, framed.data(), framed.size());
                        flight.insert(flight.end(), rec.begin(), rec.end());
                    };
                    wrap(ee_inner); wrap(cert_inner); wrap(cv_inner); wrap(sf_inner);
                    response = std::move(flight);
                    build_response = true;
                } else {
                    generate_ecdh_keypair(s);
                    auto sh_body = build_sh_body(s, false);
                    auto sh_framed = frame_handshake(s, 2, sh_body, 0, (uint32_t)sh_body.size());
                    s.send_msg_seq++;
                    transcript_add(s, sh_framed);
                    auto cert_body = build_cert_body12(*cert);
                    auto cert_framed = frame_handshake(s, 11, cert_body, 0, (uint32_t)cert_body.size());
                    s.send_msg_seq++;
                    transcript_add(s, cert_framed);
                    auto skx_body = build_skx_body(s, *cert);
                    auto skx_framed = frame_handshake(s, 12, skx_body, 0, (uint32_t)skx_body.size());
                    s.send_msg_seq++;
                    transcript_add(s, skx_framed);
                    auto shd_framed = frame_handshake(s, 14, {}, 0, 0);
                    s.send_msg_seq++;
                    transcript_add(s, shd_framed);

                    std::vector<uint8_t> flight;
                    for (auto* m : {&sh_framed, &cert_framed, &skx_framed, &shd_framed}) {
                        auto rec = plaintext_record(22, 0, s.send_seq++, m->data(), m->size());
                        flight.insert(flight.end(), rec.begin(), rec.end());
                    }
                    response = std::move(flight);
                    build_response = true;
                }
                return true;
            }
            case DTLShandshakeType::CLIENT_KEY_EXCHANGE: {
                if (dtls13) return false;
                if (body.size() < 1) return false;
                size_t pub_len = body[0];
                if (body.size() < 1 + pub_len) return false;
                if (!ecdh_derive(s, body.data() + 1, pub_len)) return false;
                transcript_add_msg(s, mtype, mseq, body, false);
                return true;
            }
            case DTLShandshakeType::FINISHED: {
                bool sha384 = suite_use_sha384(s.cipher_suite);
                size_t hl = suite_hash_len(s.cipher_suite);
                if (dtls13) {
                    if (body.size() != hl) return false;
                    uint8_t fk[48];
                    // RFC 8446 4.4.4: finished_key 基于 client handshake traffic secret
                    expand_label13(s.client_hs_traffic, "finished", nullptr, 0, fk, hl, sha384);
                    transcript_compute(s);
                    uint8_t mac[48];
                    if (sha384) hmac_sha384(fk, hl, s.transcript_hash, hl, mac);
                    else hmac_sha256(fk, hl, s.transcript_hash, hl, mac);
                    if (memcmp(mac, body.data(), hl) != 0) return false;
                    transcript_add_msg(s, mtype, mseq, body, true);
                    auto ack_body = build_ack_body(s);
                    response = dtls13_protect(s, 26, ack_body.data(), ack_body.size());
                    build_response = true;
                    s.peer_finished = true;
                    s.handshake_done = true;
                    s.send_epoch = 3; s.send_seq = 0;
                    done = true;
                } else {
                    if (body.size() != 12) return false;
                    transcript_compute(s);
                    std::vector<uint8_t> hbuf(s.transcript_hash, s.transcript_hash + hl);
                    uint8_t expected[12];
                    prf12(s.master_secret, 48, "client finished", hbuf.data(), hbuf.size(), expected, 12, sha384);
                    if (memcmp(expected, body.data(), 12) != 0) return false;
                    transcript_add_msg(s, mtype, mseq, body, false);
                    std::vector<uint8_t> flight;
                    uint8_t one = 1;
                    auto ccs_rec = plaintext_record(20, 0, s.send_seq++, &one, 1);
                    flight.insert(flight.end(), ccs_rec.begin(), ccs_rec.end());
                    s.send_epoch = 1; s.send_seq = 0;
                    auto fin_body = build_finished12(s, true);
                    auto fin_framed = frame_handshake(s, 20, fin_body, 0, (uint32_t)fin_body.size());
                    s.send_msg_seq++;
                    transcript_add(s, fin_framed);
                    auto fin_rec = dtls12_protect(s, 22, fin_framed.data(), fin_framed.size());
                    flight.insert(flight.end(), fin_rec.begin(), fin_rec.end());
                    response = std::move(flight);
                    build_response = true;
                    s.peer_finished = true;
                    s.handshake_done = true;
                    done = true;
                }
                return true;
            }
            default:
                return true;
        }
    };

    auto feed = [&](const std::vector<dtls_event>& evs) -> bool {
        std::vector<uint8_t> hb;
        for (auto& ev : evs) {
            if (ev.type == 22) {
                hb.insert(hb.end(), ev.payload.begin(), ev.payload.end());
                if (dtls13) s.received_records.push_back({ev.epoch, ev.seq});
            }
        }
        return collect_handshake(s, hb, process);
    };

    if (!feed(events)) {
        r.ok = false;
        if (r.error.empty()) r.error = "handshake message error";
        return r;
    }
    // retry pending encrypted records (keys derived by handshake messages above)
    for (int pg = 0; !pending.empty() && pg < 10; ++pg) {
        std::vector<uint8_t> pending2;
        std::vector<dtls_event> more;
        bool okp = dtls13 ? parse_dtls13_datagram(s, pending.data(), pending.size(), more, pending2)
                          : parse_dtls12_datagram(s, pending.data(), pending.size(), more, pending2);
        if (!okp) break;
        pending = std::move(pending2);
        if (!feed(more)) {
            r.ok = false;
            if (r.error.empty()) r.error = "handshake message error";
            return r;
        }
    }

    if (build_response) {
        r.out = std::move(response);
        s.last_sent = r.out;
    } else if (s.retransmit_requested && !s.last_sent.empty()) {
        r.out = s.last_sent;
    }
    s.retransmit_requested = false;
    r.done = done;
    return r;
}

// ---- public API ----------------------------------------------------------
dtls_step_result dtls_handshake_step(dtls_session& s, const dtls_handshake_input& in) {
    if (s.is_server) return server_step(s, in);
    return client_step(s, in);
}

std::vector<uint8_t> dtls_protect_application(dtls_session& s,
                                              const uint8_t* data, size_t len) {
    std::vector<uint8_t> out;
    const size_t max_record = 1200;
    size_t off = 0;
    while (off < len) {
        size_t n = std::min<size_t>(len - off, max_record);
        std::vector<uint8_t> rec;
        if (s.ver == DTLSVersion::V12)
            rec = dtls12_protect(s, 23, data + off, n);
        else
            rec = dtls13_protect(s, 23, data + off, n);
        out.insert(out.end(), rec.begin(), rec.end());
        off += n;
    }
    return out;
}

bool dtls_unprotect_application(dtls_session& s, const uint8_t* datagram, size_t len,
                                std::vector<uint8_t>& out) {
    std::vector<dtls_event> events;
    std::vector<uint8_t> pending;
    bool parsed = (s.ver == DTLSVersion::V12)
        ? parse_dtls12_datagram(s, datagram, len, events, pending)
        : parse_dtls13_datagram(s, datagram, len, events, pending);
    if (!parsed) return false;
    bool any = false;
    for (auto& ev : events) {
        if (ev.type == 23) {
            out.insert(out.end(), ev.payload.begin(), ev.payload.end());
            any = true;
        }
    }
    return any;
}

// ---- UDP socket wrapper (dtls_connection) --------------------------------
#ifdef _WIN32
using sock_t = SOCKET;
#define SOCKET_INVALID INVALID_SOCKET
#define SOCKET_CLOSE(s) closesocket(s)
#else
using sock_t = int;
#define SOCKET_INVALID (-1)
#define SOCKET_CLOSE(s) ::close(s)
#endif

static bool dtls_socket_init(std::string* err = nullptr) {
#ifdef _WIN32
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] { WSADATA wsa; ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0); });
    if (!ok && err) *err = "WSAStartup failed";
    return ok;
#else
    (void)err;
    return true;
#endif
}

static bool sock_set_nonblocking(sock_t fd, bool on) {
#ifdef _WIN32
    u_long mode = on ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return false;
    if (on) fl |= O_NONBLOCK; else fl &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, fl) == 0;
#endif
}

static bool sock_wait_readable(sock_t fd, int timeout_ms) {
#ifdef _WIN32
    fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
    timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select(0, &fds, nullptr, nullptr, &tv);
    return rc > 0;
#else
    pollfd pfd; pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
    return ::poll(&pfd, 1, timeout_ms) > 0;
#endif
}

static bool sock_send(sock_t fd, const uint8_t* data, size_t len) {
#ifdef _WIN32
    int rc = send(fd, (const char*)data, (int)len, 0);
#else
    int rc = (int)::send(fd, data, len, 0);
#endif
    return rc == (int)len;
}

static int sock_recv(sock_t fd, uint8_t* buf, size_t cap) {
#ifdef _WIN32
    int n = recv(fd, (char*)buf, (int)cap, 0);
#else
    int n = (int)::recv(fd, buf, cap, 0);
#endif
    return n;
}

static int sock_recvfrom(sock_t fd, uint8_t* buf, size_t cap, sockaddr_in* src) {
#ifdef _WIN32
    int len = (int)sizeof(*src);
    int n = recvfrom(fd, (char*)buf, (int)cap, 0, (sockaddr*)src, &len);
#else
    socklen_t len = sizeof(*src);
    int n = (int)::recvfrom(fd, buf, cap, 0, (sockaddr*)src, &len);
#endif
    return n;
}

dtls_connection::dtls_connection() { dtls_socket_init(); }
dtls_connection::~dtls_connection() { close(); }

void dtls_connection::close() {
    if (open_) {
        SOCKET_CLOSE((sock_t)(intptr_t)sock_);
        open_ = false;
    }
}

uint16_t dtls_connection::local_port() const {
    if (!open_) return 0;
    sockaddr_in sa{};
#ifdef _WIN32
    int len = (int)sizeof(sa);
#else
    socklen_t len = sizeof(sa);
#endif
    if (getsockname((sock_t)(intptr_t)sock_, (sockaddr*)&sa, &len) != 0) return 0;
    return ntohs(sa.sin_port);
}

// 剩余握手预算（毫秒）；<=0 表示已超时
static int hs_remaining(const std::chrono::steady_clock::time_point& t0, int budget_ms) {
    auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    return budget_ms - (int)el;
}

bool dtls_connection::connect(const char* host, uint16_t port,
                              const tls::tls_trust_store* trust_store) {
    dtls_socket_init();
    s_ = dtls_session{};
    s_.ver = ver_;
    s_.is_server = false;
    s_.server_name = server_name_;
    s_.cipher_suite = cipher_suite_;
    s_.ks_group = ks_group_;

    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char portstr[16]; snprintf(portstr, sizeof(portstr), "%u", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return false;

    sock_t fd = SOCKET_INVALID;
    for (auto* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd != SOCKET_INVALID) break;
    }
    if (fd == SOCKET_INVALID) { freeaddrinfo(res); return false; }
    if (::connect(fd, res->ai_addr, (int)res->ai_addrlen) != 0) { freeaddrinfo(res); SOCKET_CLOSE(fd); return false; }
    freeaddrinfo(res);
#ifdef _WIN32
    sock_ = (void*)(intptr_t)fd;
#else
    sock_ = fd;
#endif
    open_ = true;
    is_server_ = false;
    sock_set_nonblocking(fd, false);

    dtls_handshake_input in;
    in.trust_store = trust_store;

    auto step = dtls_handshake_step(s_, in);
    if (!step.ok) { last_error_ = step.error; close(); return false; }
    if (!step.out.empty()) {
        if (!sock_send(fd, step.out.data(), step.out.size())) { close(); return false; }
    }

    int timeout_ms = 500;
    int retries = 0;
    std::vector<uint8_t> buf(65536);
    auto hs_t0 = std::chrono::steady_clock::now();
    while (!step.done) {
        int wait_ms = timeout_ms;
        int remain = hs_remaining(hs_t0, handshake_timeout_ms_);
        if (remain <= 0) { last_error_ = "handshake timeout"; close(); return false; }
        if (wait_ms > remain) wait_ms = remain;
        if (!sock_wait_readable(fd, wait_ms)) {
            if (retries++ >= 8) { last_error_ = "handshake retries exhausted"; close(); return false; }
            timeout_ms *= 2;
            if (!s_.last_sent.empty() && !sock_send(fd, s_.last_sent.data(), s_.last_sent.size()))
                { close(); return false; }
            continue;
        }
        int n = sock_recv(fd, buf.data(), (int)buf.size());
        if (n <= 0) {
#ifdef _WIN32
            char eb[64]; snprintf(eb, sizeof(eb), "recv failed (wsa=%d)", WSAGetLastError());
            last_error_ = eb;
#else
            char eb[64]; snprintf(eb, sizeof(eb), "recv failed (errno=%d)", errno);
            last_error_ = eb;
#endif
            close(); return false;
        }
        dtls_handshake_input in2;
        in2.datagram = buf.data(); in2.datagram_len = (size_t)n;
        in2.trust_store = trust_store;
        step = dtls_handshake_step(s_, in2);
        if (!step.ok) { last_error_ = step.error; close(); return false; }
        if (!step.out.empty()) {
            if (!sock_send(fd, step.out.data(), step.out.size()))
                { close(); return false; }
        }
        timeout_ms = 500; retries = 0;
    }
    done_ = true;
    return true;
}

bool dtls_connection::bind(uint16_t port, const char* addr) {
    dtls_socket_init();
    sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == SOCKET_INVALID) return false;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_pton(AF_INET, addr, &sa.sin_addr) != 1) { SOCKET_CLOSE(fd); return false; }
    if (::bind(fd, (sockaddr*)&sa, sizeof(sa)) != 0) { SOCKET_CLOSE(fd); return false; }
#ifdef _WIN32
    sock_ = (void*)(intptr_t)fd;
#else
    sock_ = fd;
#endif
    open_ = true;
    is_server_ = true;
    return true;
}

bool dtls_connection::server_handshake(tls::tls_certificate_manager& cert_mgr) {
    if (!open_) return false;
    sock_t fd = (sock_t)(intptr_t)sock_;
    sock_set_nonblocking(fd, false);

    s_ = dtls_session{};
    s_.ver = ver_;
    s_.is_server = true;
    s_.cipher_suite = cipher_suite_;
    s_.ks_group = ks_group_;
    s_.require_cookie = require_cookie_;

    std::vector<uint8_t> buf(65536);
    bool done = false;
    bool peer_set = false;
    int timeout_ms = 500, retries = 0;
    auto hs_t0 = std::chrono::steady_clock::now();
    while (!done) {
        int wait_ms = timeout_ms;
        int remain = hs_remaining(hs_t0, handshake_timeout_ms_);
        if (remain <= 0) { last_error_ = "handshake timeout"; close(); return false; }
        if (wait_ms > remain) wait_ms = remain;
        if (!sock_wait_readable(fd, wait_ms)) {
            if (retries++ >= 8) { last_error_ = "handshake retries exhausted"; close(); return false; }
            timeout_ms *= 2;
            if (!s_.last_sent.empty() && !sock_send(fd, s_.last_sent.data(), s_.last_sent.size()))
                { close(); return false; }
            continue;
        }
        int n;
        if (!peer_set) {
            // 首个数据报：recvfrom 取得客户端地址并 connect，之后 send/recv 直达
            sockaddr_in src{};
            n = sock_recvfrom(fd, buf.data(), (int)buf.size(), &src);
            if (n > 0) {
                if (::connect(fd, (sockaddr*)&src, sizeof(src)) != 0) {
                    last_error_ = "peer connect failed"; close(); return false;
                }
                peer_set = true;
            }
        } else {
            n = sock_recv(fd, buf.data(), (int)buf.size());
        }
        if (n <= 0) {
#ifdef _WIN32
            char eb[64]; snprintf(eb, sizeof(eb), "recv failed (wsa=%d)", WSAGetLastError());
            last_error_ = eb;
#else
            char eb[64]; snprintf(eb, sizeof(eb), "recv failed (errno=%d)", errno);
            last_error_ = eb;
#endif
            close(); return false;
        }
        dtls_handshake_input in;
        in.datagram = buf.data(); in.datagram_len = (size_t)n;
        in.cert_manager = &cert_mgr;
        auto step = dtls_handshake_step(s_, in);
        if (!step.ok) {
            last_error_ = "step: " + step.error; close(); return false;
        }
        if (!step.out.empty()) {
            if (!sock_send(fd, step.out.data(), step.out.size()))
                { close(); return false; }
        }
        done = step.done;
        timeout_ms = 500; retries = 0;
    }
    done_ = true;
    return true;
}

bool dtls_connection::send(const uint8_t* data, size_t len) {
    if (!done_ || !open_) return false;
    auto records = dtls_protect_application(s_, data, len);
    if (records.empty() && len > 0) return false;
    return sock_send((sock_t)(intptr_t)sock_, records.data(), records.size());
}

bool dtls_connection::recv(std::vector<uint8_t>& data) {
    if (!done_ || !open_) return false;
    sock_t fd = (sock_t)(intptr_t)sock_;
    std::vector<uint8_t> buf(65536);
    while (true) {
        if (!sock_wait_readable(fd, 30000)) return false;
        int n = sock_recv(fd, buf.data(), (int)buf.size());
        if (n <= 0) return false;
        std::vector<uint8_t> out;
        if (!dtls_unprotect_application(s_, buf.data(), (size_t)n, out)) continue;
        if (!out.empty()) { data = std::move(out); return true; }
        // 握手/ACK 等非应用记录：继续等待应用数据
    }
}

} // namespace dtls
} // namespace jpssl
