/**
 * test_sm4_ccm.cpp - SM4-CCM tests.
 *
 * 1. Independent reference implementation (built on sm4_encrypt_block)
 *    validates the scalar backend against the CCM spec layout used by
 *    this library (B0 with M=16, L=q-1; zero-padded CBC-MAC segments).
 * 2. Auto dispatch must match the scalar backend byte-for-byte.
 * 3. The explicit GFNI backend (when compiled in and the CPU supports it)
 *    must match the scalar backend byte-for-byte for encryption and
 *    decrypt round-trips, in-place variants, and tamper rejection.
 */
#include "sm4.hpp"
#include "sm4_ccm.hpp"
#include "cipher_inplace.hpp"
#include "cpu_features.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s\n", msg); std::exit(1); } \
    else { std::printf("  PASS: %s\n", msg); } \
} while (0)

using jpssl::sm4_ctx;
using jpssl::sm4_init;
using jpssl::sm4_encrypt_block;
using jpssl::sm4_ccm_encrypt;
using jpssl::sm4_ccm_decrypt;
using jpssl::sm4_ccm_encrypt_auto;
using jpssl::sm4_ccm_decrypt_auto;
using jpssl::sm4_ccm_encrypt_inplace;
using jpssl::sm4_ccm_decrypt_inplace;
using jpssl::sm4_ccm_encrypt_inplace_auto;
using jpssl::sm4_ccm_decrypt_inplace_auto;

// ------------------------------------------------------------------------
//  Independent CCM reference implementation
// ------------------------------------------------------------------------

/// CBC-MAC over one byte range with zero padding to a block boundary,
/// starting from the current `mac` state (16-byte blocks).
static void ref_ccm_mac(sm4_ctx* ctx, uint8_t mac[16],
                        const uint8_t* data, size_t len) {
    uint8_t buf[16] = {};
    size_t pos = 0;
    while (pos + 16 <= len) {
        for (int i = 0; i < 16; ++i) mac[i] ^= data[pos + i];
        sm4_encrypt_block(ctx, mac, mac);
        pos += 16;
    }
    if (pos < len) {
        std::memset(buf, 0, 16);
        std::memcpy(buf, data + pos, len - pos);
        for (int i = 0; i < 16; ++i) mac[i] ^= buf[i];
        sm4_encrypt_block(ctx, mac, mac);
    }
}

/// Reference SM4-CCM encrypt (spec layout identical to the library scalar
/// backend: B0 flags = Adata|M=16|L=q-1; counter 0 keeps only L flags).
static void ref_ccm_encrypt(sm4_ctx* ctx,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* pt, size_t pt_len,
                            const uint8_t* aad, size_t aad_len,
                            uint8_t* ct, uint8_t* tag, size_t tag_len) {
    const size_t q = 15 - nonce_len;
    uint8_t b0[16] = {}, ctr0[16] = {};
    b0[0] = (uint8_t)((aad_len ? 0x40 : 0) | (7 << 3) | (q - 1));
    std::memcpy(b0 + 1, nonce, nonce_len);
    size_t m = pt_len;
    for (int i = 15; i >= 16 - (int)q; --i) {
        b0[i] = (uint8_t)(m & 0xFF);
        m >>= 8;
    }
    // A0: only the L flags (M/Adata bits cleared), zeroed counter field.
    ctr0[0] = (uint8_t)((q - 1) & 7);
    std::memcpy(ctr0 + 1, nonce, nonce_len);

    uint8_t mac[16] = {};
    ref_ccm_mac(ctx, mac, b0, 16);
    if (aad_len) {
        uint8_t prefix[8];
        size_t plen = 0;
        if (aad_len < 65280) {
            prefix[plen++] = (uint8_t)(aad_len >> 8);
            prefix[plen++] = (uint8_t)(aad_len & 0xFF);
        } else {
            prefix[plen++] = 0xFF;
            prefix[plen++] = 0xFE;
            prefix[plen++] = (uint8_t)(aad_len >> 24);
            prefix[plen++] = (uint8_t)(aad_len >> 16);
            prefix[plen++] = (uint8_t)(aad_len >> 8);
            prefix[plen++] = (uint8_t)(aad_len & 0xFF);
        }
        // AAD segment: prefix || AAD padded as one stream.
        std::vector<uint8_t> aadseg;
        aadseg.insert(aadseg.end(), prefix, prefix + plen);
        aadseg.insert(aadseg.end(), aad, aad + aad_len);
        ref_ccm_mac(ctx, mac, aadseg.data(), aadseg.size());
    }
    ref_ccm_mac(ctx, mac, pt, pt_len);

    uint8_t enc_mac[16];
    sm4_encrypt_block(ctx, ctr0, enc_mac);
    for (size_t i = 0; i < tag_len; ++i)
        tag[i] = mac[i] ^ enc_mac[i];

    // CTR from counter 1 (last q bytes, big-endian increment).
    // Data counters start at A1 = A0 + 1.
    uint8_t ctr[16];
    std::memcpy(ctr, ctr0, 16);
    for (int i = 15; i >= 16 - (int)q; --i) {
        if (++ctr[i] != 0) break;
    }
    size_t pos = 0;
    while (pos < pt_len) {
        uint8_t ks[16];
        sm4_encrypt_block(ctx, ctr, ks);
        size_t n = (pt_len - pos < 16) ? (pt_len - pos) : 16;
        for (size_t i = 0; i < n; ++i)
            ct[pos + i] = pt[pos + i] ^ ks[i];
        pos += n;
        for (int i = 15; i >= 16 - (int)q; --i) {
            if (++ctr[i] != 0) break;
        }
    }
}

// ------------------------------------------------------------------------
//  Tests
// ------------------------------------------------------------------------

static void test_against_reference() {
    std::printf("\n=== SM4-CCM vs independent reference ===\n");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    sm4_ctx ctx;
    sm4_init(&ctx, key);

    const size_t lens[] = {0, 1, 15, 16, 17, 31, 63, 100, 4096};
    const size_t nonce_lens[] = {7, 8, 11, 12, 13};
    for (size_t nl : nonce_lens) {
        for (size_t len : lens) {
            if (nl == 13 && len > 0xFFFF) continue; // q=2 limit
            std::vector<uint8_t> nonce(nl), plain(len), aad;
            for (size_t i = 0; i < nl; ++i) nonce[i] = (uint8_t)(i * 5 + 1);
            for (size_t i = 0; i < len; ++i) plain[i] = (uint8_t)(i * 7 + 3);
            if (len % 2 == 0) {
                aad.resize(300);
                for (size_t i = 0; i < aad.size(); ++i)
                    aad[i] = (uint8_t)(i * 3 + 9);
            }

            std::vector<uint8_t> ref_ct(len), jp_ct;
            uint8_t ref_tag[16], jp_tag[16];
            ref_ccm_encrypt(&ctx, nonce.data(), nl, plain.data(), len,
                            aad.data(), aad.size(), ref_ct.data(), ref_tag, 16);
            sm4_ccm_encrypt(&ctx, nonce.data(), nl,
                            std::span<const uint8_t>(plain),
                            std::span<const uint8_t>(aad),
                            jp_ct, jp_tag, 16);

            std::string label = "ref CCM nonce=" + std::to_string(nl) +
                                " len=" + std::to_string(len) +
                                " aad=" + std::to_string(aad.size());
            ASSERT(jp_ct == ref_ct && std::memcmp(jp_tag, ref_tag, 16) == 0,
                   label.c_str());
        }
    }
}

static void test_dispatch_matrix() {
    std::printf("\n=== SM4-CCM scalar / auto / GFNI dispatch matrix ===\n");

    uint8_t key[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                       0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
    sm4_ctx ctx;
    sm4_init(&ctx, key);

    const bool has_gfni = jpssl::cpu_has_gfni();
    int level = jpssl::sm4_ccm_auto_level();
    ASSERT(level == (has_gfni && jpssl::cpu_has_avx2() ? 1 : 0),
           "SM4-CCM auto level matches cpu_has_gfni()/cpu_has_avx2()");

    const size_t lens[] = {0, 1, 15, 16, 17, 63, 127, 128, 129, 255,
                           256, 1000, 4095, 4096, 16384};
    const size_t nonce_lens[] = {7, 8, 11, 12, 13};
    const size_t tag_lens[] = {4, 8, 12, 16};
    const bool aad_cases[] = {false, true};

    int total = 0;
    for (size_t nl : nonce_lens) {
        for (size_t len : lens) {
            if (nl == 13 && len > 0xFFFF) continue;
            for (size_t tl : tag_lens) {
                for (bool use_aad : aad_cases) {
                    std::vector<uint8_t> nonce(nl), plain(len), aad;
                    for (size_t i = 0; i < nl; ++i)
                        nonce[i] = (uint8_t)(i * 13 + 7);
                    for (size_t i = 0; i < len; ++i)
                        plain[i] = (uint8_t)(i * 29 + 11);
                    if (use_aad) {
                        aad.resize(300);
                        for (size_t i = 0; i < aad.size(); ++i)
                            aad[i] = (uint8_t)(i * 17 + 5);
                    }

                    const std::span<const uint8_t> p_span(plain), a_span(aad);

                    // Scalar reference.
                    std::vector<uint8_t> ct_cpu;
                    uint8_t tag_cpu[16];
                    sm4_ccm_encrypt(&ctx, nonce.data(), nl, p_span, a_span,
                                    ct_cpu, tag_cpu, tl);

                    // Auto must be byte-identical.
                    std::vector<uint8_t> ct_auto;
                    uint8_t tag_auto[16];
                    sm4_ccm_encrypt_auto(&ctx, nonce.data(), nl, p_span, a_span,
                                         ct_auto, tag_auto, tl);
                    ASSERT(ct_auto == ct_cpu &&
                               std::memcmp(tag_auto, tag_cpu, tl) == 0,
                           ("CCM auto==CPU nl=" + std::to_string(nl) +
                            " len=" + std::to_string(len) +
                            " tl=" + std::to_string(tl)).c_str());

                    // Auto decrypt round-trip.
                    std::vector<uint8_t> pt_auto;
                    bool ok = sm4_ccm_decrypt_auto(
                        &ctx, nonce.data(), nl,
                        std::span<const uint8_t>(ct_auto), a_span,
                        tag_auto, tl, pt_auto);
                    ASSERT(ok && pt_auto == plain, "CCM auto decrypt round-trip");

                    // In-place auto encrypt == vector encrypt.
                    std::vector<uint8_t> buf(plain);
                    uint8_t tag_inp[16];
                    sm4_ccm_encrypt_inplace_auto(&ctx, nonce.data(), nl,
                                                 buf.data(), buf.size(),
                                                 a_span, tag_inp, tl);
                    ASSERT(buf == ct_auto &&
                               std::memcmp(tag_inp, tag_auto, tl) == 0,
                           "CCM inplace auto == vector auto");

                    // In-place auto decrypt round-trip.
                    std::memcpy(buf.data(), ct_auto.data(), ct_auto.size());
                    bool ok_inp = sm4_ccm_decrypt_inplace_auto(
                        &ctx, nonce.data(), nl, buf.data(), buf.size(),
                        a_span, tag_auto, tl);
                    ASSERT(ok_inp && buf == plain,
                           "CCM inplace auto decrypt round-trip");

                    // Tamper: flipped tag / ciphertext byte must be rejected.
                    uint8_t bad_tag[16];
                    std::memcpy(bad_tag, tag_auto, 16);
                    bad_tag[0] ^= 0x01;
                    std::vector<uint8_t> pt_bad;
                    ASSERT(!sm4_ccm_decrypt_auto(
                               &ctx, nonce.data(), nl,
                               std::span<const uint8_t>(ct_auto), a_span,
                               bad_tag, tl, pt_bad),
                           "CCM auto rejects tampered tag");

                    if (!ct_auto.empty()) {
                        std::vector<uint8_t> ct_bad = ct_auto;
                        ct_bad[ct_bad.size() / 2] ^= 0x80;
                        ASSERT(!sm4_ccm_decrypt_auto(
                                   &ctx, nonce.data(), nl,
                                   std::span<const uint8_t>(ct_bad), a_span,
                                   tag_auto, tl, pt_bad),
                               "CCM auto rejects tampered ciphertext");
                    }

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
                    if (has_gfni) {
                        // Explicit GFNI backend == scalar.
                        std::vector<uint8_t> ct_gfni;
                        uint8_t tag_gfni[16];
                        jpssl::sm4_ccm_encrypt_gfni(
                            &ctx, nonce.data(), nl, p_span, a_span,
                            ct_gfni, tag_gfni, tl);
                        ASSERT(ct_gfni == ct_cpu &&
                                   std::memcmp(tag_gfni, tag_cpu, tl) == 0,
                               "CCM GFNI==CPU");

                        std::vector<uint8_t> pt_gfni;
                        bool ok_gfni = jpssl::sm4_ccm_decrypt_gfni(
                            &ctx, nonce.data(), nl,
                            std::span<const uint8_t>(ct_gfni), a_span,
                            tag_gfni, tl, pt_gfni);
                        ASSERT(ok_gfni && pt_gfni == plain,
                               "CCM GFNI decrypt round-trip");

                        // In-place GFNI == vector GFNI.
                        std::vector<uint8_t> gbuf(plain);
                        uint8_t gtag[16];
                        jpssl::sm4_ccm_encrypt_gfni_inplace(
                            &ctx, nonce.data(), nl, gbuf.data(), gbuf.size(),
                            a_span, gtag, tl);
                        ASSERT(gbuf == ct_gfni &&
                                   std::memcmp(gtag, tag_gfni, tl) == 0,
                               "CCM GFNI inplace == vector");

                        std::memcpy(gbuf.data(), ct_gfni.data(), ct_gfni.size());
                        bool ok_ginp = jpssl::sm4_ccm_decrypt_gfni_inplace(
                            &ctx, nonce.data(), nl, gbuf.data(), gbuf.size(),
                            a_span, tag_gfni, tl);
                        ASSERT(ok_ginp && gbuf == plain,
                               "CCM GFNI inplace decrypt round-trip");

                        std::vector<uint8_t> gbad;
                        uint8_t gbad_tag[16];
                        std::memcpy(gbad_tag, tag_gfni, 16);
                        gbad_tag[0] ^= 0x01;
                        ASSERT(!jpssl::sm4_ccm_decrypt_gfni(
                                   &ctx, nonce.data(), nl,
                                   std::span<const uint8_t>(ct_gfni), a_span,
                                   gbad_tag, tl, gbad),
                               "CCM GFNI rejects tampered tag");
                    }
#endif
                    ++total;
                }
            }
        }
    }
    std::printf("  %d combinations checked (level=%d, GFNI=%s)\n",
                total, level, has_gfni ? "Y" : "N");
}

static void test_large_inplace() {
    std::printf("\n=== SM4-CCM large payload (100 KB, in-place) ===\n");

    uint8_t key[16] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
                       0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};
    sm4_ctx ctx;
    sm4_init(&ctx, key);

    uint8_t nonce[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
    std::vector<uint8_t> aad(1234), plain(100000);
    for (size_t i = 0; i < aad.size(); ++i) aad[i] = (uint8_t)(i & 0xFF);
    for (size_t i = 0; i < plain.size(); ++i) plain[i] = (uint8_t)(i >> 8);

    std::span<const uint8_t> a_span(aad);

    // Scalar vector encrypt as the reference.
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    sm4_ccm_encrypt(&ctx, nonce, 12, std::span<const uint8_t>(plain),
                    a_span, ct, tag, 16);

    // In-place auto encrypt must be byte-identical.
    std::vector<uint8_t> buf(plain);
    uint8_t tag_inp[16];
    sm4_ccm_encrypt_inplace_auto(&ctx, nonce, 12, buf.data(), buf.size(),
                                 a_span, tag_inp, 16);
    ASSERT(buf == ct && std::memcmp(tag_inp, tag, 16) == 0,
           "large in-place auto == scalar vector");

    // In-place auto decrypt round-trip.
    std::memcpy(buf.data(), ct.data(), ct.size());
    bool ok = sm4_ccm_decrypt_inplace_auto(&ctx, nonce, 12, buf.data(),
                                           buf.size(), a_span, tag, 16);
    ASSERT(ok && buf == plain, "large in-place auto decrypt round-trip");
}

int main() {
    std::printf("jpssl SM4-CCM Tests\n");
    std::printf("===================\n");

    test_against_reference();
    test_dispatch_matrix();
    test_large_inplace();

    std::printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
