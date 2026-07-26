/**
 * aes_ccm.cpp — AES-CCM 认证加密（AES-NI 加速 + 软件回退）
 *
 * NIST SP 800-38C / RFC 3610
 * 使用 AES-NI 指令 (_mm_aesenc_si128 / _mm_aesenclast_si128) 直接实现
 * 块加密核心，避免 aes_encrypt_block 函数调用开销。
 * 非 x86_64 或无 AES-NI 时自动回退到软件实现。
 */

#include "aes.hpp"
#include "cpu_features.hpp"
#include <cstring>

#ifdef __x86_64__
#include <wmmintrin.h>   // AES-NI intrinsics
#include <emmintrin.h>   // SSE2
#endif

namespace jpssl {

// ──────────────────────────────────────────────────────────────────────────
//  AES-NI 内联加密核心
// ──────────────────────────────────────────────────────────────────────────

#ifdef __x86_64__

/// 用 AES-NI 加密单个 16 字节块（零函数调用开销的内联版本）
/// @param enc_rk  轮密钥数组 (_m128i*)，长度 = rounds + 1
/// @param rounds  轮数 (10/12/14)
/// @param state   输入明文 16 字节 → 原地输出密文 16 字节
static inline void aesni_encrypt_inplace(const __m128i* enc_rk, int rounds,
                                          uint8_t state[16]) {
    __m128i s = _mm_loadu_si128((const __m128i*)state);
    s = _mm_xor_si128(s, enc_rk[0]);
    for (int r = 1; r < rounds; ++r)
        s = _mm_aesenc_si128(s, enc_rk[r]);
    s = _mm_aesenclast_si128(s, enc_rk[rounds]);
    _mm_storeu_si128((__m128i*)state, s);
}

/// 用 AES-NI 加密单个 16 字节块，目标地址可不同于源地址
static inline void aesni_encrypt_block(const __m128i* enc_rk, int rounds,
                                        const uint8_t plain[16],
                                        uint8_t cipher[16]) {
    __m128i s = _mm_loadu_si128((const __m128i*)plain);
    s = _mm_xor_si128(s, enc_rk[0]);
    for (int r = 1; r < rounds; ++r)
        s = _mm_aesenc_si128(s, enc_rk[r]);
    s = _mm_aesenclast_si128(s, enc_rk[rounds]);
    _mm_storeu_si128((__m128i*)cipher, s);
}

#endif // __x86_64__

// ──────────────────────────────────────────────────────────────────────────
//  计数器增量（大端序）
// ──────────────────────────────────────────────────────────────────────────

/// Increment a big-endian q-byte counter at the end of a 16-byte block
static void inc_counter(uint8_t ctr[16], size_t q) {
    for (int i = 15; i >= 16 - static_cast<int>(q); --i) {
        if (++ctr[i] != 0) break;
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  CCM 加密实现
// ──────────────────────────────────────────────────────────────────────────

void aes_ccm_encrypt(const aes_context& ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len) {

    // ── 参数验证 ──────────────────────────────────────────────────────────
    size_t q = 15 - nonce_len;

    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0)
        throw std::runtime_error("CCM: invalid tag length");
    if (nonce_len < 7 || nonce_len > 13)
        throw std::runtime_error("CCM: invalid nonce length");
    if (plaintext.size() >= (size_t{1} << (q * 8)))
        throw std::runtime_error("CCM: plaintext too large for given nonce length");

    // ── 构建 B0 ───────────────────────────────────────────────────────────
    uint8_t flags = static_cast<uint8_t>(((tag_len - 2) / 2) << 3);
    if (!aad.empty()) flags |= 0x40;
    flags |= static_cast<uint8_t>(q - 1);

    uint8_t B0[16] = {};
    B0[0] = flags;
    std::memcpy(B0 + 1, nonce, nonce_len);
    size_t pt_len = plaintext.size();
    for (size_t i = 0; i < q; ++i) {
        B0[15 - i] = static_cast<uint8_t>(pt_len & 0xFF);
        pt_len >>= 8;
    }

    // ── 构建 MAC 输入 ─────────────────────────────────────────────────────
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), B0, B0 + 16);

    if (!aad.empty()) {
        size_t a_len = aad.size();
        if (a_len < 0xFF00) {
            mac_input.push_back(static_cast<uint8_t>((a_len >> 8) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>(a_len & 0xFF));
        } else {
            mac_input.push_back(0xFF);
            mac_input.push_back(0xFE);
            mac_input.push_back(static_cast<uint8_t>((a_len >> 24) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>((a_len >> 16) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>((a_len >> 8) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>(a_len & 0xFF));
        }
        mac_input.insert(mac_input.end(), aad.begin(), aad.end());
        size_t pad = (16 - (a_len % 16)) % 16;
        mac_input.insert(mac_input.end(), pad, 0);
    }

    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    size_t pt_pad = (16 - (plaintext.size() % 16)) % 16;
    mac_input.insert(mac_input.end(), pt_pad, 0);

    // ── CBC-MAC ───────────────────────────────────────────────────────────
    size_t num_mac_blocks = mac_input.size() / 16;
    uint8_t mac[16] = {};

#ifdef __x86_64__
    if (cpu_has_aesni()) {
        const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
        __m128i mac_state = _mm_setzero_si128();

        for (size_t i = 0; i < num_mac_blocks; ++i) {
            __m128i block = _mm_loadu_si128(
                (const __m128i*)(mac_input.data() + i * 16));
            mac_state = _mm_xor_si128(mac_state, block);
            mac_state = _mm_xor_si128(mac_state, rk[0]);
            for (int r = 1; r < ctx.rounds; ++r)
                mac_state = _mm_aesenc_si128(mac_state, rk[r]);
            mac_state = _mm_aesenclast_si128(mac_state, rk[ctx.rounds]);
        }
        _mm_storeu_si128((__m128i*)mac, mac_state);
    } else
#endif
    {
        for (size_t i = 0; i < num_mac_blocks; ++i) {
            for (int j = 0; j < 16; ++j)
                mac[j] ^= mac_input[i * 16 + j];
            aes_encrypt_block(ctx, mac, mac);
        }
    }

    // ── CTR 模式 keystream 生成 + 加密 ────────────────────────────────────
    size_t num_ctr_blocks = (plaintext.size() + 15) / 16;
    size_t keystream_size = (num_ctr_blocks + 1) * 16;
    std::vector<uint8_t> keystream(keystream_size);

    uint8_t ctr[16] = {};
    ctr[0] = static_cast<uint8_t>(q - 1);
    std::memcpy(ctr + 1, nonce, nonce_len);

#ifdef __x86_64__
    if (cpu_has_aesni()) {
        const __m128i* rk = (const __m128i*)ctx.enc_rk.data();

        // Block 0: keystream[0..15] for tag encryption
        aesni_encrypt_block(rk, ctx.rounds, ctr, keystream.data());

        // Blocks 1..N: keystream for plaintext
        for (size_t i = 1; i <= num_ctr_blocks; ++i) {
            inc_counter(ctr, q);
            aesni_encrypt_block(rk, ctx.rounds, ctr,
                                keystream.data() + i * 16);
        }
    } else
#endif
    {
        for (size_t i = 0; i <= num_ctr_blocks; ++i) {
            if (i > 0) inc_counter(ctr, q);
            aes_encrypt_block(ctx, ctr, keystream.data() + i * 16);
        }
    }

    // ── XOR：ciphertext = plaintext ⊕ keystream[16..] ─────────────────────
    ciphertext.resize(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext[i] = plaintext[i] ^ keystream[16 + i];
    }

    // ── 加密认证标签：tag = mac[0..tag_len] ⊕ keystream[0..tag_len] ──────
    for (size_t i = 0; i < tag_len; ++i) {
        tag[i] = mac[i] ^ keystream[i];
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  CCM 解密 + 验证实现
// ──────────────────────────────────────────────────────────────────────────

bool aes_ccm_decrypt(const aes_context& ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext) {

    // ── 参数验证 ──────────────────────────────────────────────────────────
    size_t q = 15 - nonce_len;

    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0) return false;
    if (nonce_len < 7 || nonce_len > 13) return false;
    if (ciphertext.size() >= (size_t{1} << (q * 8))) return false;

    // ── CTR 模式 keystream 生成 + 解密 ────────────────────────────────────
    size_t num_ctr_blocks = (ciphertext.size() + 15) / 16;
    size_t keystream_size = (num_ctr_blocks + 1) * 16;
    std::vector<uint8_t> keystream(keystream_size);

    uint8_t ctr[16] = {};
    ctr[0] = static_cast<uint8_t>(q - 1);
    std::memcpy(ctr + 1, nonce, nonce_len);

#ifdef __x86_64__
    if (cpu_has_aesni()) {
        const __m128i* rk = (const __m128i*)ctx.enc_rk.data();

        // Block 0: keystream[0..15] for tag verification
        aesni_encrypt_block(rk, ctx.rounds, ctr, keystream.data());

        // Blocks 1..N: keystream for ciphertext
        for (size_t i = 1; i <= num_ctr_blocks; ++i) {
            inc_counter(ctr, q);
            aesni_encrypt_block(rk, ctx.rounds, ctr,
                                keystream.data() + i * 16);
        }
    } else
#endif
    {
        for (size_t i = 0; i <= num_ctr_blocks; ++i) {
            if (i > 0) inc_counter(ctr, q);
            aes_encrypt_block(ctx, ctr, keystream.data() + i * 16);
        }
    }

    // ── XOR：plaintext = ciphertext ⊕ keystream[16..] ─────────────────────
    plaintext.resize(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext[i] = ciphertext[i] ^ keystream[16 + i];
    }

    // ── 构建 MAC 输入 ─────────────────────────────────────────────────────
    uint8_t flags = static_cast<uint8_t>(((tag_len - 2) / 2) << 3);
    if (!aad.empty()) flags |= 0x40;
    flags |= static_cast<uint8_t>(q - 1);

    uint8_t B0[16] = {};
    B0[0] = flags;
    std::memcpy(B0 + 1, nonce, nonce_len);
    size_t pt_len = plaintext.size();
    for (size_t i = 0; i < q; ++i) {
        B0[15 - i] = static_cast<uint8_t>(pt_len & 0xFF);
        pt_len >>= 8;
    }

    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), B0, B0 + 16);

    if (!aad.empty()) {
        size_t a_len = aad.size();
        if (a_len < 0xFF00) {
            mac_input.push_back(static_cast<uint8_t>((a_len >> 8) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>(a_len & 0xFF));
        } else {
            mac_input.push_back(0xFF);
            mac_input.push_back(0xFE);
            mac_input.push_back(static_cast<uint8_t>((a_len >> 24) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>((a_len >> 16) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>((a_len >> 8) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>(a_len & 0xFF));
        }
        mac_input.insert(mac_input.end(), aad.begin(), aad.end());
        size_t pad = (16 - (a_len % 16)) % 16;
        mac_input.insert(mac_input.end(), pad, 0);
    }

    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    size_t pt_pad = (16 - (plaintext.size() % 16)) % 16;
    mac_input.insert(mac_input.end(), pt_pad, 0);

    // ── CBC-MAC ───────────────────────────────────────────────────────────
    size_t num_mac_blocks = mac_input.size() / 16;
    uint8_t mac[16] = {};

#ifdef __x86_64__
    if (cpu_has_aesni()) {
        const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
        __m128i mac_state = _mm_setzero_si128();

        for (size_t i = 0; i < num_mac_blocks; ++i) {
            __m128i block = _mm_loadu_si128(
                (const __m128i*)(mac_input.data() + i * 16));
            mac_state = _mm_xor_si128(mac_state, block);
            mac_state = _mm_xor_si128(mac_state, rk[0]);
            for (int r = 1; r < ctx.rounds; ++r)
                mac_state = _mm_aesenc_si128(mac_state, rk[r]);
            mac_state = _mm_aesenclast_si128(mac_state, rk[ctx.rounds]);
        }
        _mm_storeu_si128((__m128i*)mac, mac_state);
    } else
#endif
    {
        for (size_t i = 0; i < num_mac_blocks; ++i) {
            for (int j = 0; j < 16; ++j)
                mac[j] ^= mac_input[i * 16 + j];
            aes_encrypt_block(ctx, mac, mac);
        }
    }

    // ── 标签验证（常数时间）───────────────────────────────────────────────
    uint8_t expected_tag[16];
    for (size_t i = 0; i < tag_len; ++i) {
        expected_tag[i] = mac[i] ^ keystream[i];
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i) {
        diff |= tag[i] ^ expected_tag[i];
    }

    return diff == 0;
}

} // namespace jpssl
