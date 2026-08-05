/**
 * ed25519_batch_cpu.cpp — Ed25519 批量验证（真·多标量批验证）
 *
 * 实现：随机 128 位盲化后的单点多标量乘法
 *
 *    Σ z_i·s_i·B + Σ z_i·k_i·A_i + Σ (l − z_i)·R_i = O
 *
 * 与逐条调用 ed25519_verify 相比：
 *  - 全部 2N+1 个点共享同一条倍点链（64 个 4-bit 窗口，每个窗口只做
 *    N 次部分加，而非每条签名独立做 256 次倍点）
 *  - 各点的预计算表用一次批量求逆完成仿射化
 *  - z_i 为每签名 128 位随机盲化因子，保证任一伪造签名使整条方程
 *    以 1 − 2^−128 概率非零（防批量伪造放大攻击）
 *
 * 算法为可变时间（验签输入均为公开数据，与常数时间签名路径无关）。
 */
#include "ed25519_batch.hpp"
#include "fe_25519_r51.hpp"
#include "sha512.hpp"
#include "rand_os.hpp"

#include <cstring>

namespace jpssl { namespace ed25519_r51_batch_impl { namespace {

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

#define JPSSL_ED25519_R51
#define JPSSL_ED25519_NO_PUBLIC_API
#include "ed25519_body.inc"   // 内含 } // anonymous namespace 闭合
#undef JPSSL_ED25519_NO_PUBLIC_API
#undef JPSSL_ED25519_R51

// ── 批量参数 ──

/// 单次批验证的签名数上限（表内存 ~0.6 MB / 线程）
static constexpr int kBatchChunk = 128;

/// 4-bit 有符号窗口重编码：digits[w] ∈ [-8, 7]，Σ digits[w]·2^(4w) = scalar
/// 每窗口恰好对应 4 个二进制位，进位在重编码内部消化（小端位序）。
/// 标量 < l < 2^253 ⇒ 顶窗口（bits 252..255）值 ≤ 2，不会溢出第 64 窗口。
static void recode_window4(int8_t digits[64], const uint8_t scalar[32]) {
    int carry = 0;
    for (int w = 0; w < 64; ++w) {
        int v = carry;  // 进位必须与窗口位相加，不能用 OR（carry=1 且 bit0=1 时 OR 会丢进位）
        for (int b = 0; b < 4; ++b) {
            const int i = 4 * w + b;
            v += ((scalar[i >> 3] >> (i & 7)) & 1) << b;
        }
        if (v >= 8) {
            digits[w] = (int8_t)(v - 16);
            carry = 1;
        } else {
            digits[w] = (int8_t)v;
            carry = 0;
        }
    }
}

/// 生成 16 字节随机盲化因子（128 位，小于 l，无需额外约减）
static bool random_blinding(uint8_t* out, int count) {
    return jpssl::os_rand_bytes(out, (size_t)count * 16);
}

} } // namespace jpssl::ed25519_r51_batch_impl

namespace jpssl { namespace detail {

bool ed25519_batch_verify_cpu(
    const uint8_t* const* pubs,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* sigs,
    int count)
{
    using namespace ed25519_r51_batch_impl;

    if (count <= 0) return true;
    if (count == 1) return ed25519_verify(pubs[0], msgs[0], msg_lens[0], sigs[0]);
    if (count > kBatchChunk) {
        // 防御性分块（正常分派层已按 kBatchChunk 切块）
        for (int off = 0; off < count; off += kBatchChunk) {
            const int n = (count - off < kBatchChunk) ? (count - off) : kBatchChunk;
            if (!ed25519_batch_verify_cpu(pubs + off, msgs + off, msg_lens + off,
                                          sigs + off, n))
                return false;
        }
        return true;
    }

    struct Entry {
        ge_p3 A, R;
        uint8_t za[32], zr[32];
        int8_t digitsA[64], digitsR[64];
    };

    // 线程私有工作区（批量 API 可能被并发调用）
    static thread_local Entry entries[kBatchChunk];
    static thread_local ge_p3 p3tab[kBatchChunk * 16];      // 每签名 A/R 各 8 项（1P..8P）
    static thread_local ge_precomp pretab[kBatchChunk * 16]; // 对应的仿射 precomp

    const int npts = count * 16;  // 批量求逆点数（2 * count * 8）

    // ── 逐签名预处理：规范化检查 + 解压 + 哈希 + 盲化标量 ──

    thread_local uint8_t rng[16 * kBatchChunk];
    if (!random_blinding(rng, count)) {
        // 随机源不可用：退化为逐条验证（安全性优先，性能降级）
        for (int i = 0; i < count; ++i)
            if (!ed25519_verify(pubs[i], msgs[i], msg_lens[i], sigs[i]))
                return false;
        return true;
    }

    uint8_t zs[32] = {};
    static thread_local uint8_t k_hashed[64];
    uint8_t zk[32];
    static const uint8_t kZero[32] = {};

    for (int i = 0; i < count; ++i) {
        // s < l（规范性检查）
        uint64_t s_l[4];
        sc_load_64(s_l, sigs[i] + 32);
        for (int j = 3; j >= 0; --j) {
            if (s_l[j] > L64[j]) return false;
            if (s_l[j] < L64[j]) break;
            if (j == 0) return false;  // s == l
        }

        if (ge_frombytes(&entries[i].A, pubs[i]) != 0) return false;
        if (ge_frombytes(&entries[i].R, sigs[i]) != 0) return false;

        // k = SHA512(R || A || M) mod l
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, sigs[i], 32);
        sha512_update(&ctx, pubs[i], 32);
        sha512_update(&ctx, msgs[i], msg_lens[i]);
        sha512_final(&ctx, k_hashed);
        sc_reduce(k_hashed);

        // 盲化：z 为 16 字节随机值（< 2^128 < l）
        uint8_t z[32];
        memcpy(z, rng + 16 * i, 16);
        memset(z + 16, 0, 16);
        if (memcmp(z, kZero, 32) == 0) z[0] = 1;  // 概率 2^-128，兜底

        // za = l − z·k（mod l），zr = l − z（mod l），zs += z·s（mod l）
        sc_mul_add(zk, z, k_hashed, kZero);
        sc_negate(entries[i].za, zk);
        sc_negate(entries[i].zr, z);
        sc_mul_add(zs, z, sigs[i] + 32, zs);

        recode_window4(entries[i].digitsA, entries[i].za);
        recode_window4(entries[i].digitsR, entries[i].zr);

        // ── 构建 1P..8P 投影表（7 次 ge_add / 点） ──
        ge_p3* at = &p3tab[(2 * i) * 8];
        ge_p3* rt = &p3tab[(2 * i + 1) * 8];
        ge_p3_to_p3(&at[0], &entries[i].A);
        for (int d = 1; d < 8; ++d) {
            ge_p1p1 t;
            ge_add(&t, &at[d - 1], &entries[i].A);
            ge_p1p1_to_p3(&at[d], &t);
        }
        ge_p3_to_p3(&rt[0], &entries[i].R);
        for (int d = 1; d < 8; ++d) {
            ge_p1p1 t;
            ge_add(&t, &rt[d - 1], &entries[i].R);
            ge_p1p1_to_p3(&rt[d], &t);
        }
    }

    // ── 全部点一次批量求逆 + 仿射 precomp 化 ──
    precomp_batch_from_p3(pretab, p3tab, npts);

    // ── 共享倍点链的多标量乘：R = [zs]B + Σ za_i·A_i + Σ zr_i·R_i ──

    int8_t bdigits[64];
    recode_window4(bdigits, zs);
    const ge_precomp* bpre = basepoint_table16_precomp();

    ge_p3 R;
    ge_p3_0(&R);

    for (int w = 63; w >= 0; --w) {
        for (int j = 0; j < 4; ++j) {
            ge_p1p1 t;
            ge_p3_dbl(&t, &R);
            ge_p1p1_to_p3(&R, &t);
        }

        const int db = bdigits[w];
        if (db) {
            ge_p1p1 t;
            if (db > 0) ge_madd(&t, &R, &bpre[db]);
            else         ge_msub(&t, &R, &bpre[-db]);
            ge_p1p1_to_p3(&R, &t);
        }

        for (int i = 0; i < count; ++i) {
            const int da = entries[i].digitsA[w];
            if (da) {
                ge_p1p1 t;
                if (da > 0) ge_madd(&t, &R, &pretab[(2 * i) * 8 + da - 1]);
                else         ge_msub(&t, &R, &pretab[(2 * i) * 8 - da - 1]);
                ge_p1p1_to_p3(&R, &t);
            }
            const int dr = entries[i].digitsR[w];
            if (dr) {
                ge_p1p1 t;
                if (dr > 0) ge_madd(&t, &R, &pretab[(2 * i + 1) * 8 + dr - 1]);
                else         ge_msub(&t, &R, &pretab[(2 * i + 1) * 8 - dr - 1]);
                ge_p1p1_to_p3(&R, &t);
            }
        }
    }

    // ── 恒等式判定：R == O ⇔ X == 0 且 T == 0 且 Y == Z ──
    if (fe_isnonzero(R.X)) return false;
    if (fe_isnonzero(R.T)) return false;
    if (!fe_equal(R.Y, R.Z)) return false;
    return true;
}

} } // namespace jpssl::detail
