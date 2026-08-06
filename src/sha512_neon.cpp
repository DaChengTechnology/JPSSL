/**
 * sha512_neon.cpp — ARMv8.2 SHA-512 硬件加速实现
 *
 * 使用 ARMv8.2 Crypto 扩展（FEAT_SHA512，Apple M 系列全部支持）：
 *   - vsha512hq_u64 / vsha512h2q_u64 ：压缩函数（每对指令处理 2 轮）
 *   - vsha512su0q_u64 / vsha512su1q_u64：NEON 消息调度
 *
 * 循环结构移植自 OpenSSL sha512_block_armv8（.Loop_hw）：4 个 128 位寄存器
 * 保存 8 个 64 位状态字 {a,b},{c,d},{e,f},{g,h}，每轮迭代旋转一次；
 * 指令实参顺序与 lane 语义已对照 ARM 伪代码 + 本机实测逐条验证。
 *
 * 编译要求：-march=armv8.4-a+crypto 及以上（Apple Clang 下 FEAT_SHA512
 * intrinsic 需 armv8.4-a 才定义）。运行时由 cpu_has_arm_sha512() 分派，
 * 不支持 FEAT_SHA512 的机器自动回退到标量实现。
 */

#include "sha512.hpp"

#include "cpu_features.hpp"

#if defined(__aarch64__) && defined(JP_NEON) && defined(__ARM_FEATURE_SHA512)
#include <arm_neon.h>

namespace jpssl {

namespace {

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

} // namespace

extern void (*sha512_transform_ptr)(uint64_t[8], const uint8_t[128]);

/// 处理一个 128 字节块（与 sha512_transform_cpu 同接口）
void sha512_transform_neon(uint64_t h[8], const uint8_t data[128]) {
    // 消息字按大端读入（与标量实现一致）
    uint64_t W[16];
    for (int i = 0; i < 16; ++i) {
        W[i] = ((uint64_t)data[i * 8] << 56) | ((uint64_t)data[i * 8 + 1] << 48) |
               ((uint64_t)data[i * 8 + 2] << 40) | ((uint64_t)data[i * 8 + 3] << 32) |
               ((uint64_t)data[i * 8 + 4] << 24) | ((uint64_t)data[i * 8 + 5] << 16) |
               ((uint64_t)data[i * 8 + 6] << 8) | (uint64_t)data[i * 8 + 7];
    }

    // 状态：4 个 128 位寄存器保存 8 个 64 位哈希字 {a,b},{c,d},{e,f},{g,h}
    uint64x2_t H[5];
    H[0] = vld1q_u64(h);
    H[1] = vld1q_u64(h + 2);
    H[2] = vld1q_u64(h + 4);
    H[3] = vld1q_u64(h + 6);

    // 消息块：8 个 128 位寄存器 {W0,W1},{W2,W3},...,{W14,W15}
    uint64x2_t MSG[8];
    for (int j = 0; j < 8; ++j) MSG[j] = vld1q_u64(&W[j * 2]);

    // 保存原始状态用于最后的累加
    const uint64x2_t AB = H[0], CD = H[1], EF = H[2], GH = H[3];

    for (int i = 0; i < 40; ++i) { // 80 轮，每迭代 2 轮
        uint64x2_t fg = vextq_u64(H[2], H[3], 1);   // {f, g}
        uint64x2_t de = vextq_u64(H[1], H[2], 1);   // {d, e}

        // W0 = {K[2i]+W[2i], K[2i+1]+W[2i+1]}，再交换 lane 成 {K1+W1, K0+W0}
        uint64x2_t kw = vaddq_u64(vld1q_u64(&K[i * 2]), MSG[0]);
        uint64x2_t W0 = vextq_u64(kw, kw, 1);

        H[3] = vaddq_u64(H[3], W0);                 // {g+K1+W1, h+K0+W0}
        H[3] = vsha512hq_u64(H[3], fg, de);         // 2 轮 Σ1+Ch

        // NEON 消息调度：W[2i+16..2i+17] = su0 + su1
        MSG[0] = vsha512su0q_u64(MSG[0], MSG[1]);
        uint64x2_t m9_10 = vextq_u64(MSG[4], MSG[5], 1); // {W[2i+9], W[2i+10]}
        MSG[0] = vsha512su1q_u64(MSG[0], MSG[7], m9_10);

        H[4] = vaddq_u64(H[1], H[3]);               // {c+T1_1, d+T1_0}
        H[3] = vsha512h2q_u64(H[3], H[1], H[0]);    // 2 轮 Σ0+MAJ

        // 寄存器轮转（与 OpenSSL 一致）
        const uint64x2_t old0 = H[0], old1 = H[1], old2 = H[2], old4 = H[4];
        H[0] = H[3]; H[1] = old0; H[2] = old4; H[3] = old2; H[4] = old1;

        // MSG 轮转：MSG[0] 移到队尾
        const uint64x2_t oldm = MSG[0];
        for (int j = 0; j < 7; ++j) MSG[j] = MSG[j + 1];
        MSG[7] = oldm;
    }

    // 累加原始状态
    H[0] = vaddq_u64(H[0], AB);
    H[1] = vaddq_u64(H[1], CD);
    H[2] = vaddq_u64(H[2], EF);
    H[3] = vaddq_u64(H[3], GH);

    vst1q_u64(h, H[0]);
    vst1q_u64(h + 2, H[1]);
    vst1q_u64(h + 4, H[2]);
    vst1q_u64(h + 6, H[3]);
}

/// 静态初始化：FEAT_SHA512 可用时接管 sha512_transform_ptr
/// （与 x86 的 sha512_opt.cpp 使用同一分派指针，顺序无关，最终以支持方为准）
static bool init_neon() {
    if (cpu_has_arm_sha512()) sha512_transform_ptr = sha512_transform_neon;
    return true;
}
static const bool _neon_init = init_neon();

} // namespace jpssl
#endif // __aarch64__ && JP_NEON && __ARM_FEATURE_SHA512
