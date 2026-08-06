/**
 * sha3_neon.cpp — ARMv8.2 SHA-3 硬件加速实现（FEAT_SHA3）
 *
 * 使用 ARMv8.2 Crypto 扩展的 4 条指令（Apple M 系列全部支持）：
 *   - veor3q_u64  : 3 输入 XOR（Theta 列校验）
 *   - vrax1q_u64  : ROL(x,1) XOR y（D 向量）
 *   - vxarq_u64   : ROR(x XOR y, imm)（Theta+Rho+Pi 合并）
 *   - vbcaxq_u64  : x XOR (y AND NOT z)（Chi）
 *
 * 本实现是 OpenSSL keccak1600-armv8.pl 中 KeccakF1600_ce 的逐指令移植：
 * 25 个向量寄存器各保存一个 64 位状态字（与 jpssl 标量 s[x+5y] 布局一致），
 * 上一条 XAR 立即数已用脚本从汇编逐条提取，并与标量实现做过 100 组随机
 * 全状态对比验证。
 *
 * 编译要求：-march=armv8.4-a+crypto 及以上（Apple Clang 下 FEAT_SHA3
 * intrinsic 需 armv8.4-a 才定义）。运行时由 cpu_has_arm_sha3() 分派，
 * 不支持 FEAT_SHA3 的机器自动回退到标量实现。
 */

#include "sha3.hpp"

#include "cpu_features.hpp"

#if defined(__aarch64__) && defined(JP_NEON) && defined(__ARM_FEATURE_SHA3)
#include <arm_neon.h>

namespace jpssl {

namespace {

static const uint64_t RC[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808AULL,0x8000000080008000ULL,
    0x000000000000808BULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008AULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000AULL,
    0x000000008000808BULL,0x800000000000008BULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800AULL,0x800000008000000AULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

} // namespace

/// Keccak-f[1600] 置换（与标量 keccak_f1600 同接口）
/// 状态布局与标量一致：s[x + 5*y]，x=列，y=行。
void keccak_f1600_neon(uint64_t s[25]) {
    // V[0..24] 对应状态字 s[0..24]；V[25..31] 为临时 C/D 寄存器
    uint64x2_t V[32];
    for (int i = 0; i < 25; ++i) V[i] = vld1q_dup_u64(&s[i]);

#define XAR(d, n, m, imm) V[d] = vxarq_u64(V[n], V[m], (imm))
#define BCAX(d, n, m, a)  V[d] = vbcaxq_u64(V[n], V[m], V[a])

    for (int r = 0; r < 24; ++r) {
        // ── Theta：C[x] = 列异或（EOR3 两两合并）──
        V[25] = veor3q_u64(V[20], V[15], V[10]);
        V[26] = veor3q_u64(V[21], V[16], V[11]);
        V[27] = veor3q_u64(V[22], V[17], V[12]);
        V[28] = veor3q_u64(V[23], V[18], V[13]);
        V[29] = veor3q_u64(V[24], V[19], V[14]);
        V[25] = veor3q_u64(V[25], V[5], V[0]);
        V[26] = veor3q_u64(V[26], V[6], V[1]);
        V[27] = veor3q_u64(V[27], V[7], V[2]);
        V[28] = veor3q_u64(V[28], V[8], V[3]);
        V[29] = veor3q_u64(V[29], V[9], V[4]);

        // D[x] = C[(x+4)%5] ^ ROL(C[(x+1)%5], 1)（RAX1）
        V[30] = vrax1q_u64(V[25], V[27]);   // D[1]
        V[31] = vrax1q_u64(V[26], V[28]);   // D[2]
        V[27] = vrax1q_u64(V[27], V[29]);   // D[3]
        V[28] = vrax1q_u64(V[28], V[25]);   // D[4]
        V[29] = vrax1q_u64(V[29], V[26]);   // D[0]

        // ── Rho+Pi：XAR(A, D, 64-rho) = ROL(A ^ D, rho) ──
        // 立即数由 OpenSSL 汇编逐条提取（rhotates[i][j] = r[x=j][y=i]）
        XAR(25,  1, 30, 63);   // C0 = A[2][0]，rho[0][1]=1
        XAR( 1,  6, 30, 20);   // rho[1][1]=44
        XAR( 6,  9, 28, 44);   // rho[1][4]=20
        XAR( 9, 22, 31,  3);   // rho[4][2]=61
        XAR(22, 14, 28, 25);   // rho[2][4]=39
        XAR(14, 20, 29, 46);   // rho[4][0]=18
        XAR(26,  2, 31,  2);   // C1 = A[4][0]，rho[0][2]=62
        XAR( 2, 12, 31, 21);   // rho[2][2]=43
        XAR(12, 13, 27, 39);   // rho[2][3]=25
        XAR(13, 19, 28, 56);   // rho[3][4]=8
        XAR(19, 23, 27,  8);   // rho[4][3]=56
        XAR(23, 15, 29, 23);   // rho[3][0]=41
        XAR(15,  4, 28, 37);   // rho[0][4]=27
        XAR(28, 24, 28, 50);   // D4 = A[0][4]，rho[4][4]=14
        XAR(24, 21, 30, 62);   // rho[4][1]=2
        XAR( 8,  8, 27,  9);   // A[1][3] = A[4][1]，rho[1][3]=55
        XAR( 4, 16, 30, 19);   // A[0][4] = A[1][3]，rho[3][1]=45
        XAR(16,  5, 29, 28);   // rho[1][0]=36
        XAR( 5,  3, 27, 36);   // rho[0][3]=28
        V[0] = veorq_u64(V[0], V[29]);      // A[0][0] ^= D[0]
        XAR(27, 18, 27, 43);   // D3 = A[0][3]，rho[3][3]=21
        XAR( 3, 17, 31, 49);   // A[0][3] = A[3][3]，rho[3][2]=15
        XAR(30, 11, 30, 54);   // D1 = A[3][2]，rho[2][1]=10
        XAR(31,  7, 31, 58);   // D2 = A[2][1]，rho[1][2]=6
        XAR(29, 10, 29, 61);   // D0 = A[1][2]，rho[2][0]=3

        // ── Chi：A[x] ^= ~A[x+1] & A[x+2]（BCAX）──
        BCAX(20, 26, 22,  8);
        BCAX(21,  8, 23, 22);
        BCAX(22, 22, 24, 23);
        BCAX(23, 23, 26, 24);
        BCAX(24, 24,  8, 26);

        V[26] = vld1q_dup_u64(&RC[r]);      // ld1r {C1}, [x10], #8

        BCAX(17, 30, 19,  3);
        BCAX(18,  3, 15, 19);
        BCAX(19, 19, 16, 15);
        BCAX(15, 15, 30, 16);
        BCAX(16, 16,  3, 30);

        BCAX(10, 25, 12, 31);
        BCAX(11, 31, 13, 12);
        BCAX(12, 12, 14, 13);
        BCAX(13, 13, 25, 14);
        BCAX(14, 14, 31, 25);

        BCAX( 7, 29,  9,  4);
        BCAX( 8,  4,  5,  9);
        BCAX( 9,  9,  6,  5);
        BCAX( 5,  5, 29,  6);
        BCAX( 6,  6,  4, 29);

        BCAX( 3, 27,  0, 28);
        BCAX( 4, 28,  1,  0);
        BCAX( 0,  0,  2,  1);
        BCAX( 1,  1, 27,  2);
        BCAX( 2,  2, 28, 27);

        V[0] = veorq_u64(V[0], V[26]);      // Iota
    }

#undef XAR
#undef BCAX

    for (int i = 0; i < 25; ++i) s[i] = vgetq_lane_u64(V[i], 0);
}

// 静态初始化：FEAT_SHA3 可用时接管 keccak_f1600_ptr（与 sha512_neon.cpp 同模式）
extern void (*keccak_f1600_ptr)(uint64_t[25]);
static bool init_neon() {
    if (cpu_has_arm_sha3()) keccak_f1600_ptr = keccak_f1600_neon;
    return true;
}
static const bool _neon_init = init_neon();

} // namespace jpssl
#endif // __aarch64__ && JP_NEON && __ARM_FEATURE_SHA3
