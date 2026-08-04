/**
 * x25519_body.inc — X25519 Montgomery ladder 核心实现（radix-2^51）
 *
 * 此文件被多个编译单元包含（CPU 标量 / AVX2 / AVX512），
 * 每个编译单元通过不同的编译标志让编译器自动向量化同一份 fe51 域运算：
 *   - CPU 标量：默认标志
 *   - AVX2：    -mavx2 -madx  （MULX/ADCX/ADOX 加速 64-bit 乘法）
 *   - AVX512：  -mavx512f -mavx512dq（512-bit 自动向量化）
 *
 * 使用 fe_25519_r51.hpp 的 radix-2^51 5×uint64 表示：
 *   25 次 64×64→128 乘法（vs 10-limb 的 100 次 32×32）
 */

#include "fe_25519_r51.hpp"
using namespace jpssl::x25519_r51;

// 无进位减法: r = a - b (mod p)。
// 输入 limb 须 < 2^51 + eps（来自 mul/sq 输出），加 2p 补偿保证非负；
// 输出 limb 非负且 < 2^53，可直接作为后续 mul/sq 输入（无需再 carry）。
// 仅用于梯形中间运算，不能直接 tobytes。
static inline void ladder_sub(fe51 r, const fe51 a, const fe51 b) {
    static const uint64_t TWO_P[5] = {
        0x0FFFFFFFFFFFDAULL,  // 2*(2^51-19)
        0xFFFFFFFFFFFFEULL,   // 2*(2^51-1)
        0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL,
    };
    for (int i = 0; i < 5; i++)
        r[i] = a[i] + TWO_P[i] - b[i];
}

static void x25519_scalar_mult_impl(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0] &= 248; e[31] &= 127; e[31] |= 64;

    static const uint8_t base[32] = {9};
    const uint8_t* u = point ? point : base;

    fe51 x1, x2, z2, x3, z3;
    fe51 a, b, c, d, da, cb, t, a24;

    fe51_frombytes(x1, u);

    fe51_1(x2); fe51_0(z2);
    fe51_frombytes(x3, u); fe51_1(z3);

    fe51_0(a24); a24[0] = 121665;

    uint64_t swap = 0;
    for (int i = 254; i >= 0; --i) {
        uint64_t bit = (e[i >> 3] >> (i & 7)) & 1;
        swap ^= bit;
        fe51_cswap(x2, x3, swap);
        fe51_cswap(z2, z3, swap);
        swap = bit;

        // A = x2 + z2 ; B = x2 - z2
        fe51_add(a, x2, z2);
        ladder_sub(b, x2, z2);
        // C = x3 + z3 ; D = x3 - z3
        fe51_add(c, x3, z3);
        ladder_sub(d, x3, z3);

        // DA = D * A ; CB = C * B
        fe51_mul(da, d, a);
        fe51_mul(cb, c, b);

        // x3 = (DA + CB)^2
        fe51_add(x3, da, cb);
        fe51_sq(x3, x3);
        // z3 = x1 * (DA - CB)^2
        ladder_sub(t, da, cb);
        fe51_sq(z3, t);
        fe51_mul(z3, z3, x1);

        // AA = A^2 (a 原地平方, A 不再需要) ; BB = B^2
        fe51_sq(a, a);
        fe51_sq(z2, b);
        // E = AA - BB (t), 随后 x2 = AA*BB ; z2 = E*(AA + a24*E)
        ladder_sub(t, a, z2);
        fe51_mul(x2, a, z2);
        // z2 = E * (AA + a24 * E)
        fe51_mul(z2, t, a24);
        fe51_add(z2, z2, a);
        fe51_mul(z2, z2, t);
    }

    fe51_cswap(x2, x3, swap);
    fe51_cswap(z2, z3, swap);

    // out = x2 / z2
    fe51_invert(z2, z2);
    fe51_mul(x2, x2, z2);
    fe51_tobytes(out, x2);
}
