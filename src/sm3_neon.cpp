/**
 * sm3_neon.cpp — ARMv8.2 SM3 硬件加速实现（FEAT_SM3）
 *
 * 移植自 OpenSSL sm3-armv8.pl 的 ossl_hwsm3_block_data_order，使用
 * ARMv8.2 Crypto 扩展的 SM3 专用指令：
 *   - vsm3ss1q_u32     : sm3ss1（SS1 = ROL(ROL(A,12)+Tj<<<j+E,7)，仅 lane3）
 *   - vsm3tt1a/bq_u32  : sm3tt1a/sm3tt1b（TT1：FF0 = A^B^C / FF1 = MAJ）
 *   - vsm3tt2a/bq_u32  : sm3tt2a/sm3tt2b（TT2：GG0 = E^F^G / GG1 = (E&F)|(~E&G)）
 *   - vsm3partw1q_u32 / vsm3partw2q_u32：消息扩展 W16..W63
 *
 * 状态/消息寄存器布局、64 轮调度、常量 Tj 旋转方式与 OpenSSL 汇编逐条
 * 对应；7 条指令的语义按 ARM ARM 伪代码（并与 QEMU 已验证实现交叉核对）
 * 用标量模拟器逐指令验证：SM3("abc") 已知答案 + 100 组随机块均与标量
 * 实现完全一致（详见 /tmp/sim_sm3.cpp 的验证记录）。
 *
 * 编译要求：-march=armv8.4-a+crypto 及以上（Apple Clang 下 FEAT_SM3
 * intrinsic 需 armv8.4-a 才定义）。运行时由 cpu_has_arm_sm3() 分派，
 * 不支持 FEAT_SM3 的机器自动回退到标量实现。
 */

#include "sm3.hpp"

#include "cpu_features.hpp"

#if defined(__aarch64__) && defined(JP_NEON) && defined(__ARM_FEATURE_SM3)
#include <arm_neon.h>

namespace jpssl {
namespace {

using V = uint32x4_t;

/// ext vd.16b, vn.16b, vm.16b, #imm（imm 必须是编译期常量）
template <int imm>
static inline V sm3_vext(V a, V b) {
    return vreinterpretq_u32_u8(
        vextq_u8(vreinterpretq_u8_u32(a), vreinterpretq_u8_u32(b), imm));
}

/// rev64 .4s + ext #8（状态字序转换，见 OpenSSL 汇编头尾）
static inline V sm3_rev64_ext8(V x) {
    x = vrev64q_u32(x);
    return sm3_vext<8>(x, x);
}

/// 消息扩展：s4 = P1(...) 组合生成 W[16..19]（s0..s3 = W[0..15] 轮转）
static inline void sm3_msg_exp(V& s4, V s0, V s1, V s2, V s3) {
    s4 = sm3_vext<12>(s1, s2);        // {w7, w8, w9, w10}
    V vtmp1 = sm3_vext<12>(s0, s1);   // {w3, w4, w5, w6}
    V vtmp2 = sm3_vext<8>(s2, s3);    // {w10, w11, w12, w13}
    s4 = vsm3partw1q_u32(s4, s0, s3);
    s4 = vsm3partw2q_u32(s4, vtmp2, vtmp1);
}

/// 单轮：SS1 -> 常量旋转 -> TT1/TT2
template <bool b, int i>
static inline void sm3_round(V& st0, V& st1, V& c0, V& c1, V& vtmp, V vw,
                             V s0) {
    vtmp = vsm3ss1q_u32(st0, c0, st1);
    // Tj <<< j：每轮把 lane3 的常量左旋 1 位
    c1 = vorrq_u32(vshlq_n_u32(c0, 1), vshrq_n_u32(c0, 31));
    if (b) {
        st0 = vsm3tt1bq_u32(st0, vtmp, vw, i);
        st1 = vsm3tt2bq_u32(st1, vtmp, s0, i);
    } else {
        st0 = vsm3tt1aq_u32(st0, vtmp, vw, i);
        st1 = vsm3tt2aq_u32(st1, vtmp, s0, i);
    }
}

/// 4 轮一组；s4p 非空时先做消息扩展（vw = s0^s1 提供 Wj' = Wj^Wj+4）
template <bool b>
static inline void sm3_qround_impl(V& st0, V& st1, V& c0, V& c1,
                                   V& vt1, V& vt2, V& s0, V& s1,
                                   V* s4p, V* s2p, V* s3p) {
    if (s4p) sm3_msg_exp(*s4p, s0, s1, *s2p, *s3p);
    vt1 = veorq_u32(s0, s1);
    sm3_round<b, 0>(st0, st1, c0, c1, vt2, vt1, s0);
    sm3_round<b, 1>(st0, st1, c1, c0, vt2, vt1, s0);
    sm3_round<b, 2>(st0, st1, c0, c1, vt2, vt1, s0);
    sm3_round<b, 3>(st0, st1, c1, c0, vt2, vt1, s0);
}

template <bool b>
static inline void sm3_qround(V& st0, V& st1, V& c0, V& c1,
                              V& vt1, V& vt2, V& s0, V& s1, V& s2, V& s3,
                              V& s4) {
    sm3_qround_impl<b>(st0, st1, c0, c1, vt1, vt2, s0, s1, &s4, &s2, &s3);
}

/// 无消息扩展的 qround（最后 3 组，仅用 s0/s1）
template <bool b>
static inline void sm3_qround2(V& st0, V& st1, V& c0, V& c1,
                               V& vt1, V& vt2, V& s0, V& s1) {
    sm3_qround_impl<b>(st0, st1, c0, c1, vt1, vt2, s0, s1, nullptr, nullptr,
                    nullptr);
}

} // namespace

/// 处理一个 64 字节块（与标量 sm3_cf 同接口）
void sm3_cf_neon(uint32_t v[8], const uint8_t block[64]) {
    // 状态载入：rev64 + ext#8 → lane3=A..lane0=D（state1），lane3=E..lane0=H
    V st1 = sm3_rev64_ext8(vld1q_u32(v));
    V st2 = sm3_rev64_ext8(vld1q_u32(v + 4));

    // 消息载入：rev32 把大端字转成 lane 内小端（s0 = {w0..w3}）
    V s0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block)));
    V s1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    V s2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    V s3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    const V bk1 = st1;
    const V bk2 = st2;
    V s4, vt1, vt2;

    // 16 轮 "a"（0..15）：FF/GG = XOR
    {
        V cc0 = sm3_vext<4>(vsetq_lane_u32(0x79cc4519u, vdupq_n_u32(0), 0),
                            vdupq_n_u32(0));
        V cc1 = vdupq_n_u32(0);
        sm3_qround<false>(st1, st2, cc0, cc1, vt1, vt2, s0, s1, s2, s3, s4);
        sm3_qround<false>(st1, st2, cc0, cc1, vt1, vt2, s1, s2, s3, s4, s0);
        sm3_qround<false>(st1, st2, cc0, cc1, vt1, vt2, s2, s3, s4, s0, s1);
        sm3_qround<false>(st1, st2, cc0, cc1, vt1, vt2, s3, s4, s0, s1, s2);
    }
    // 48 轮 "b"（16..63）：FF1 = MAJ / GG1 = 选择
    {
        V cc0 = sm3_vext<4>(vsetq_lane_u32(0x9d8a7a87u, vdupq_n_u32(0), 0),
                            vdupq_n_u32(0));
        V cc1 = vdupq_n_u32(0);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s4, s0, s1, s2, s3);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s0, s1, s2, s3, s4);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s1, s2, s3, s4, s0);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s2, s3, s4, s0, s1);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s3, s4, s0, s1, s2);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s4, s0, s1, s2, s3);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s0, s1, s2, s3, s4);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s1, s2, s3, s4, s0);
        sm3_qround<true>(st1, st2, cc0, cc1, vt1, vt2, s2, s3, s4, s0, s1);
        sm3_qround2<true>(st1, st2, cc0, cc1, vt1, vt2, s3, s4);
        sm3_qround2<true>(st1, st2, cc0, cc1, vt1, vt2, s4, s0);
        sm3_qround2<true>(st1, st2, cc0, cc1, vt1, vt2, s0, s1);
    }

    // 累加原状态，rev64+ext#8 还原字序后存回
    st1 = veorq_u32(st1, bk1);
    st2 = veorq_u32(st2, bk2);
    vst1q_u32(v, sm3_rev64_ext8(st1));
    vst1q_u32(v + 4, sm3_rev64_ext8(st2));
}

/// 分派指针（定义在 sm3.cpp，默认 nullptr 即标量）
extern void (*sm3_cf_ptr)(uint32_t[8], const uint8_t[64]);

/// 静态初始化：FEAT_SM3 可用时接管压缩函数分派
static bool init_sm3_neon() {
    if (cpu_has_arm_sm3()) sm3_cf_ptr = sm3_cf_neon;
    return true;
}
static const bool _sm3_neon_init = init_sm3_neon();

} // namespace jpssl
#endif // __aarch64__ && JP_NEON && __ARM_FEATURE_SM3
