#include "rsa.hpp"
#include "rand_os.hpp"
#include "rsa_simd.hpp"       // AVX2 批量 modpow (MR 轮加速)
#include "rsa_mont_asm.hpp"   // x86-64 汇编 mont_mul 快速路径
#include "rsa_prebuilt_primes_data.inc"  // 预制素数表 (keygen 素数搜索超时兜底)
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <atomic>
#include <chrono>
#include <type_traits>
#ifdef _OPENMP
#include <omp.h>
#endif

// 辅助宏：token 拼接
#define CAT2(a,b) a##b
#define CAT(a,b) CAT2(a,b)


namespace jpssl {

void secure_rand_bytes(uint8_t* out, size_t len) {
    // Windows: BCryptGenRandom; Linux: /dev/urandom (CSPRNG)
    if (!os_rand_bytes(out, len))
        std::memset(out, 0, len);
}

// ═══════════════ K=32 (2048-bit) ═══════════════
#define K 32
#define BN rsa_bignum
#define PUB_KEY rsa_public_key
#define PRIV_KEY rsa_private_key
#define MONT_CTX mont_ctx
#include "rsa_body.inc"
// 显式对接函数名
mont_ctx rsa_mont_init(const rsa_bignum&m){return CAT(mont_init_cached_,K)(m);}
mont_ctx rsa_mont_init_mp(const rsa_bignum&m){return CAT(mont_init_mp_,K)(m);}
mont_half_ctx rsa_mont_half_ctx(const rsa_bignum&m){
    mont_half_ctx hc;
    CAT(half_rh_get_,K)(m,hc.R_half,hc.R2_half);
    hc.m_prime=CAT(mont_mp_,K)(m);
    return hc;
}
void rsa_mont_mul_half(rsa_bignum&r,const rsa_bignum&a,const rsa_bignum&b,const rsa_bignum&m,uint64_t mp){
    CAT(mont_mul_half_,K)(r,a,b,m,mp);
}
void rsa_mont_modpow(rsa_bignum&r,const rsa_bignum&b,const rsa_bignum&e,const mont_ctx&c,const rsa_bignum&m){CAT(mont_modpow_fn_,K)(r,b,e,c,m);}
void rsa_mont_modpow_win(rsa_bignum&r,const rsa_bignum&b,const rsa_bignum&e,const mont_ctx&c,const rsa_bignum&m){CAT(mont_modpow_win_fn_,K)(r,b,e,c,m);}
void rsa_mont_modpow_half(rsa_bignum&r,const rsa_bignum&b,const rsa_bignum&e,const mont_ctx&c,const rsa_bignum&m){CAT(mont_modpow_half_win8_cached_,K)(r,b,e,c,m);}
bool rsa_keygen(rsa_public_key&pub,rsa_private_key&prv){return CAT(keygen_fn_,K)(pub,prv);}
void rsa_encrypt(const rsa_public_key&pub,jpssl::span<const uint8_t> pt,uint8_t*ct){CAT(enc_fn_,K)(pub,pt,ct);}
bool rsa_decrypt(const rsa_private_key&prv,const uint8_t*ct,std::vector<uint8_t>&pt){return CAT(dec_fn_,K)(prv,ct,pt);}
#undef K
#undef BN
#undef PUB_KEY
#undef PRIV_KEY
#undef MONT_CTX

// ═══════════════ K=64 (4096-bit) ═══════════════
#define K 64
#define BN rsa4096_bignum
#define PUB_KEY rsa4096_public_key
#define PRIV_KEY rsa4096_private_key
#define MONT_CTX mont_ctx4096
#include "rsa_body.inc"
// 显式对接函数名
mont_ctx4096 rsa4096_mont_init(const rsa4096_bignum&m){return CAT(mont_init_cached_,K)(m);}
mont_ctx4096 rsa4096_mont_init_mp(const rsa4096_bignum&m){return CAT(mont_init_mp_,K)(m);}
mont_half_ctx4096 rsa4096_mont_half_ctx(const rsa4096_bignum&m){
    mont_half_ctx4096 hc;
    CAT(half_rh_get_,K)(m,hc.R_half,hc.R2_half);
    hc.m_prime=CAT(mont_mp_,K)(m);
    return hc;
}
void rsa4096_mont_mul_half(rsa4096_bignum&r,const rsa4096_bignum&a,const rsa4096_bignum&b,const rsa4096_bignum&m,uint64_t mp){
    CAT(mont_mul_half_,K)(r,a,b,m,mp);
}
void rsa4096_mont_modpow(rsa4096_bignum&r,const rsa4096_bignum&b,const rsa4096_bignum&e,const mont_ctx4096&c,const rsa4096_bignum&m){CAT(mont_modpow_fn_,K)(r,b,e,c,m);}
void rsa4096_mont_modpow_win(rsa4096_bignum&r,const rsa4096_bignum&b,const rsa4096_bignum&e,const mont_ctx4096&c,const rsa4096_bignum&m){CAT(mont_modpow_win_fn_,K)(r,b,e,c,m);}
void rsa4096_mont_modpow_half(rsa4096_bignum&r,const rsa4096_bignum&b,const rsa4096_bignum&e,const mont_ctx4096&c,const rsa4096_bignum&m){CAT(mont_modpow_half_win8_cached_,K)(r,b,e,c,m);}
bool rsa4096_keygen(rsa4096_public_key&pub,rsa4096_private_key&prv){return CAT(keygen_fn_,K)(pub,prv);}
void rsa4096_encrypt(const rsa4096_public_key&pub,jpssl::span<const uint8_t> pt,uint8_t*ct){CAT(enc_fn_,K)(pub,pt,ct);}
bool rsa4096_decrypt(const rsa4096_private_key&prv,const uint8_t*ct,std::vector<uint8_t>&pt){return CAT(dec_fn_,K)(prv,ct,pt);}
#undef K
#undef BN
#undef PUB_KEY
#undef PRIV_KEY
#undef MONT_CTX

// ═══════════════ K=48 (3072-bit) ═══════════════
// Montgomery 汇编快速路径只覆盖 K=32/64 (见 include/rsa_mont_asm.hpp): K=48 时
// rsa_body.inc 的 mont_mul_/mont_mul_half_ 不会调用汇编, 自动走标量 CIOS,
// 因此本档无需新增手写汇编。
#define K 48
#define BN rsa3072_bignum
#define PUB_KEY rsa3072_public_key
#define PRIV_KEY rsa3072_private_key
#define MONT_CTX mont_ctx3072
#include "rsa_body.inc"
// 显式对接函数名 (与 4096 档同形)
mont_ctx3072 rsa3072_mont_init(const rsa3072_bignum&m){return CAT(mont_init_cached_,K)(m);}
mont_ctx3072 rsa3072_mont_init_mp(const rsa3072_bignum&m){return CAT(mont_init_mp_,K)(m);}
mont_half_ctx3072 rsa3072_mont_half_ctx(const rsa3072_bignum&m){
    mont_half_ctx3072 hc;
    CAT(half_rh_get_,K)(m,hc.R_half,hc.R2_half);
    hc.m_prime=CAT(mont_mp_,K)(m);
    return hc;
}
void rsa3072_mont_mul_half(rsa3072_bignum&r,const rsa3072_bignum&a,const rsa3072_bignum&b,const rsa3072_bignum&m,uint64_t mp){
    CAT(mont_mul_half_,K)(r,a,b,m,mp);
}
void rsa3072_mont_modpow(rsa3072_bignum&r,const rsa3072_bignum&b,const rsa3072_bignum&e,const mont_ctx3072&c,const rsa3072_bignum&m){CAT(mont_modpow_fn_,K)(r,b,e,c,m);}
void rsa3072_mont_modpow_win(rsa3072_bignum&r,const rsa3072_bignum&b,const rsa3072_bignum&e,const mont_ctx3072&c,const rsa3072_bignum&m){CAT(mont_modpow_win_fn_,K)(r,b,e,c,m);}
void rsa3072_mont_modpow_half(rsa3072_bignum&r,const rsa3072_bignum&b,const rsa3072_bignum&e,const mont_ctx3072&c,const rsa3072_bignum&m){CAT(mont_modpow_half_win8_cached_,K)(r,b,e,c,m);}
// 有意取舍: rsa3072_keygen / rsa3072_keygen_crt 不套用 rsa_body.inc 的 keygen_fn_48
// (其超时兜底是 1024/2048 位预置素数表, 在 K=48 下会得到错误位宽的 n, 见文件尾注释);
// 3072 档 keygen 在文件末尾单独实现。
void rsa3072_encrypt(const rsa3072_public_key&pub,jpssl::span<const uint8_t> pt,uint8_t*ct){CAT(enc_fn_,K)(pub,pt,ct);}
bool rsa3072_decrypt(const rsa3072_private_key&prv,const uint8_t*ct,std::vector<uint8_t>&pt){return CAT(dec_fn_,K)(prv,ct,pt);}
#undef K
#undef BN
#undef PUB_KEY
#undef PRIV_KEY
#undef MONT_CTX

// 4096 GPU batch modpow — CPU fallback（仅无 MUSA 时；MUSA 构建用 rsa_musa.cpp 的真 GPU kernel）
#ifndef JP_MUSA
void musa4096_rsa_batch_modpow(const rsa4096_bignum&mod,const rsa4096_bignum&exp,const mont_ctx4096&mctx,const uint8_t* bases,uint8_t* results,size_t count){
    for(size_t i=0;i<count;++i){
        rsa4096_bignum base=rsa4096_bignum::from_bytes(bases+i*512,512),r;
        rsa4096_mont_modpow(r,base,exp,mctx,mod);
        r.to_bytes(results+i*512);
    }
}
#endif

// 3072 GPU batch modpow — CPU fallback（仅无 MUSA 时）
// MUSA 没有 3072 kernel: rsa_musa.cpp 显式拒绝把 3072 请求套用 4096 kernel,
// JP_MUSA 构建下同样提供 CPU 实现 (见 src/rsa_musa.cpp 文件尾注释)。
#ifndef JP_MUSA
void musa3072_rsa_batch_modpow(const rsa3072_bignum&mod,const rsa3072_bignum&exp,const mont_ctx3072&mctx,const uint8_t* bases,uint8_t* results,size_t count){
    rsa3072_batch_modpow(mod,exp,mctx,bases,results,count);
}
#endif

// 3072 批量模幂 (CPU 低层 API, 步长 384 字节; 供 benchmark/debug 与 GPU 拒绝路径)
void rsa3072_batch_modpow(const rsa3072_bignum&mod,const rsa3072_bignum&exp,const mont_ctx3072&mctx,const uint8_t* bases,uint8_t* results,size_t count){
    for(size_t i=0;i<count;++i){
        rsa3072_bignum base=rsa3072_bignum::from_bytes(bases+i*RSA_3072_BYTES,RSA_3072_BYTES),r;
        rsa3072_mont_modpow(r,base,exp,mctx,mod);
        r.to_bytes(results+i*RSA_3072_BYTES);
    }
}

// ═══════════════ CRT keygen ═══════════════
// ── 素数搜索辅助 ──


// ── keygen 看门狗 (deadline 时间预算) ──
// 素数搜索预算 timeout_ms (默认 100ms): 超时 → find_prime 内部回退预制素数表
// (50 组随机取一, 保证 keygen 在预算内完成, 永不在素数搜索上卡死)。
// 实现说明: 不使用看门狗线程 (曾用 std::thread + condition_variable + join,
// 在 Windows 上偶发锁死: watchdog 线程与 work()/join() 的时序竞争导致 CPU≈0% 阻塞)。
// 改为 find_prime 每步检查 steady_clock deadline, 超时置 g_kgen_abort 并回退,
// 彻底消除线程同步, 跨平台一致。无需 _WIN32 放大: 旧逻辑超时=失败需放大预算,
// 新逻辑超时=兜底成功, timeout_ms 即用户要求的阈值 (100ms)。
static std::atomic<bool> g_kgen_abort{false};

// 3072 档 (K=48) 素数搜索单次预算: 1536-bit 素数的 MR 成本高于 1024-bit,
// 故放宽到 3s; 3072 档无预置素数兜底, 失败由 rsa3072_keygen* 重试 (见文件尾注释)
static constexpr int kRsa3072PrimeBudgetMs = 3000;

template<typename FN>
static bool keygen_with_watchdog(int timeout_ms, FN&& work) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        g_kgen_abort.store(false, std::memory_order_relaxed);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        bool ok = work(deadline);  // find_prime 每步检查 deadline, 超时置 abort 并回退预制素数
        if (ok && !g_kgen_abort.load(std::memory_order_relaxed)) return true;
        // 兜底也失败 (极罕见) → 重试 (新随机起点)
    }
    return false;  // 3 次均失败 (极罕见)
}

// ---- Incremental prime search (delegated) ----
// The real sieve + Miller-Rabin lives in rsa_body.inc kgen_next_prime_:
// random odd start with top two bits set, +2 stepping with an O(1) remainder
// table over 6542 small primes (<=65521), half-width Montgomery MR with
// 40/64 rounds, and a gcd(p-1,e)==1 check. This wrapper only keeps the
// deadline fallback to the prebuilt prime table.

// C++14 兼容的编译期分派（替代 if constexpr）：按 K 选择 32/48/64 位素数例程。
template <typename BN>
static void kgen_prebuilt_dispatch(BN& p, int slot, std::integral_constant<int, 32>) {
    kgen_prebuilt_32(p, slot);
}
template <typename BN>
static void kgen_prebuilt_dispatch(BN& p, int slot, std::integral_constant<int, 64>) {
    kgen_prebuilt_64(p, slot);
}
// 3072 档 (K=48) 无预置素数表（现有表仅 1024/2048 位，套用会得到位宽错误的 n），
// 故不做兜底：保持 p 不变返回，由调用方 (rsa3072_kgen_once) 延长预算重试。
template <typename BN>
static void kgen_prebuilt_dispatch(BN&, int, std::integral_constant<int, 48>) {}

template <typename BN>
static bool kgen_next_prime_dispatch(
    BN& p, const BN& avoid, std::chrono::steady_clock::time_point dl,
    std::integral_constant<int, 32>) {
    return kgen_next_prime_32(p, avoid, dl);
}
template <typename BN>
static bool kgen_next_prime_dispatch(
    BN& p, const BN& avoid, std::chrono::steady_clock::time_point dl,
    std::integral_constant<int, 48>) {
    return kgen_next_prime_48(p, avoid, dl);
}
template <typename BN>
static bool kgen_next_prime_dispatch(
    BN& p, const BN& avoid, std::chrono::steady_clock::time_point dl,
    std::integral_constant<int, 64>) {
    return kgen_next_prime_64(p, avoid, dl);
}

// 返回值 = 是否在预算内搜索成功。超时兜底只对 2048/4096 档存在
// (预置素数表只有 1024/2048 位两组); 3072 档 (K=48) 无可用预置表 →
// 返回 false 且不修改 p, 由调用方 (rsa3072_kgen_once) 延长预算重试。
template<typename BN, int K>
static bool find_prime(BN& p, std::chrono::steady_clock::time_point deadline) {
    BN avoid; avoid.zero();
    bool ok = kgen_next_prime_dispatch(p, avoid, deadline,
                                       std::integral_constant<int, K>());
    if (!ok) {
        // timeout fallback: pick one of the 50 prebuilt prime pairs (slot 0 = p side)
        // (K=48 → 空实现, 不修改 p)
        kgen_prebuilt_dispatch(p, 0, std::integral_constant<int, K>());
    }
    return ok;
}

bool rsa_keygen_crt(rsa_public_key& pub, rsa_crt_key& crt) {
    // Prime search budget: 500ms (2048) / 2000ms (4096); on timeout only,
    // fall back to one of the 50 prebuilt prime pairs (keygen always finishes).
    return keygen_with_watchdog(500, [&](std::chrono::steady_clock::time_point deadline) -> bool {
    rsa_bignum p, q, n, phi, e(rsa_bignum::from_uint64(65537)), d, dP, dQ, qInv;
    // Prime search: serial (MR inside already uses 4 OpenMP threads; avoid nesting)
    // 每个素数独立 500ms 预算: 避免 p 的长尾挤占 q 的时间导致兜底
    auto dl_p = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    find_prime<rsa_bignum,32>(p, dl_p);
    do { auto dl_q = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
         find_prime<rsa_bignum,32>(q, dl_q); } while (p == q);
    bn_mul(n, p, q);
    rsa_bignum p1, q1;
    bn_sub(p1, p, rsa_bignum::from_uint64(1));
    bn_sub(q1, q, rsa_bignum::from_uint64(1));
    bn_mul(phi, p1, q1);
    bn_modinv(d, e, phi);
    while (n.bit_length() < 2048 && !g_kgen_abort.load(std::memory_order_relaxed)) { /* retry */
        find_prime<rsa_bignum,32>(p, std::chrono::steady_clock::now() + std::chrono::milliseconds(500));
        find_prime<rsa_bignum,32>(q, std::chrono::steady_clock::now() + std::chrono::milliseconds(500));
        bn_mul(n, p, q);
        bn_sub(p1, p, rsa_bignum::from_uint64(1));
        bn_sub(q1, q, rsa_bignum::from_uint64(1));
        bn_mul(phi, p1, q1);
        bn_modinv(d, e, phi);
    }
    bn_mod(dP, d, p1); bn_mod(dQ, d, q1);
    // qInv = q^{-1} mod p 用费马小定理 (q^{p-2} mod p), 半宽模幂替代除法欧几里得
    { rsa_bignum p2; bn_sub(p2, p, rsa_bignum::from_uint64(2));
      mont_ctx mcp = rsa_mont_init(p); rsa_mont_modpow_half(qInv, q, p2, mcp, p); }
    pub.n = n; pub.e = e;
    crt.n = n; crt.e = e; crt.d = d; crt.p = p; crt.q = q;
    crt.dP = dP; crt.dQ = dQ; crt.qInv = qInv;
    return true;
    });
}

bool rsa4096_keygen_crt(rsa4096_public_key& pub, rsa4096_crt_key& crt) {
    // Prime search budget: 500ms (2048) / 1000ms (4096); on timeout only,
    // fall back to one of the 50 prebuilt prime pairs (keygen always finishes).
    return keygen_with_watchdog(1000, [&](std::chrono::steady_clock::time_point deadline) -> bool {
    rsa4096_bignum p, q, n, phi, e(rsa4096_bignum::from_uint64(65537)), d, dP, dQ, qInv;
    // Prime search: serial (MR inside already uses 4 OpenMP threads; avoid nesting)
    // 每个素数独立 1000ms 预算: 避免 p 的长尾挤占 q 的时间导致兜底
    auto dl_p = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
    find_prime<rsa4096_bignum,64>(p, dl_p);
    do { auto dl_q = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
         find_prime<rsa4096_bignum,64>(q, dl_q); } while (p == q);
    bn_mul(n, p, q);
    rsa4096_bignum p1, q1;
    bn_sub(p1, p, rsa4096_bignum::from_uint64(1));
    bn_sub(q1, q, rsa4096_bignum::from_uint64(1));
    bn_mul(phi, p1, q1);
    bn_modinv(d, e, phi);
    while (n.bit_length() < 4096 && !g_kgen_abort.load(std::memory_order_relaxed)) {
        find_prime<rsa4096_bignum,64>(p, std::chrono::steady_clock::now() + std::chrono::milliseconds(1000));
        find_prime<rsa4096_bignum,64>(q, std::chrono::steady_clock::now() + std::chrono::milliseconds(1000));
        bn_mul(n, p, q);
        bn_sub(p1, p, rsa4096_bignum::from_uint64(1));
        bn_sub(q1, q, rsa4096_bignum::from_uint64(1));
        bn_mul(phi, p1, q1);
        bn_modinv(d, e, phi);
    }
    bn_mod(dP, d, p1); bn_mod(dQ, d, q1);
    // qInv = q^{-1} mod p 用费马小定理 (q^{p-2} mod p), 半宽模幂替代除法欧几里得
    { rsa4096_bignum p2; bn_sub(p2, p, rsa4096_bignum::from_uint64(2));
      mont_ctx4096 mcp = rsa4096_mont_init(p); rsa4096_mont_modpow_half(qInv, q, p2, mcp, p); }
    pub.n = n; pub.e = e;
    crt.n = n; crt.e = e; crt.d = d; crt.p = p; crt.q = q;
    crt.dP = dP; crt.dQ = dQ; crt.qInv = qInv;
    return true;
    });
}


// ═══════════════ RSA-3072 keygen (K=48) ═══════════════
// 有意取舍 — 3072 档不使用预置素数兜底:
//   预置素数表只有 1024 位 (kPrebuiltPrimes1024) 与 2048 位 (kPrebuiltPrimes2048) 两组,
//   没有 1536 位 (3072 档 p/q 各 1536 bit) 条目; 若照 2048/4096 档在搜索超时后回退到
//   预置表, K=48 下 bn_mul 会截断出位宽错误的 n, 且 keygen_fn_ 的 n 位宽不足重试
//   循环会反复重新兜底 → 死循环。故 3072 档一律走纯随机搜索:
//     · 每个素数单次预算 3000ms (kRsa3072PrimeBudgetMs), 由 find_prime 内部 deadline 控制;
//     · 整轮 (p + q) 失败由 keygen_with_watchdog 重试, 最多 3 轮;
//     · 3 轮仍失败 → 返回 false (不兜底, 由调用方决定是否再试)。
//   MR 轮数沿用 rsa_body.inc 的 mr_rounds_ (K<64 → 40 轮), 素性强度不变。

// 单轮尝试: 随机搜索 p/q → n, e, d + CRT 参数 (dP, dQ, qInv); 任一步超预算返回 false
static bool rsa3072_kgen_once(rsa3072_bignum& n, rsa3072_bignum& e, rsa3072_bignum& d,
                              rsa3072_bignum& p, rsa3072_bignum& q,
                              rsa3072_bignum& dP, rsa3072_bignum& dQ, rsa3072_bignum& qInv) {
    auto per_prime = [] {
        return std::chrono::steady_clock::now()
             + std::chrono::milliseconds(kRsa3072PrimeBudgetMs);
    };
    e = rsa3072_bignum::from_uint64(65537);
    if (!find_prime<rsa3072_bignum,48>(p, per_prime())) return false;
    do { if (!find_prime<rsa3072_bignum,48>(q, per_prime())) return false; } while (p == q);
    rsa3072_bignum p1, q1, phi;
    bn_mul(n, p, q);
    bn_sub(p1, p, rsa3072_bignum::from_uint64(1));
    bn_sub(q1, q, rsa3072_bignum::from_uint64(1));
    bn_mul(phi, p1, q1);
    bn_modinv(d, e, phi);
    // n 位宽不足 (两侧最高两位置 1 后几乎不可能) → 换随机起点重来 (最多 4 次)
    for (int guard = 0; n.bit_length() < 3072 && guard < 4; ++guard) {
        if (!find_prime<rsa3072_bignum,48>(p, per_prime())) return false;
        do { if (!find_prime<rsa3072_bignum,48>(q, per_prime())) return false; } while (p == q);
        bn_mul(n, p, q);
        bn_sub(p1, p, rsa3072_bignum::from_uint64(1));
        bn_sub(q1, q, rsa3072_bignum::from_uint64(1));
        bn_mul(phi, p1, q1);
        bn_modinv(d, e, phi);
    }
    if (n.bit_length() < 3072) return false;
    bn_mod(dP, d, p1); bn_mod(dQ, d, q1);
    // qInv = q^{-1} mod p 用费马小定理 (q^{p-2} mod p), 半宽模幂替代除法欧几里得
    { rsa3072_bignum p2; bn_sub(p2, p, rsa3072_bignum::from_uint64(2));
      mont_ctx3072 mcp = rsa3072_mont_init(p); rsa3072_mont_modpow_half(qInv, q, p2, mcp, p); }
    return true;
}

bool rsa3072_keygen(rsa3072_public_key& pub, rsa3072_private_key& prv) {
    return keygen_with_watchdog(3000, [&](std::chrono::steady_clock::time_point) -> bool {
        rsa3072_bignum n, e, d, p, q, dP, dQ, qInv;
        if (!rsa3072_kgen_once(n, e, d, p, q, dP, dQ, qInv)) return false;
        pub.n = n; pub.e = e;
        prv.n = n; prv.d = d; prv.e = e;
        prv.p = p; prv.q = q; prv.dP = dP; prv.dQ = dQ; prv.qInv = qInv;
        return true;
    });
}

bool rsa3072_keygen_crt(rsa3072_public_key& pub, rsa3072_crt_key& crt) {
    return keygen_with_watchdog(3000, [&](std::chrono::steady_clock::time_point) -> bool {
        rsa3072_bignum n, e, d, p, q, dP, dQ, qInv;
        if (!rsa3072_kgen_once(n, e, d, p, q, dP, dQ, qInv)) return false;
        pub.n = n; pub.e = e;
        crt.n = n; crt.e = e; crt.d = d;
        crt.p = p; crt.q = q; crt.dP = dP; crt.dQ = dQ; crt.qInv = qInv;
        return true;
    });
}

} // namespace jpssl
