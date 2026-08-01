#include "rsa.hpp"
#include "rand_os.hpp"
#include "rsa_simd.hpp"  // AVX2 批量 modpow (MR 轮加速)
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <atomic>
#include <chrono>
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
mont_ctx rsa_mont_init(const rsa_bignum&m){return CAT(mont_init_fn_,K)(m);}
void rsa_mont_modpow(rsa_bignum&r,const rsa_bignum&b,const rsa_bignum&e,const mont_ctx&c,const rsa_bignum&m){CAT(mont_modpow_fn_,K)(r,b,e,c,m);}
void rsa_mont_modpow_win(rsa_bignum&r,const rsa_bignum&b,const rsa_bignum&e,const mont_ctx&c,const rsa_bignum&m){CAT(mont_modpow_win_fn_,K)(r,b,e,c,m);}
bool rsa_keygen(rsa_public_key&pub,rsa_private_key&prv){return CAT(keygen_fn_,K)(pub,prv);}
void rsa_encrypt(const rsa_public_key&pub,std::span<const uint8_t> pt,uint8_t*ct){CAT(enc_fn_,K)(pub,pt,ct);}
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
mont_ctx4096 rsa4096_mont_init(const rsa4096_bignum&m){return CAT(mont_init_fn_,K)(m);}
void rsa4096_mont_modpow(rsa4096_bignum&r,const rsa4096_bignum&b,const rsa4096_bignum&e,const mont_ctx4096&c,const rsa4096_bignum&m){CAT(mont_modpow_fn_,K)(r,b,e,c,m);}
void rsa4096_mont_modpow_win(rsa4096_bignum&r,const rsa4096_bignum&b,const rsa4096_bignum&e,const mont_ctx4096&c,const rsa4096_bignum&m){CAT(mont_modpow_win_fn_,K)(r,b,e,c,m);}
bool rsa4096_keygen(rsa4096_public_key&pub,rsa4096_private_key&prv){return CAT(keygen_fn_,K)(pub,prv);}
void rsa4096_encrypt(const rsa4096_public_key&pub,std::span<const uint8_t> pt,uint8_t*ct){CAT(enc_fn_,K)(pub,pt,ct);}
bool rsa4096_decrypt(const rsa4096_private_key&prv,const uint8_t*ct,std::vector<uint8_t>&pt){return CAT(dec_fn_,K)(prv,ct,pt);}
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

// ═══════════════ CRT keygen ═══════════════
// ── 素数搜索辅助 ──

/// 快速小素数试除 (OpenMP 并行, 各素数独立; if 守卫避免单线程团队开销)
template<int K>
static bool small_prime_divides(const uint64_t* xx) {
    static constexpr uint64_t primes[] = {
        3,5,7,11,13,17,19,23,29
    };
    for (uint64_t p : primes) {
        uint64_t acc = 0;
        for (int i = K-1; i >= 0; --i) {
            acc = (acc * 0x100000000ULL % p + (xx[i] >> 32)) % p;
            acc = (acc * 0x100000000ULL % p + (xx[i] & 0xFFFFFFFFULL)) % p;
        }
        if (acc == 0) return true;
    }
    return false;
}

// ── keygen 看门狗 (deadline 时间预算) ──
// 2048 keygen 超 300ms / 4096 超 3s → 置中止标志, 重新 keygen (最多 3 次)
// 实现说明: 不使用看门狗线程 (曾用 std::thread + condition_variable + join,
// 在 Windows 上偶发锁死: watchdog 线程与 work()/join() 的时序竞争导致 CPU≈0% 阻塞)。
// 改为 find_prime 每步检查 steady_clock deadline, 超时置 g_kgen_abort 并返回,
// 彻底消除线程同步, 跨平台一致。
static std::atomic<bool> g_kgen_abort{false};

template<typename FN>
static bool keygen_with_watchdog(int timeout_ms, FN&& work) {
#ifdef _WIN32
    // MSVC jp_uint128 模拟层比 GCC 原生 __uint128_t 慢约一个数量级，
    // 300ms/3s 的 Linux 超时在 Windows 上必然触发 abort 重试并失败，故放大。
    timeout_ms *= 20;
#endif
    for (int attempt = 0; attempt < 3; ++attempt) {
        g_kgen_abort.store(false, std::memory_order_relaxed);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        bool ok = work(deadline);  // find_prime 每步检查 deadline, 超时置 abort 并返回
        if (ok && !g_kgen_abort.load(std::memory_order_relaxed)) return true;
        // 超时或失败 → 重试 (新随机起点)
    }
    return false;  // 3 次均超时 (极罕见)
}

// ── 增量素数搜索 (全量小素数筛复用) ──
// 随机奇数起点 → 相邻奇数步进 (+2), 对全部 ~500 个小素数 (≤3600, 与 bn_is_prime
// 内部筛同集合) 维护余数表, O(1) 增量更新 rem = (rem+2) mod p。
// 过筛后调用 bn_is_prime_sieved (跳过其内部重筛) → MR 只对真候选运行。
// 找到素数期望步数: 2048-bit 素数密度 ~1/710, 4096-bit ~1/1420
template<typename BN, int K>
static void find_prime(BN& p, std::chrono::steady_clock::time_point deadline) {
    // 小素数表: 3..3600 (与 bn_is_prime 内部筛一致), 静态生成一次
    static const uint64_t* sp = []() -> const uint64_t* {
        static uint64_t tbl[512];
        static bool sieve[3601] = {};
        static int nn = 0;
        if (nn == 0) {
            for (int i = 2; i <= 3600; ++i) {
                if (!sieve[i]) {
                    if (i > 2) tbl[nn++] = (uint64_t)i;
                    for (int j = i*2; j <= 3600; j += i) sieve[j] = 1;
                }
            }
        }
        return tbl;
    }();
    static const int np = []() {
        static bool s2[3601] = {};
        int n = 0;
        for (int i = 2; i <= 3600; ++i) if (!s2[i]) { if (i > 2) ++n; for (int j = i*2; j <= 3600; j += i) s2[j] = 1; }
        return n;
    }();
    uint64_t rems[512];
    for (;;) {
        // 随机奇数起点, 设最高位 (满 K/2-bit)
        p = BN::random_odd();
        for (int i = K/2; i < K; ++i) p.d[i] = 0;
        p.d[K/2-1] |= (uint64_t)1 << 63;
        // 初始化余数表: rems[i] = p mod sp[i]
        for (int pi = 0; pi < np; ++pi) {
            uint64_t acc = 0;
            for (int i = K-1; i >= 0; --i) {
                acc = (acc * 0x100000000ULL % sp[pi] + (p.d[i] >> 32)) % sp[pi];
                acc = (acc * 0x100000000ULL % sp[pi] + (p.d[i] & 0xFFFFFFFFULL)) % sp[pi];
            }
            rems[pi] = acc;
        }
        // 增量搜索: 步进 +2, 余数 O(1) 更新
        for (int steps = 0; steps < 300000; ++steps) {
            if (g_kgen_abort.load(std::memory_order_relaxed)) return;  // 看门狗超时中止
            if (std::chrono::steady_clock::now() >= deadline) { g_kgen_abort.store(true, std::memory_order_relaxed); return; }  // deadline 超时
            // 过筛检查: 全部小素数余数非零
            bool pass = true;
            for (int pi = 0; pi < np; ++pi)
                if (rems[pi] == 0) { pass = false; break; }
            // 已用增量筛覆盖全部小素数 → 免内部重筛直接 MR
            if (pass && bn_is_prime_sieved(p, 3)) return;
            // p += 2 (低 word 加法, 极少进位)
            {
                uint64_t c = 2;
                for (int i = 0; i < K; ++i) {
                    uint64_t s = p.d[i] + c;
                    c = (s < p.d[i]) ? 1 : 0;
                    p.d[i] = s;
                    if (!c) break;
                }
            }
            // 溢出到上半区 → 重新随机起点
            if (p.d[K/2] != 0) break;
            // 余数 O(1) 更新: rem = (rem + 2) mod sp
            for (int pi = 0; pi < np; ++pi) {
                rems[pi] += 2;
                if (rems[pi] >= sp[pi]) rems[pi] -= sp[pi];
            }
        }
        // 300000 步未找到 (理论上不可能) → 换随机起点
    }
}

bool rsa_keygen_crt(rsa_public_key& pub, rsa_crt_key& crt) {
    // 看门狗: 超 300ms 中止并重启 (最多 3 次)
    return keygen_with_watchdog(300, [&](std::chrono::steady_clock::time_point deadline) -> bool {
    rsa_bignum p, q, n, phi, e(rsa_bignum::from_uint64(65537)), d, dP, dQ, qInv;
    // 素数搜索: p/q 并行 (2 线程, 完全独立); 无 OpenMP 时串行
#ifdef _OPENMP
    #pragma omp parallel num_threads(2)
    {
        if (omp_get_thread_num() == 0) find_prime<rsa_bignum,32>(p, deadline);
        else find_prime<rsa_bignum,32>(q, deadline);
    }
    if (p == q) find_prime<rsa_bignum,32>(q, deadline);  // 罕见碰撞串行重试
#else
    find_prime<rsa_bignum,32>(p, deadline);
    do { find_prime<rsa_bignum,32>(q, deadline); } while (p == q);
#endif
    bn_mul(n, p, q);
    rsa_bignum p1, q1;
    bn_sub(p1, p, rsa_bignum::from_uint64(1));
    bn_sub(q1, q, rsa_bignum::from_uint64(1));
    bn_mul(phi, p1, q1);
    bn_modinv(d, e, phi);
    while (n.bit_length() < 2048 && !g_kgen_abort.load(std::memory_order_relaxed)) { /* retry */
#ifdef _OPENMP
        #pragma omp parallel num_threads(2)
        {
            if (omp_get_thread_num() == 0) find_prime<rsa_bignum,32>(p, deadline);
            else find_prime<rsa_bignum,32>(q, deadline);
        }
#else
        find_prime<rsa_bignum,32>(p, deadline);
        find_prime<rsa_bignum,32>(q, deadline);
#endif
        bn_mul(n, p, q);
        bn_sub(p1, p, rsa_bignum::from_uint64(1));
        bn_sub(q1, q, rsa_bignum::from_uint64(1));
        bn_mul(phi, p1, q1);
        bn_modinv(d, e, phi);
    }
    bn_mod(dP, d, p1); bn_mod(dQ, d, q1); bn_modinv(qInv, q, p);
    pub.n = n; pub.e = e;
    crt.n = n; crt.e = e; crt.d = d; crt.p = p; crt.q = q;
    crt.dP = dP; crt.dQ = dQ; crt.qInv = qInv;
    return true;
    });
}

bool rsa4096_keygen_crt(rsa4096_public_key& pub, rsa4096_crt_key& crt) {
    // 看门狗: 超 3s 中止并重启 (最多 3 次)
    return keygen_with_watchdog(3000, [&](std::chrono::steady_clock::time_point deadline) -> bool {
    rsa4096_bignum p, q, n, phi, e(rsa4096_bignum::from_uint64(65537)), d, dP, dQ, qInv;
    // 素数搜索: p/q 并行 (2 线程); 无 OpenMP 时串行
#ifdef _OPENMP
    #pragma omp parallel num_threads(2)
    {
        if (omp_get_thread_num() == 0) find_prime<rsa4096_bignum,64>(p, deadline);
        else find_prime<rsa4096_bignum,64>(q, deadline);
    }
    if (p == q) find_prime<rsa4096_bignum,64>(q, deadline);
#else
    find_prime<rsa4096_bignum,64>(p, deadline);
    do { find_prime<rsa4096_bignum,64>(q, deadline); } while (p == q);
#endif
    bn_mul(n, p, q);
    rsa4096_bignum p1, q1;
    bn_sub(p1, p, rsa4096_bignum::from_uint64(1));
    bn_sub(q1, q, rsa4096_bignum::from_uint64(1));
    bn_mul(phi, p1, q1);
    bn_modinv(d, e, phi);
    while (n.bit_length() < 4096 && !g_kgen_abort.load(std::memory_order_relaxed)) {
#ifdef _OPENMP
        #pragma omp parallel num_threads(2)
        {
            if (omp_get_thread_num() == 0) find_prime<rsa4096_bignum,64>(p, deadline);
            else find_prime<rsa4096_bignum,64>(q, deadline);
        }
#else
        find_prime<rsa4096_bignum,64>(p, deadline);
        find_prime<rsa4096_bignum,64>(q, deadline);
#endif
        bn_mul(n, p, q);
        bn_sub(p1, p, rsa4096_bignum::from_uint64(1));
        bn_sub(q1, q, rsa4096_bignum::from_uint64(1));
        bn_mul(phi, p1, q1);
        bn_modinv(d, e, phi);
    }
    bn_mod(dP, d, p1); bn_mod(dQ, d, q1); bn_modinv(qInv, q, p);
    pub.n = n; pub.e = e;
    crt.n = n; crt.e = e; crt.d = d; crt.p = p; crt.q = q;
    crt.dP = dP; crt.dQ = dQ; crt.qInv = qInv;
    return true;
    });
}


} // namespace jpssl
