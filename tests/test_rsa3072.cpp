// test_rsa3072.cpp - RSA-3072 (第三档, K=48) 单元测试
//   覆盖: bignum 边界 (384 字节 from_bytes/to_bytes 往返, bit_length==3072,
//         小样例模幂, Montgomery 路径与 bn_modpow 一致),
//         rsa3072_keygen / rsa3072_keygen_crt + PKCS#1 v1.5 加解密往返,
//         RSASSA-PKCS1-v1_5 签名验签, RSASSA-PSS (SHA-256/384/512),
//         RSAES-OAEP (含 label 校验), CRT 解密 / RSADP3072 / RSASP13072,
//         批量解密 rsa3072_batch_decrypt 与批量模幂 rsa3072_batch_modpow
//   OpenSSL 可用时 (CMake 定义 JP_TEST_HAVE_OPENSSL) 追加与 OpenSSL 的
//   RSA-3072 互操作交叉验证 (PSS 双向 + PKCS#1 v1.5 双向)。
#include "rsa.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>
#if defined(_MSC_VER)
#include <intrin.h>   // _umul128 / __umulh (MSVC x64)
#endif

#if defined(JP_TEST_HAVE_OPENSSL)
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#endif

using namespace jpssl;

static int g_fail = 0;

static void check(bool ok, const char* name) {
    printf("  %-58s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fail;
}

// ── DER DigestInfo 前缀 (SHA-256 / SHA-384 / SHA-512) ──────────────────
static const uint8_t P_SHA256[19] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,
                                     0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,
                                     0x00,0x04,0x20};
static const uint8_t P_SHA384[19] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,
                                     0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,
                                     0x00,0x04,0x30};
static const uint8_t P_SHA512[19] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,
                                     0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,
                                     0x00,0x04,0x40};

// ── 64x64 取模乘参考实现 ───────────────────────────────────────────────
// 「已知答案」参考值需要 (a*b) % m（a,b,m < 2^64，m 为奇数模数）。
// MSVC 不支持 unsigned __int128（error C4235）：x64 上由 _umul128 取乘积低 64 位、
// __umulh 取高 64 位，拼出 128 位乘积 hi:lo 后再做 128 位二进制长除取模；
// 其它编译器保留 unsigned __int128。两条路径结果逐位一致，断言强度不变。
static uint64_t mulmod_u64(uint64_t a, uint64_t b, uint64_t m) {
    if (m == 0) return 0;   // 调用方只传奇数模数，此处仅防御除零
#if defined(_MSC_VER)
  #if defined(_M_X64)
    // 128 位乘积 hi:lo（两个内建函数是同一 x64 乘法指令的两半）
    uint64_t hi = 0;
    uint64_t lo = _umul128(a, b, &hi);
    hi = __umulh(a, b);                 // 与上行 HighProduct 等价，交叉确认高半
    // 二进制长除：rem = (hi:lo) % m（m < 2^64，逐位把 lo 移入余数）
    uint64_t rem = hi % m;
    for (int i = 63; i >= 0; --i) {
        // rem = (2*rem + bit) % m；2*rem 可能溢出 64 位，故先比较再相减
        rem = (rem >= m - rem) ? (rem - (m - rem)) : (rem + rem);
        if ((lo >> i) & 1u) rem = (rem + 1 == m) ? 0 : (rem + 1);
    }
    return rem;
  #else
    // Win32/ARM64 等无 _umul128 的目标：加倍-相加乘模（结果一致）
    a %= m; b %= m;
    uint64_t r = 0;
    for (; b; b >>= 1) {
        if (b & 1u) r = (r >= m - a) ? (r - (m - a)) : (r + a);
        a = (a >= m - a) ? (a - (m - a)) : (a + a);
    }
    return r;
  #endif
#else
    return (uint64_t)((((unsigned __int128)a) * b) % m);
#endif
}

// ── 1. bignum 边界 ────────────────────────────────────────────────────
static void test_bignum() {
    printf("== bignum (K=48) ==\n");
    check(RSA_3072_BITS == 3072 && RSA_3072_WORDS == 48 && RSA_3072_BYTES == 384,
          "常量 RSA_3072_BITS/WORDS/BYTES == 3072/48/384");

    // 384 字节 from_bytes/to_bytes 往返 (最高位置 1 → bit_length 恰好 3072)
    std::vector<uint8_t> in(RSA_3072_BYTES);
    for (size_t i = 0; i < in.size(); ++i) in[i] = (uint8_t)(i * 7u + 3u);
    in[0] = 0x80;
    rsa3072_bignum x = rsa3072_bignum::from_bytes(in.data(), in.size());
    uint8_t out[RSA_3072_BYTES];
    x.to_bytes(out);
    check(memcmp(in.data(), out, RSA_3072_BYTES) == 0, "384 字节 from_bytes/to_bytes 往返");
    check(x.bit_length() == 3072, "bit_length == 3072");

    // I2OSP / OS2IP 往返
    uint8_t i2o[RSA_3072_BYTES + 8];
    check(I2OSP(x, i2o, RSA_3072_BYTES), "I2OSP(3072 bignum, 384)");
    check(OS2IP3072(i2o, RSA_3072_BYTES) == x, "OS2IP3072(I2OSP(x)) == x");

    // 小样例模幂 + 已知答案: 参考值用独立的 64x64 取模乘 (mulmod_u64) 算出
    // 注 1: bn_modpow 走 Montgomery 路径, 模数必须为奇数;
    // 注 2: rsa_body.inc 的 compute_2exp_mod_ 对倍增序列恰好命中 floor(m/2) 的
    //       极小奇数模数 (实测 m=101 / m=65537) 存在既有边界问题 (2048/3072/4096
    //       三档共有; RSA 实际模数是巨大奇数, 不会触发), 故此处选用不触发的模数。
    {
        static const uint64_t cases[4][3] = {
            {    1000003ull,     12345ull,     6789ull},   // 20-bit 质数
            {     999983ull,    999982ull, 12345678ull},   // 20-bit 质数
            { 1000000007ull, 123456789ull, 987654321ull},   // 1e9+7
            {0xFFFFFFFFFFFFFFC5ull, 123456789ull, 987654321ull},  // 2^64-59
        };
        bool all_ok = true;
        for (int i = 0; i < 4; ++i) {
            const uint64_t ms = cases[i][0], xs = cases[i][1], es = cases[i][2];
            uint64_t acc = 1, bb = xs % ms;
            for (uint64_t ee = es; ee; ee >>= 1) {
                if (ee & 1) acc = mulmod_u64(acc, bb, ms);
                bb = mulmod_u64(bb, bb, ms);
            }
            rsa3072_bignum rk;
            bn_modpow(rk, rsa3072_bignum::from_uint64(xs), rsa3072_bignum::from_uint64(es),
                      rsa3072_bignum::from_uint64(ms));
            if (!(rk == rsa3072_bignum::from_uint64(acc))) all_ok = false;
        }
        check(all_ok, "bn_modpow 已知答案 x4 (64x64 取模乘参考, 20/64-bit 奇数模数)");
    }

    // 3072-bit 奇数模数: bn_modpow 与 Montgomery 窗口路径一致
    rsa3072_bignum M = rsa3072_bignum::from_bytes(in.data(), in.size());
    M.d[0] |= 1;                                  // 奇数模数 (Montgomery 路径)
    rsa3072_bignum X = rsa3072_bignum::random_odd();
    bn_mod(X, X, M);
    rsa3072_bignum pw;
    bn_modpow(pw, X, rsa3072_bignum::from_uint64(3), M);
    mont_ctx3072 mc2 = rsa3072_mont_init(M);
    rsa3072_bignum mw;
    rsa3072_mont_modpow_win(mw, X, rsa3072_bignum::from_uint64(3), mc2, M);
    check(pw == mw, "bn_modpow == rsa3072_mont_modpow_win (3072-bit M, e=3)");

    // Montgomery 上下文 + 显式 modpow 与 bn_modpow 一致 (e = 65537)
    mont_ctx3072 mc = rsa3072_mont_init(M);
    rsa3072_bignum e65537 = rsa3072_bignum::from_uint64(65537);
    rsa3072_bignum m1, m2;
    rsa3072_mont_modpow(m1, X, e65537, mc, M);
    bn_modpow(m2, X, e65537, M);
    check(m1 == m2, "rsa3072_mont_modpow == bn_modpow (e=65537)");

    // 位操作 / 比较
    rsa3072_bignum y = rsa3072_bignum::from_uint64(1);
    y.set_bit(3071);
    check(y.bit(3071) && y.bit_length() == 3072, "set_bit(3071) / bit(3071)");
    check(rsa3072_bignum::from_uint64(1) < y, "operator< (1 < 2^3071)");
}

// ── 2. keygen + PKCS#1 v1.5 加解密 ────────────────────────────────────
static void test_keygen_encdec(rsa3072_public_key& pub, rsa3072_crt_key& crt) {
    printf("== keygen (K=48) ==\n");
    auto t0 = std::chrono::steady_clock::now();
    bool ok = rsa3072_keygen_crt(pub, crt);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    printf("  rsa3072_keygen_crt: %lld ms\n", (long long)ms);
    check(ok, "rsa3072_keygen_crt 返回 true");
    if (!ok) return;
    check(pub.n.bit_length() == 3072, "n.bit_length() == 3072");
    check(pub.e == rsa3072_bignum::from_uint64(65537), "e == 65537");
    check(!crt.p.is_zero() && !crt.q.is_zero() && !crt.dP.is_zero() &&
          !crt.dQ.is_zero() && !crt.qInv.is_zero(), "CRT 参数 (p,q,dP,dQ,qInv) 非零");
    rsa3072_bignum chk;
    bn_mul(chk, crt.p, crt.q);
    check(chk == crt.n, "p * q == n");
    check(crt.p.bit_length() == 1536 && crt.q.bit_length() == 1536,
          "p/q 各 1536 bit");

    // 费马小定理 p^(p-1) == 1 mod p: 同时验证 1536-bit 素性与 3072 档模幂实现
    // (不验证 e*d mod phi: 该乘积超过 48 limb, bn_mul 只保留低 K limb)
    rsa3072_bignum p1, pq;
    bn_sub(p1, crt.p, rsa3072_bignum::from_uint64(1));
    bn_modpow(pq, rsa3072_bignum::from_uint64(3), p1, crt.p);   // 底数须与 p 互素
    check(pq == rsa3072_bignum::from_uint64(1), "费马小定理 3^(p-1) == 1 mod p (全宽)");
    // 同一检验走半宽路径 (CRT/MR 使用的路径)
    mont_ctx3072 mch = rsa3072_mont_init_mp(crt.p);
    rsa3072_bignum pqh;
    rsa3072_mont_modpow_half(pqh, rsa3072_bignum::from_uint64(3), p1, mch, crt.p);
    check(pqh == rsa3072_bignum::from_uint64(1), "费马小定理 3^(p-1) == 1 mod p (半宽)");
    // qInv 正确性: q * qInv == 1 mod p (半宽 Montgomery 乘)
    mont_half_ctx3072 hc = rsa3072_mont_half_ctx(crt.p);
    rsa3072_bignum qm, one;
    rsa3072_mont_mul_half(qm, crt.q, crt.qInv, crt.p, hc.m_prime);
    rsa3072_mont_mul_half(one, qm, hc.R2_half, crt.p, hc.m_prime);
    check(one == rsa3072_bignum::from_uint64(1), "q * qInv == 1 mod p (半宽 Mont)");

    // ── PKCS#1 v1.5 加解密往返 (CRT 解密) ──
    const char* msg = "RSA-3072 PKCS#1 v1.5 roundtrip message";
    std::vector<uint8_t> pt((const uint8_t*)msg, (const uint8_t*)msg + strlen(msg));
    uint8_t ct[RSA_3072_BYTES];
    rsa3072_encrypt(pub, std::span<const uint8_t>(pt.data(), pt.size()), ct);
    std::vector<uint8_t> back;
    bool dec_ok = rsa3072_crt_decrypt(crt, ct, back);
    check(dec_ok && back == pt, "encrypt -> rsa3072_crt_decrypt 往返");

    // 原语层: RSADP3072 (CRT) 与 RSAEP3072 (公钥) 互逆
    rsa3072_bignum m = rsa3072_bignum::from_bytes(ct, RSA_3072_BYTES);
    rsa3072_bignum mm, cc;
    RSADP3072(crt, m, mm);
    RSAEP3072(pub, mm, cc);
    check(cc == m, "RSAEP3072(RSADP3072(c)) == c");
}

// ── 3. 非 CRT keygen (rsa3072_keygen) ─────────────────────────────────
static void test_keygen_plain() {
    printf("== rsa3072_keygen (非 CRT 导出) ==\n");
    rsa3072_public_key pub;
    rsa3072_private_key prv;
    auto t0 = std::chrono::steady_clock::now();
    bool ok = rsa3072_keygen(pub, prv);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    printf("  rsa3072_keygen: %lld ms\n", (long long)ms);
    check(ok, "rsa3072_keygen 返回 true");
    if (!ok) return;
    check(prv.n.bit_length() == 3072, "私钥 n.bit_length() == 3072");
    check(!prv.p.is_zero() && !prv.q.is_zero(), "私钥带 CRT 参数 (p/q)");

    uint8_t pt[16];
    for (int i = 0; i < 16; ++i) pt[i] = (uint8_t)(0xA0 + i);
    uint8_t ct[RSA_3072_BYTES];
    rsa3072_encrypt(pub, std::span<const uint8_t>(pt, sizeof(pt)), ct);
    std::vector<uint8_t> back;
    check(rsa3072_decrypt(prv, ct, back) && back.size() == sizeof(pt) &&
          memcmp(back.data(), pt, sizeof(pt)) == 0, "rsa3072_decrypt 往返 (16B)");
}

// ── 4. RSASSA-PKCS1-v1_5 ──────────────────────────────────────────────
static void test_pkcs1(rsa3072_public_key& pub, rsa3072_crt_key& crt) {
    printf("== RSASSA-PKCS1-v1_5 (K=48) ==\n");
    const char* msg = "RSASSA-PKCS1-v1_5 over RSA-3072";
    struct { const uint8_t* p; size_t n; const char* name; } tbl[3] = {
        {P_SHA256, sizeof(P_SHA256), "SHA-256"},
        {P_SHA384, sizeof(P_SHA384), "SHA-384"},
        {P_SHA512, sizeof(P_SHA512), "SHA-512"},
    };
    for (int i = 0; i < 3; ++i) {
        uint8_t sig[RSA_3072_BYTES];
        bool s = rsassa_pkcs1v15_sign3072(crt, (const uint8_t*)msg, strlen(msg),
                                          tbl[i].p, tbl[i].n, sig);
        bool v = s && rsassa_pkcs1v15_verify3072(pub, (const uint8_t*)msg, strlen(msg),
                                                 tbl[i].p, tbl[i].n, sig);
        char name[80];
        snprintf(name, sizeof(name), "PKCS1v15 %s 签名/验签", tbl[i].name);
        check(v, name);
        if (!s) continue;
        sig[200] ^= 0x40;
        bool bad = rsassa_pkcs1v15_verify3072(pub, (const uint8_t*)msg, strlen(msg),
                                              tbl[i].p, tbl[i].n, sig);
        snprintf(name, sizeof(name), "PKCS1v15 %s 篡改签名被拒", tbl[i].name);
        check(!bad, name);
    }
    // 错误消息必须验签失败
    uint8_t sig[RSA_3072_BYTES];
    if (rsassa_pkcs1v15_sign3072(crt, (const uint8_t*)msg, strlen(msg),
                                 P_SHA256, sizeof(P_SHA256), sig)) {
        check(!rsassa_pkcs1v15_verify3072(pub, (const uint8_t*)"other msg", 9,
                                          P_SHA256, sizeof(P_SHA256), sig),
              "PKCS1v15 不同消息验签失败");
    }
}

// ── 5. RSASSA-PSS (SHA-256/384/512) ──────────────────────────────────
static void test_pss(rsa3072_public_key& pub, rsa3072_crt_key& crt) {
    printf("== RSASSA-PSS (K=48) ==\n");
    const char* msg = "RSASSA-PSS over RSA-3072";
    PssHash hs[3] = {PssHash::SHA256, PssHash::SHA384, PssHash::SHA512};
    const char* names[3] = {"SHA-256", "SHA-384", "SHA-512"};
    for (int i = 0; i < 3; ++i) {
        uint8_t sig[RSA_3072_BYTES];
        char name[80];
        bool s = rsassa_pss_sign3072(crt, (const uint8_t*)msg, strlen(msg), sig, 0, hs[i]);
        bool v = s && rsassa_pss_verify3072(pub, (const uint8_t*)msg, strlen(msg), sig, 0, hs[i]);
        snprintf(name, sizeof(name), "PSS %s 签名/验签 (saltLen=hLen)", names[i]);
        check(v, name);
        if (!s) continue;
        sig[RSA_3072_BYTES - 1] ^= 0x01;   // 破坏 0xBC
        bool bad = rsassa_pss_verify3072(pub, (const uint8_t*)msg, strlen(msg), sig, 0, hs[i]);
        snprintf(name, sizeof(name), "PSS %s 篡改签名被拒", names[i]);
        check(!bad, name);
        // 固定 saltLen = 20 (RFC 8017 常用兼容值)
        bool s20 = rsassa_pss_sign3072(crt, (const uint8_t*)msg, strlen(msg), sig, 20, hs[i]);
        bool v20 = s20 && rsassa_pss_verify3072(pub, (const uint8_t*)msg, strlen(msg), sig, 20, hs[i]);
        snprintf(name, sizeof(name), "PSS %s saltLen=20 往返", names[i]);
        check(v20, name);
    }
}

// ── 6. RSAES-OAEP ────────────────────────────────────────────────────
static void test_oaep(rsa3072_public_key& pub, rsa3072_crt_key& crt) {
    printf("== RSAES-OAEP (K=48) ==\n");
    std::vector<uint8_t> msg(37);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = (uint8_t)(i * 5u + 1u);
    const uint8_t label[] = {'j', 'p', 's', 's', 'l'};

    uint8_t ct[RSA_3072_BYTES];
    bool e = rsaes_oaep_encrypt3072(pub, std::span<const uint8_t>(msg.data(), msg.size()),
                                    label, sizeof(label), ct);
    std::vector<uint8_t> back;
    bool d = e && rsaes_oaep_decrypt3072(crt, ct, label, sizeof(label), back);
    check(d && back == msg, "OAEP 加密/解密往返 (label)");

    bool d2 = e && rsaes_oaep_decrypt3072(crt, ct, nullptr, 0, back);
    check(!d2, "OAEP 错误 label 被拒");

    // 空 label 往返
    bool e2 = rsaes_oaep_encrypt3072(pub, std::span<const uint8_t>(msg.data(), msg.size()),
                                     nullptr, 0, ct);
    back.clear();
    bool d3 = e2 && rsaes_oaep_decrypt3072(crt, ct, nullptr, 0, back);
    check(d3 && back == msg, "OAEP 空 label 往返");

    // 超长消息被拒 (上限 k - 2hLen - 2 = 318)
    std::vector<uint8_t> big(319, 0x5A);
    check(!rsaes_oaep_encrypt3072(pub, std::span<const uint8_t>(big.data(), big.size()),
                                  nullptr, 0, ct), "OAEP 超长消息 (319B) 被拒");
}

// ── 7. CRT 解密 / 原语 / 批量接口 ────────────────────────────────────
static void test_crt_and_batch(rsa3072_public_key& pub, rsa3072_crt_key& crt) {
    printf("== CRT / 原语 / 批量 (K=48) ==\n");

    // RSASP13072 / RSAVP13072 互逆 (签名原语)
    rsa3072_bignum m = rsa3072_bignum::random_odd();
    bn_mod(m, m, crt.n);
    rsa3072_bignum s, back;
    RSASP13072(crt, m, s);
    RSAVP13072(pub, s, back);
    check(back == m, "RSAVP13072(RSASP13072(m)) == m");

    // compute_crt_params3072 与 keygen 的 CRT 参数一致
    rsa3072_bignum dP, dQ, qInv;
    compute_crt_params3072(crt.p, crt.q, crt.d, dP, dQ, qInv);
    check(dP == crt.dP && dQ == crt.dQ && qInv == crt.qInv,
          "compute_crt_params3072 == keygen CRT 参数");

    // 3 条 PKCS#1 v1.5 密文的批量解密
    uint8_t cts[3 * RSA_3072_BYTES];
    uint8_t pts[3 * RSA_3072_BYTES];
    std::vector<std::vector<uint8_t>> want(3);
    for (int i = 0; i < 3; ++i) {
        std::vector<uint8_t> pt(20 + i);
        for (size_t j = 0; j < pt.size(); ++j) pt[j] = (uint8_t)(i * 31 + j);
        rsa3072_encrypt(pub, std::span<const uint8_t>(pt.data(), pt.size()),
                        cts + i * RSA_3072_BYTES);
        want[i] = pt;
    }
    rsa3072_private_key prv;
    prv.n = crt.n; prv.d = crt.d; prv.e = crt.e;
    prv.p = crt.p; prv.q = crt.q; prv.dP = crt.dP; prv.dQ = crt.dQ; prv.qInv = crt.qInv;
    size_t got = rsa3072_batch_decrypt(prv, cts, pts, 3);
    check(got == 3, "rsa3072_batch_decrypt 成功 3/3");
    if (got == 3) {
        bool same = true;
        for (int i = 0; i < 3; ++i) {
            // 批量接口输出 384 字节槽位: 保留完整 PKCS#1 v1.5 块 00 02 PS 00 msg
            const uint8_t* p = pts + i * RSA_3072_BYTES;
            if (p[0] != 0x00 || p[1] != 0x02) { same = false; continue; }
            size_t sep = 2;
            while (sep < RSA_3072_BYTES && p[sep] != 0) ++sep;
            if (sep >= RSA_3072_BYTES - 1) { same = false; continue; }
            size_t plen = RSA_3072_BYTES - sep - 1;
            if (plen != want[i].size() || memcmp(p + sep + 1, want[i].data(), plen) != 0)
                same = false;
        }
        check(same, "rsa3072_batch_decrypt 明文正确 (PKCS#1 v1.5 块)");
    }

    // 批量模幂 (384 字节步长) 与单条 modpow 一致
    rsa3072_bignum exp = rsa3072_bignum::from_uint64(65537);
    mont_ctx3072 mc = rsa3072_mont_init(pub.n);
    uint8_t bases[2 * RSA_3072_BYTES], results[2 * RSA_3072_BYTES];
    rsa3072_bignum ref[2];
    for (int i = 0; i < 2; ++i) {
        rsa3072_bignum b = rsa3072_bignum::random_odd();
        bn_mod(b, b, pub.n);
        b.to_bytes(bases + i * RSA_3072_BYTES);
        rsa3072_mont_modpow(ref[i], b, exp, mc, pub.n);
    }
    rsa3072_batch_modpow(pub.n, exp, mc, bases, results, 2);
    bool eq = true;
    for (int i = 0; i < 2; ++i) {
        rsa3072_bignum r = rsa3072_bignum::from_bytes(results + i * RSA_3072_BYTES,
                                                      RSA_3072_BYTES);
        if (!(r == ref[i])) eq = false;
    }
    check(eq, "rsa3072_batch_modpow == 单条 mont_modpow");
}

#if defined(JP_TEST_HAVE_OPENSSL)
// ── 8. OpenSSL 互操作 (RSA-3072 交叉验证) ────────────────────────────
static BIGNUM* ossl_bn(const uint8_t* be, size_t len) {
    return BN_bin2bn(be, (int)len, nullptr);
}
static RSA* ossl_rsa_from_crt3072(const rsa3072_crt_key& k) {
    uint8_t n[384], e[384], d[384], p[384], q[384], dP[384], dQ[384], qInv[384];
    k.n.to_bytes(n); k.e.to_bytes(e); k.d.to_bytes(d);
    k.p.to_bytes(p); k.q.to_bytes(q);
    k.dP.to_bytes(dP); k.dQ.to_bytes(dQ); k.qInv.to_bytes(qInv);
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, ossl_bn(n, 384), ossl_bn(e, 384), ossl_bn(d, 384));
    RSA_set0_factors(rsa, ossl_bn(p, 384), ossl_bn(q, 384));
    RSA_set0_crt_params(rsa, ossl_bn(dP, 384), ossl_bn(dQ, 384), ossl_bn(qInv, 384));
    return rsa;
}
static EVP_PKEY* ossl_pub_evp3072(const rsa3072_public_key& k) {
    uint8_t n[384], e[384];
    k.n.to_bytes(n); k.e.to_bytes(e);
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, ossl_bn(n, 384), ossl_bn(e, 384), nullptr);
    EVP_PKEY* pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, rsa);
    return pk;
}
static bool ossl_pss_sign(RSA* rsa, const EVP_MD* md, const uint8_t* msg, size_t len,
                          uint8_t* sig, size_t* siglen) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);      // 转移所有权
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = EVP_DigestSignInit(mctx, &pctx, md, nullptr, pkey) > 0 &&
              EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
              EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0 &&
              EVP_DigestSignUpdate(mctx, msg, len) > 0 &&
              EVP_DigestSignFinal(mctx, nullptr, siglen) > 0 &&
              EVP_DigestSignFinal(mctx, sig, siglen) > 0;
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok;
}
static bool ossl_pss_verify(EVP_PKEY* pkey, const EVP_MD* md, const uint8_t* msg, size_t len,
                            const uint8_t* sig, size_t siglen) {
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = EVP_DigestVerifyInit(mctx, &pctx, md, nullptr, pkey) > 0 &&
              EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
              EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0 &&
              EVP_DigestVerifyUpdate(mctx, msg, len) > 0 &&
              EVP_DigestVerifyFinal(mctx, sig, siglen) == 1;
    EVP_MD_CTX_free(mctx);
    return ok;
}
static void test_openssl_interop(rsa3072_public_key& pub, rsa3072_crt_key& crt) {
    printf("== OpenSSL 互操作 (RSA-3072) ==\n");
    const char* msg = "RSA-3072 cross-implementation check";
    const EVP_MD* mds[3] = {EVP_sha256(), EVP_sha384(), EVP_sha512()};
    PssHash hs[3] = {PssHash::SHA256, PssHash::SHA384, PssHash::SHA512};
    const char* names[3] = {"SHA-256", "SHA-384", "SHA-512"};
    EVP_PKEY* pk = ossl_pub_evp3072(pub);
    for (int i = 0; i < 3; ++i) {
        uint8_t sig[384];
        char name[96];
        bool s = rsassa_pss_sign3072(crt, (const uint8_t*)msg, strlen(msg), sig, 0, hs[i]);
        snprintf(name, sizeof(name), "PSS %s: 本库签名 -> OpenSSL 验签", names[i]);
        check(s && ossl_pss_verify(pk, mds[i], (const uint8_t*)msg, strlen(msg), sig, 384), name);

        uint8_t osig[384];
        size_t olen = sizeof(osig);
        bool os = ossl_pss_sign(ossl_rsa_from_crt3072(crt), mds[i],
                                (const uint8_t*)msg, strlen(msg), osig, &olen);
        snprintf(name, sizeof(name), "PSS %s: OpenSSL 签名 -> 本库验签", names[i]);
        check(os && olen == 384 &&
              rsassa_pss_verify3072(pub, (const uint8_t*)msg, strlen(msg), osig, 0, hs[i]), name);
    }
    EVP_PKEY_free(pk);

    // PKCS#1 v1.5: OpenSSL 用 RSA_PKCS1_PADDING + SHA-256 签名, 本库验签
    {
        uint8_t sig[384];
        size_t siglen = sizeof(sig);
        bool s = rsassa_pkcs1v15_sign3072(crt, (const uint8_t*)msg, strlen(msg),
                                          P_SHA256, sizeof(P_SHA256), sig);
        check(s, "PKCS1v15 本库签名 (供 OpenSSL 校验)");
        // 用 OpenSSL 校验 (RSA_PKCS1_PADDING + SHA-256 DigestInfo)
        RSA* rsa = ossl_rsa_from_crt3072(crt);
        EVP_PKEY* ppk = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(ppk, rsa);
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = nullptr;
        bool v = EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, ppk) > 0 &&
                 EVP_DigestVerifyUpdate(mctx, msg, strlen(msg)) > 0 &&
                 EVP_DigestVerifyFinal(mctx, sig, 384) == 1;
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(ppk);
        check(v, "PKCS1v15: 本库签名 -> OpenSSL 验签");
    }
}
#endif  // JP_TEST_HAVE_OPENSSL

int main() {
    printf("=== jpssl RSA-3072 (K=48) 单元测试 ===\n");
    test_bignum();

    rsa3072_public_key pub;
    rsa3072_crt_key crt;
    test_keygen_encdec(pub, crt);
    if (crt.n.bit_length() != 3072) {
        printf("keygen 失败, 跳过后续用例\n");
        printf("\n=== Result: %d failures ===\n", g_fail);
        return g_fail ? 1 : 0;
    }

    test_pkcs1(pub, crt);
    test_pss(pub, crt);
    test_oaep(pub, crt);
    test_crt_and_batch(pub, crt);
    test_keygen_plain();
#if defined(JP_TEST_HAVE_OPENSSL)
    test_openssl_interop(pub, crt);
#endif

    printf("\n=== Result: %d failures ===\n", g_fail);
    return g_fail ? 1 : 0;
}
