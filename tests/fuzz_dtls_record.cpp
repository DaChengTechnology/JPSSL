/**
 * fuzz_dtls_record.cpp — DTLS 记录层 fuzz 测试
 *
 * 目标：jpssl 的 DTLS 记录层解密入口 dtls_unprotect_application()
 * （src/dtls.cpp，覆盖 RFC 6347 DTLS 1.2 与 RFC 9147 DTLS 1.3）。
 * 任何数据报必须被安全拒绝（返回 false 且不崩溃/不越界/不死循环），
 * 合法数据报必须被正确还原。
 *
 *   1. 确定性回归 fuzz（默认模式，main 入口）
 *      固定种子 PRNG 生成畸形输入，覆盖 DTLS 1.2/1.3 × 各 AEAD 套件 ×
 *      双方向 × 多种语料形态（纯随机 / 受控头部 / 有效数据报变异 / 边界）。
 *      ASan/UBSan 下运行即可把内存错误转化为进程崩溃，由 ctest 捕获。
 *
 *   2. libFuzzer 模式（编译期 -DJP_FUZZ_LIBFUZZER）
 *      LLVMFuzzerTestOneInput 入口：首字节选会话，其余字节直接作为
 *      DTLS 数据报喂给 dtls_unprotect_application。
 *
 * 语料构造：
 *   - 每个会话对手工构造密钥材料（DTLS 1.2 写密钥 + DTLS 1.3 traffic
 *     secrets），dtls_protect_application 生成真实有效数据报作为变异基底
 *     （自检必须解密成功）。
 *   - 变异操作：比特翻转、截断、追加、长度/epoch/seq/类型字段篡改、
 *     DTLS 1.3 首字节位翻转（0x20/0x10/seq16/has_len/epoch_bits）、
 *     随机重写、多数据报拼接、原样透传。
 */

#include "dtls.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::dtls;
using namespace jpssl::tls;

namespace {

// ──────────────────────────────────────────────────────────────────────
// 确定性 PRNG（splitmix64）
// ──────────────────────────────────────────────────────────────────────
struct Rng {
    uint64_t state;
    explicit Rng(uint64_t seed) : state(seed) {}
    uint64_t next() {
        uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    size_t below(size_t n) { return n == 0 ? 0 : (size_t)(next() % n); }
    uint8_t byte() { return (uint8_t)(next() >> 56); }
    bool coin() { return (next() & 1) != 0; }
};

// ──────────────────────────────────────────────────────────────────────
// 会话矩阵：DTLS 版本 × AEAD 套件 × 双方向
// ──────────────────────────────────────────────────────────────────────
struct DtlsCase {
    DTLSVersion ver;
    CipherSuite suite;
    size_t key_len;  // 记录密钥长度（DTLS 1.2 直接使用；1.3 由 traffic secret 派生）
    size_t iv_len;   // DTLS 1.2 固定 IV 长度（GCM=4 / ChaCha20=12）
    const char* name;
};

const DtlsCase kDtlsSuites[] = {
    // DTLS 1.2（RFC 6347：AEAD 记录，仅 AES-GCM / ChaCha20-Poly1305）
    { DTLSVersion::V12, CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,       16,  4, "1.2 AES-128-GCM" },
    { DTLSVersion::V12, CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,       32,  4, "1.2 AES-256-GCM" },
    { DTLSVersion::V12, CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 12, "1.2 ChaCha20-Poly1305" },
    // DTLS 1.3（RFC 9147：首字节 0x20 位标记 + 掩码序列号）
    { DTLSVersion::V13, CipherSuite::TLS_AES_128_GCM_SHA256,                      16, 12, "1.3 AES-128-GCM" },
    { DTLSVersion::V13, CipherSuite::TLS_AES_256_GCM_SHA384,                      32, 12, "1.3 AES-256-GCM" },
    { DTLSVersion::V13, CipherSuite::TLS_CHACHA20_POLY1305_SHA256,                32, 12, "1.3 ChaCha20-Poly1305" },
};

// 会话对：enc 生成有效数据报，dec 解析任意数据报。
struct DtlsPair {
    DtlsCase dc;
    bool dec_is_server;
    dtls_session enc;  // 发送方
    dtls_session dec;  // 解析方
    const char* dir_name;
};

DtlsPair make_dtls_pair(const DtlsCase& dc, bool dec_is_server, Rng& rng) {
    DtlsPair p;
    p.dc = dc;
    p.dec_is_server = dec_is_server;
    p.dir_name = dec_is_server ? "client→server" : "server→client";

    // 一份随机密钥材料 + DTLS 1.3 traffic secrets，enc/dec 共享
    uint8_t ck[32], sk[32], civ[16], siv[16];
    uint8_t c_hs[48], s_hs[48], c_app[48], s_app[48];
    for (auto& b : ck)   b = rng.byte();
    for (auto& b : sk)   b = rng.byte();
    for (auto& b : civ)  b = rng.byte();
    for (auto& b : siv)  b = rng.byte();
    for (auto& b : c_hs) b = rng.byte();
    for (auto& b : s_hs) b = rng.byte();
    for (auto& b : c_app) b = rng.byte();
    for (auto& b : s_app) b = rng.byte();

    auto fill = [&](dtls_session& s, bool is_server) {
        s.ver = dc.ver;
        s.is_server = is_server;
        s.cipher_suite = dc.suite;
        s.key_len = dc.key_len;
        s.iv_len = dc.iv_len;
        std::memcpy(s.client_write_key, ck, sizeof ck);
        std::memcpy(s.server_write_key, sk, sizeof sk);
        std::memcpy(s.client_write_iv,  civ, sizeof civ);
        std::memcpy(s.server_write_iv,  siv, sizeof siv);
        std::memcpy(s.client_hs_traffic,  c_hs, sizeof c_hs);
        std::memcpy(s.server_hs_traffic,  s_hs, sizeof s_hs);
        std::memcpy(s.client_app_traffic, c_app, sizeof c_app);
        std::memcpy(s.server_app_traffic, s_app, sizeof s_app);
        // 应用数据 epoch：1.2 任意 ≥1；1.3 为 3（application traffic）
        s.send_epoch = (dc.ver == DTLSVersion::V12) ? 1 : 3;
        s.recv_epoch = s.send_epoch;
        s.send_seq = 0;
        s.recv_seq = 0;
    };

    fill(p.enc, !dec_is_server);
    fill(p.dec, dec_is_server);
    return p;
}

// 用发送方当前状态生成一条真实有效数据报（拷贝会话，不污染 enc 的 seq）。
std::vector<uint8_t> fresh_valid_datagram(DtlsPair& p, size_t payload_len) {
    std::vector<uint8_t> payload(payload_len);
    for (size_t i = 0; i < payload_len; ++i)
        payload[i] = (uint8_t)(i * 131 + payload_len);
    dtls_session tmp = p.enc;
    return dtls_protect_application(tmp, payload.data(), payload.size());
}

// ──────────────────────────────────────────────────────────────────────
// 变异语料
// ──────────────────────────────────────────────────────────────────────

// 长度字段边界值
const uint16_t kLenBoundaries[] = {
    0, 1, 2, 7, 8, 15, 16, 17, 22, 23, 24, 25, 31, 63, 64, 255, 256, 1024, 2047, 65535
};

std::vector<uint8_t> mutate_dtls_valid(const std::vector<uint8_t>& valid, const DtlsCase& dc,
                                       Rng& rng) {
    const bool v13 = (dc.ver == DTLSVersion::V13);
    const size_t hdr = v13 ? 5 : 13;
    const size_t op = rng.below(9);
    std::vector<uint8_t> m = valid;

    switch (op) {
        case 0: {  // 比特翻转 1..8 处
            unsigned flips = 1 + rng.below(8);
            for (unsigned i = 0; i < flips && !m.empty(); ++i)
                m[rng.below(m.size())] ^= (uint8_t)(1u << rng.below(8));
            break;
        }
        case 1: {  // 截断尾部
            if (m.size() > 1)
                m.resize(m.size() - 1 - rng.below(std::min<size_t>(m.size() - 1, 32)));
            break;
        }
        case 2: {  // 追加随机垃圾
            size_t n = 1 + rng.below(64);
            for (size_t i = 0; i < n; ++i) m.push_back(rng.byte());
            break;
        }
        case 3: {  // 篡改长度字段到边界值并同步 buffer
            if (m.size() >= hdr) {
                uint16_t len = kLenBoundaries[rng.below(sizeof(kLenBoundaries) / sizeof(kLenBoundaries[0]))];
                if (v13) { m[3] = (uint8_t)(len >> 8); m[4] = (uint8_t)len; }
                else     { m[11] = (uint8_t)(len >> 8); m[12] = (uint8_t)len; }
                m.resize(hdr + len);
                for (size_t i = hdr; i < m.size(); ++i) m[i] = rng.byte();
            }
            break;
        }
        case 4: {  // 篡改长度字段但不同步 buffer
            if (m.size() >= hdr) {
                uint16_t len = kLenBoundaries[rng.below(sizeof(kLenBoundaries) / sizeof(kLenBoundaries[0]))];
                if (v13) { m[3] = (uint8_t)(len >> 8); m[4] = (uint8_t)len; }
                else     { m[11] = (uint8_t)(len >> 8); m[12] = (uint8_t)len; }
            }
            break;
        }
        case 5: {  // 篡改头部字段
            if (!m.empty()) {
                if (v13) {
                    m[0] = rng.byte();                       // 首字节（0x20 位/seq16/has_len/epoch）
                    if (m.size() >= 3) { m[1] = rng.byte(); m[2] = rng.byte(); }  // 掩码序列号
                } else {
                    m[0] = rng.byte();                       // content type
                    if (m.size() >= 3) { m[1] = 0xfe; m[2] = 0xfd; }
                    if (m.size() >= 5) { m[3] = rng.byte(); m[4] = rng.byte(); }  // epoch
                    if (m.size() >= 11) { for (int i = 5; i < 11; ++i) m[i] = rng.byte(); }  // seq
                }
            }
            break;
        }
        case 6: {  // 首 5/13 字节受控 + 载荷随机重写
            if (m.size() >= hdr) {
                if (v13) {
                    m[0] = (uint8_t)(0x20 | 0x08 | 0x04 | rng.below(4));
                    m[1] = rng.byte(); m[2] = rng.byte();
                    uint16_t len = kLenBoundaries[rng.below(sizeof(kLenBoundaries) / sizeof(kLenBoundaries[0]))];
                    m[3] = (uint8_t)(len >> 8); m[4] = (uint8_t)len;
                    if (len <= 4096) m.resize(5u + len);
                } else {
                    m[0] = rng.byte(); m[1] = 0xfe; m[2] = 0xfd;
                    m[3] = rng.byte(); m[4] = rng.byte();
                    for (int i = 5; i < 11; ++i) m[i] = rng.byte();
                    uint16_t len = kLenBoundaries[rng.below(sizeof(kLenBoundaries) / sizeof(kLenBoundaries[0]))];
                    m[11] = (uint8_t)(len >> 8); m[12] = (uint8_t)len;
                    if (len <= 4096) m.resize(13u + len);
                }
                for (size_t i = hdr; i < m.size(); ++i) m[i] = rng.byte();
            }
            break;
        }
        case 7: {  // 多数据报拼接
            size_t n = 2 + rng.below(3);
            std::vector<uint8_t> joined;
            for (size_t i = 0; i < n; ++i) {
                if (rng.coin()) joined.insert(joined.end(), valid.begin(), valid.end());
                else {
                    size_t junk = 1 + rng.below(64);
                    for (size_t j = 0; j < junk; ++j) joined.push_back(rng.byte());
                }
            }
            m.swap(joined);
            break;
        }
        case 8:  // 原样透传
        default:
            break;
    }
    return m;
}

std::vector<uint8_t> random_datagram(Rng& rng) {
    size_t n = rng.below(8192);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = rng.byte();
    return v;
}

std::vector<uint8_t> boundary_datagram(const DtlsCase& dc, Rng& rng) {
    const bool v13 = (dc.ver == DTLSVersion::V13);
    const size_t hdr = v13 ? 5 : 13;
    switch (rng.below(8)) {
        case 0: return {};
        case 1: return { rng.byte() };
        case 2: {  // 残头
            std::vector<uint8_t> v;
            for (size_t i = 0; i < hdr - 1; ++i) v.push_back(rng.byte());
            return v;
        }
        case 3: {  // 恰好头部，长度=0
            std::vector<uint8_t> v;
            for (size_t i = 0; i < hdr; ++i) v.push_back(rng.byte());
            if (!v13) { v[1] = 0xfe; v[2] = 0xfd; v[11] = 0; v[12] = 0; }
            else { v[0] = (uint8_t)(0x20 | 0x08 | 0x04 | rng.below(4)); v[3] = 0; v[4] = 0; }
            return v;
        }
        case 4: {  // 微型长度 1..15（AEAD tag 边界之下）
            std::vector<uint8_t> v;
            for (size_t i = 0; i < hdr; ++i) v.push_back(rng.byte());
            uint16_t len = (uint16_t)(1 + rng.below(15));
            if (!v13) { v[1] = 0xfe; v[2] = 0xfd; v[11] = (uint8_t)(len >> 8); v[12] = (uint8_t)len; }
            else { v[0] = (uint8_t)(0x20 | 0x08 | 0x04 | rng.below(4)); v[3] = (uint8_t)(len >> 8); v[4] = (uint8_t)len; }
            for (size_t i = 0; i < len; ++i) v.push_back(rng.byte());
            return v;
        }
        case 5: {  // 声称 65535 长度但 buffer 很小
            std::vector<uint8_t> v;
            for (size_t i = 0; i < hdr; ++i) v.push_back(rng.byte());
            if (!v13) { v[1] = 0xfe; v[2] = 0xfd; v[11] = 0xFF; v[12] = 0xFF; }
            else { v[0] = (uint8_t)(0x20 | 0x08 | 0x04 | rng.below(4)); v[3] = 0xFF; v[4] = 0xFF; }
            for (size_t i = 0; i < rng.below(48); ++i) v.push_back(rng.byte());
            return v;
        }
        case 6: {  // DTLS 1.3 首字节位组合穷举（0x20 位开/关、0x10 位、seq16、has_len、epoch）
            std::vector<uint8_t> v;
            if (v13) {
                uint8_t b0 = (uint8_t)((rng.coin() ? 0x20 : 0) | (rng.coin() ? 0x10 : 0) |
                                       (rng.coin() ? 0x08 : 0) | (rng.coin() ? 0x04 : 0) |
                                       rng.below(4));
                v.push_back(b0);
                if (b0 & 0x08) v.push_back(rng.byte());
                v.push_back(rng.byte());
                if (b0 & 0x04) { v.push_back(rng.byte()); v.push_back(rng.byte()); }
                for (size_t i = 0; i < rng.below(64); ++i) v.push_back(rng.byte());
            } else {
                return { 22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            }
            return v;
        }
        default: {  // 全 0xFF 大记录
            std::vector<uint8_t> v;
            for (size_t i = 0; i < hdr; ++i) v.push_back(0xFF);
            if (!v13) { v[0] = 23; v[1] = 0xfe; v[2] = 0xfd; }
            v.resize(hdr + 65535u, 0xFF);
            return v;
        }
    }
}

void fuzz_unprotect(DtlsPair& p, const std::vector<uint8_t>& input) {
    std::vector<uint8_t> out;
    (void)dtls_unprotect_application(p.dec, input.data(), input.size(), out);
}

int run_dtls_regression(uint64_t seed, size_t iters_per_pair, bool verbose) {
    Rng rng(seed);
    int failures = 0;

    for (const auto& dc : kDtlsSuites) {
        for (int dir = 0; dir < 2; ++dir) {
            DtlsPair p = make_dtls_pair(dc, dir == 1, rng);

            // 自检：有效数据报必须能解密（harness 自身正确性）
            std::vector<uint8_t> valid = fresh_valid_datagram(p, 64);
            std::vector<uint8_t> out;
            dtls_session check = p.dec;
            bool ok = dtls_unprotect_application(check, valid.data(), valid.size(), out);
            if (!ok || out.empty()) {
                std::fprintf(stderr, "[SELF-CHECK FAIL] %s %s 有效数据报解密失败\n",
                             dc.name, p.dir_name);
                ++failures;
                continue;
            }

            for (size_t i = 0; i < iters_per_pair; ++i) {
                std::vector<uint8_t> input;
                unsigned kind = rng.below(100);
                if (kind < 40) {
                    input = random_datagram(rng);
                } else if (kind < 55) {
                    input = boundary_datagram(dc, rng);
                } else if (kind < 90) {
                    std::vector<uint8_t> fresh = fresh_valid_datagram(p, 1 + rng.below(2048));
                    input = mutate_dtls_valid(fresh, dc, rng);
                } else if (kind < 97) {
                    input = mutate_dtls_valid(valid, dc, rng);
                } else {
                    input = valid;  // 原样透传
                }
                fuzz_unprotect(p, input);
            }

            if (verbose)
                std::printf("  %-20s %-14s %zu 迭代完成\n", dc.name, p.dir_name, iters_per_pair);
        }
    }
    return failures;
}

}  // namespace

// ──────────────────────────────────────────────────────────────────────
// libFuzzer 入口
// ──────────────────────────────────────────────────────────────────────
#ifdef JP_FUZZ_LIBFUZZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    static Rng rng(0xD7E1A7E0F00DULL);
    size_t n = sizeof(kDtlsSuites) / sizeof(kDtlsSuites[0]);
    size_t idx = data[0] % (n * 2);
    const DtlsCase& dc = kDtlsSuites[idx / 2];
    bool dec_is_server = (idx & 1) != 0;

    static DtlsPair* cache = nullptr;
    static DtlsCase cache_dc{};
    static bool cache_dir = false;
    if (cache == nullptr || cache_dc.ver != dc.ver || cache_dc.suite != dc.suite ||
        cache_dc.key_len != dc.key_len || cache_dc.iv_len != dc.iv_len ||
        cache_dir != dec_is_server) {
        if (cache) delete cache;
        cache = new DtlsPair(make_dtls_pair(dc, dec_is_server, rng));
        cache_dc = dc;
        cache_dir = dec_is_server;
    }

    const uint8_t* rec = data + 1;
    size_t rec_len = size - 1;
    if (rec_len > 65535 + 13) rec_len = 65535 + 13;
    fuzz_unprotect(*cache, std::vector<uint8_t>(rec, rec + rec_len));
    return 0;
}
#else

int main(int argc, char** argv) {
    uint64_t seed = 0x243F6A8885A308D3ULL;
    size_t iters = 20000;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--seed" && i + 1 < argc) seed = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--iters" && i + 1 < argc) iters = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--verbose") verbose = true;
        else {
            std::fprintf(stderr,
                "用法: %s [--seed N] [--iters N] [--verbose]\n"
                "  DTLS 记录层 fuzz 回归：%zu 套件 × 2 方向 × %zu 迭代\n"
                "  建议在 ASan/UBSan 构建下运行以捕获内存错误。\n",
                argv[0], sizeof(kDtlsSuites) / sizeof(kDtlsSuites[0]), iters);
            return 2;
        }
    }

    std::printf("DTLS 记录层 fuzz 回归：seed=0x%llx iters/pair=%zu\n",
                (unsigned long long)seed, iters);
    int failures = run_dtls_regression(seed, iters, verbose);
    if (failures == 0) {
        std::printf("PASS: 全部 %zu 个会话对通过，无崩溃/越界/失败\n",
                    sizeof(kDtlsSuites) / sizeof(kDtlsSuites[0]) * 2);
        return 0;
    }
    std::fprintf(stderr, "FAIL: %d 个会话对失败\n", failures);
    return 1;
}
#endif  // JP_FUZZ_LIBFUZZER
