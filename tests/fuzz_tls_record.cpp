/**
 * fuzz_tls_record.cpp — TLS 记录层 fuzz 测试
 *
 * 目标：jpssl 的 TLS 记录层解密入口 tls_decrypt()（src/tls_router.cpp）。
 * 任何字节流都必须被安全拒绝（返回 false 且不崩溃/不越界/不死循环），
 * 合法记录必须被正确还原。本 harness 用两类手段穷举解析路径：
 *
 *   1. 确定性回归 fuzz（默认模式，main 入口）
 *      固定种子 PRNG 生成畸形输入，覆盖全部 cipher suite × 双方向 ×
 *      多种语料形态（纯随机 / 受控头部 / 有效记录变异 / 边界 / 拼接）。
 *      在 ASan/UBSan 下运行即可把内存错误转化为进程崩溃，由 ctest 捕获。
 *
 *   2. libFuzzer 模式（编译期 -DJP_FUZZ_LIBFUZZER）
 *      LLVMFuzzerTestOneInput 入口：首字节选会话（版本/套件/方向），
 *      其余字节直接作为 record 输入喂给 tls_decrypt。
 *      配合 clang -fsanitize=fuzzer,address,undefined 使用。
 *
 * 语料构造：
 *   - 每个会话对用随机 key/IV/MAC 手工构造（不握手，毫秒级），
 *     tls_encrypt 生成一条真实有效记录作为变异基底（自检必须解密成功）。
 *   - 变异操作：比特翻转、截断、追加、长度字段篡改（含 rlen-24 下溢窗口
 *     [16,23]）、类型/版本篡改、随机重写、多记录拼接、原样透传。
 */

#include "tls.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace jpssl;
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
// 会话矩阵：全部记录层 cipher suite × 双解密方向
// ──────────────────────────────────────────────────────────────────────
struct SuiteCase {
    TLSVersion ver;
    CipherSuite suite;
    const char* name;
};

const SuiteCase kSuites[] = {
    // TLS 1.3（RFC 8446 / RFC 8998）
    { TLSVersion::V13, CipherSuite::TLS_AES_128_GCM_SHA256,       "1.3 AES-128-GCM"       },
    { TLSVersion::V13, CipherSuite::TLS_AES_256_GCM_SHA384,       "1.3 AES-256-GCM"       },
    { TLSVersion::V13, CipherSuite::TLS_CHACHA20_POLY1305_SHA256, "1.3 ChaCha20-Poly1305" },
    { TLSVersion::V13, CipherSuite::TLS_AES_128_CCM_SHA256,       "1.3 AES-128-CCM"       },
    { TLSVersion::V13, CipherSuite::TLS_AES_128_CCM_8_SHA256,     "1.3 AES-128-CCM-8"     },
    { TLSVersion::V13, CipherSuite::TLS_SM4_GCM_SM3,              "1.3 SM4-GCM"           },
    { TLSVersion::V13, CipherSuite::TLS_SM4_CCM_SM3,              "1.3 SM4-CCM"           },
    // TLS 1.2（GCM / CBC / ChaCha20 / CBC-SHA384）
    { TLSVersion::V12, CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   "1.2 ECDHE-RSA AES-128-GCM"   },
    { TLSVersion::V12, CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,   "1.2 ECDHE-RSA AES-256-GCM"   },
    { TLSVersion::V12, CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,         "1.2 RSA AES-128-CBC(SHA256)" },
    { TLSVersion::V12, CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384,         "1.2 PSK AES-256-CBC(SHA384)" },
    { TLSVersion::V12, CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "1.2 ECDHE-RSA ChaCha20" },
    { TLSVersion::V12, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "1.2 ECDHE-ECDSA AES-128-GCM" },
};

// 一个会话对：enc 用写密钥加密有效记录，dec 用读密钥解析任意输入。
struct SessionPair {
    SuiteCase sc;
    bool dec_is_server;
    tls_session enc;  // 发送方（is_server 与 dec 相反）
    tls_session dec;  // 接收方/解析方
    const char* dir_name;
};

// 填满随机密钥/IV/MAC，构造可独立加密解密的会话对（不握手）。
// 注意：一份密钥材料必须同时写入双方会话（加密方用写密钥、解析方用读密钥，
// 否则两侧密钥不一致，有效记录也无法解密）。
SessionPair make_pair(const SuiteCase& sc, bool dec_is_server, Rng& rng) {
    SessionPair p;
    p.sc = sc;
    p.dec_is_server = dec_is_server;
    p.dir_name = dec_is_server ? "client→server" : "server→client";

    // 一次性生成随机密钥材料，enc/dec 共享同一份
    uint8_t ck[32], sk[32], civ[16], siv[16], cmac[48], smac[48];
    for (auto& b : ck)   b = rng.byte();
    for (auto& b : sk)   b = rng.byte();
    for (auto& b : civ)  b = rng.byte();
    for (auto& b : siv)  b = rng.byte();
    for (auto& b : cmac) b = rng.byte();
    for (auto& b : smac) b = rng.byte();

    auto fill_session = [&](tls_session& s, bool is_server) {
        s.ver = sc.ver;
        s.is_server = is_server;
        s.cipher_suite = sc.suite;
        std::memcpy(s.client_write_key, ck, sizeof ck);
        std::memcpy(s.server_write_key, sk, sizeof sk);
        std::memcpy(s.client_write_iv,  civ, sizeof civ);
        std::memcpy(s.server_write_iv,  siv, sizeof siv);
        std::memcpy(s.client_write_mac, cmac, sizeof cmac);
        std::memcpy(s.server_write_mac, smac, sizeof smac);
        s.client_seq = 0;
        s.server_seq = 0;
    };

    fill_session(p.enc, !dec_is_server);
    fill_session(p.dec, dec_is_server);
    return p;
}

// 用发送方当前写密钥加密一条有效记录（克隆会话，不污染 enc 的 seq）。
std::vector<uint8_t> fresh_valid_record(SessionPair& p, size_t payload_len) {
    std::vector<uint8_t> payload(payload_len);
    for (auto& b : payload) b = (uint8_t)(p.sc.name[0] + payload_len + (&b - payload.data()));
    tls_session tmp = p.enc;  // 拷贝，内部 seq 独立推进
    return tls_encrypt(tmp, ContentType::APPLICATION_DATA, payload.data(), payload.size());
}

// ──────────────────────────────────────────────────────────────────────
// 变异语料
// ──────────────────────────────────────────────────────────────────────

// rlen（长度字段）边界值：覆盖 0 / 1 / tag-1 / tag / CBC 块 / GCM 下溢窗口 / 16 位上限
const uint16_t kRlenBoundaries[] = {
    0, 1, 2, 7, 8, 15, 16, 17, 22, 23, 24, 25, 31, 32, 47, 63, 64,
    255, 256, 1024, 16384, 65535
};

// 变异一条有效记录，返回新输入。
std::vector<uint8_t> mutate_valid(const std::vector<uint8_t>& valid, Rng& rng) {
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
            if (m.size() > 1) m.resize(m.size() - 1 - rng.below(std::min<size_t>(m.size() - 1, 32)));
            break;
        }
        case 2: {  // 追加随机垃圾
            size_t n = 1 + rng.below(64);
            for (size_t i = 0; i < n; ++i) m.push_back(rng.byte());
            break;
        }
        case 3: {  // 篡改长度字段到边界值，并同步 buffer 到 5+rlen'
            if (m.size() >= 5) {
                uint16_t rlen = kRlenBoundaries[rng.below(sizeof(kRlenBoundaries) / sizeof(kRlenBoundaries[0]))];
                m[3] = (uint8_t)(rlen >> 8);
                m[4] = (uint8_t)rlen;
                m.resize(5u + rlen);
                for (size_t i = 5; i < m.size(); ++i) m[i] = rng.byte();
            }
            break;
        }
        case 4: {  // 篡改长度字段但不同步 buffer（外层/内层长度校验路径）
            if (m.size() >= 5) {
                uint16_t rlen = kRlenBoundaries[rng.below(sizeof(kRlenBoundaries) / sizeof(kRlenBoundaries[0]))];
                m[3] = (uint8_t)(rlen >> 8);
                m[4] = (uint8_t)rlen;
            }
            break;
        }
        case 5: {  // 篡改类型 / 版本字节
            if (!m.empty()) m[0] = rng.byte();
            if (m.size() >= 3) { m[1] = rng.byte(); m[2] = rng.byte(); }
            break;
        }
        case 6: {  // 首 5 字节受控（类型/版本/长度），载荷随机重写
            if (m.size() >= 5) {
                m[0] = rng.byte();                       // content type
                m[1] = rng.byte(); m[2] = rng.byte();    // version
                uint16_t rlen = kRlenBoundaries[rng.below(sizeof(kRlenBoundaries) / sizeof(kRlenBoundaries[0]))];
                m[3] = (uint8_t)(rlen >> 8);
                m[4] = (uint8_t)rlen;
                if (rlen <= 4096) m.resize(5u + rlen);
                for (size_t i = 5; i < m.size(); ++i) m[i] = rng.byte();
            }
            break;
        }
        case 7: {  // 多条记录拼接：有效 ± 垃圾
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
        case 8:  // 原样透传（有效记录，解密应成功）
        default:
            break;
    }
    return m;
}

// 纯随机输入（覆盖任意长度，含 0..4 字节残头）
std::vector<uint8_t> random_input(Rng& rng) {
    size_t n = rng.below(8192);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = rng.byte();
    return v;
}

// 边界输入：空、残头、单条/多条记录边界形态
std::vector<uint8_t> boundary_input(Rng& rng) {
    switch (rng.below(8)) {
        case 0: return {};
        case 1: return { rng.byte() };
        case 2: return { rng.byte(), rng.byte(), rng.byte(), rng.byte() };
        case 3: {  // 恰好 5 字节头，rlen=0
            std::vector<uint8_t> v = { rng.byte(), rng.byte(), rng.byte(), 0, 0 };
            return v;
        }
        case 4: {  // rlen=1..4 的微型记录
            uint8_t r = (uint8_t)(1 + rng.below(4));
            std::vector<uint8_t> v = { rng.byte(), rng.byte(), rng.byte(), 0, r };
            for (int i = 0; i < r; ++i) v.push_back(rng.byte());
            return v;
        }
        case 5: {  // 声称 65535 长度但 buffer 很小（外层 5+rlen 校验）
            std::vector<uint8_t> v = { rng.byte(), rng.byte(), rng.byte(), 0xFF, 0xFF };
            for (size_t i = 0; i < rng.below(48); ++i) v.push_back(rng.byte());
            return v;
        }
        case 6: {  // 多条：合法空记录(5B)拼接 + 残尾
            std::vector<uint8_t> v;
            for (int i = 0; i < 3; ++i) v.push_back(rng.byte());
            for (int i = 0; i < 3; ++i) { v.push_back(rng.byte()); v.push_back(0x03); v.push_back(0x03); v.push_back(0); v.push_back(0); }
            v.push_back(rng.byte());
            return v;
        }
        default: {  // 全 0xFF 大记录（rlen=65535，payload 65535 字节）
            std::vector<uint8_t> v = { 0x17, 0x03, 0x03, 0xFF, 0xFF };
            v.resize(5u + 65535u, 0xFF);
            return v;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// 单次 fuzz 迭代：把输入喂给 tls_decrypt
// ──────────────────────────────────────────────────────────────────────
void fuzz_decrypt(SessionPair& p, const std::vector<uint8_t>& input) {
    ContentType ct;
    std::vector<uint8_t> out;
    // 任何输入都必须安全返回：不崩溃、不越界（ASan/UBSan 验证）、不死循环。
    (void)tls_decrypt(p.dec, input.data(), input.size(), ct, out);
}

// ──────────────────────────────────────────────────────────────────────
// 回归主流程
// ──────────────────────────────────────────────────────────────────────
int run_regression(uint64_t seed, size_t iters_per_pair, bool verbose) {
    Rng rng(seed);
    int failures = 0;

    for (const auto& sc : kSuites) {
        for (int dir = 0; dir < 2; ++dir) {
            SessionPair p = make_pair(sc, dir == 1, rng);

            // 自检：有效记录必须能被正确解密（harness 自身正确性）
            std::vector<uint8_t> valid = fresh_valid_record(p, 32 + rng.below(256));
            ContentType ct;
            std::vector<uint8_t> out;
            bool ok = tls_decrypt(p.dec, valid.data(), valid.size(), ct, out);
            if (!ok || ct != ContentType::APPLICATION_DATA || out.empty()) {
                std::fprintf(stderr, "[SELF-CHECK FAIL] %s %s 有效记录解密失败\n",
                             sc.name, p.dir_name);
                ++failures;
                continue;
            }

            size_t iters = iters_per_pair;
            for (size_t i = 0; i < iters; ++i) {
                // 发送方 seq 与解析方 seq 同步推进，保证"原样透传"输入可解密成功
                ++p.enc.client_seq;
                ++p.enc.server_seq;

                std::vector<uint8_t> input;
                unsigned kind = rng.below(100);
                if (kind < 40) {
                    input = random_input(rng);
                } else if (kind < 55) {
                    input = boundary_input(rng);
                } else if (kind < 70) {
                    // 变异基底：当前 seq 下重新生成的有效记录
                    std::vector<uint8_t> fresh = fresh_valid_record(p, 1 + rng.below(4096));
                    input = mutate_valid(fresh, rng);
                } else if (kind < 95) {
                    // 变异基底：固定有效记录（跨 seq，解密多失败——覆盖 seq 不匹配路径）
                    input = mutate_valid(valid, rng);
                } else {
                    input = valid;  // 原样有效记录（与当前 seq 匹配，应成功）
                }
                fuzz_decrypt(p, input);
            }

            if (verbose)
                std::printf("  %-24s %-14s %zu 迭代完成\n", sc.name, p.dir_name, iters);
        }
    }
    return failures;
}

// ──────────────────────────────────────────────────────────────────────
// 已知缺陷回归：fuzz 曾发现并已修复的崩溃输入，固化防止重新引入
// ──────────────────────────────────────────────────────────────────────
// 缺陷：TLS 1.2 AES-GCM 记录 rlen∈[16,23] 时 ct_len = rlen-24 无符号下溢，
// aes_gcm_decrypt 以巨大长度访问内存导致进程崩溃（已修复于 tls_router.cpp）。
// 此函数构造该输入窗口，断言 tls_decrypt 安全返回 false。
int known_crash_regressions() {
    int failures = 0;
    Rng rng(0xF0CACC1EBAD5EEDULL);
    const SuiteCase& sc = kSuites[7];  // 1.2 ECDHE-RSA AES-128-GCM
    for (int dir = 0; dir < 2; ++dir) {
        SessionPair p = make_pair(sc, dir == 1, rng);
        for (uint16_t rlen = 16; rlen <= 23; ++rlen) {
            std::vector<uint8_t> in = { 0x17, 0x03, 0x03,
                                        (uint8_t)(rlen >> 8), (uint8_t)rlen };
            in.resize(5u + rlen, 0x42);
            ContentType ct;
            std::vector<uint8_t> out;
            bool ok = tls_decrypt(p.dec, in.data(), in.size(), ct, out);
            if (ok) {
                std::fprintf(stderr, "[REGRESSION] %s %s rlen=%u 畸形记录被解密成功\n",
                             sc.name, p.dir_name, (unsigned)rlen);
                ++failures;
            }
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
    static Rng rng(0x5EEDF00DC0FFEEULL);  // 仅用于构造会话

    size_t n_suites = sizeof(kSuites) / sizeof(kSuites[0]);
    size_t idx = (data[0] % (n_suites * 2));
    const SuiteCase& sc = kSuites[idx / 2];
    bool dec_is_server = (idx & 1) != 0;

    // 每个会话对缓存一次，之后复用（避免每次迭代重建）
    static SessionPair* cache = nullptr;
    static SuiteCase cache_sc{};
    static bool cache_dir = false;
    if (cache == nullptr || cache_sc.ver != sc.ver || cache_sc.suite != sc.suite ||
        cache_dir != dec_is_server) {
        if (cache) delete cache;
        cache = new SessionPair(make_pair(sc, dec_is_server, rng));
        cache_sc = sc;
        cache_dir = dec_is_server;
        ++cache->enc.client_seq; ++cache->enc.server_seq;  // 推进一次，模拟新记录
    }

    const uint8_t* rec = data + 1;
    size_t rec_len = size - 1;
    if (rec_len > 65540) rec_len = 65540;  // 单条 record 上限 5 + 65535
    fuzz_decrypt(*cache, std::vector<uint8_t>(rec, rec + rec_len));
    return 0;
}
#else

// ──────────────────────────────────────────────────────────────────────
// 独立回归模式 main
// ──────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    uint64_t seed = 0x6A09E667F3BCC909ULL;
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
                "  TLS 记录层 fuzz 回归：%zu 套件 × 2 方向 × %zu 迭代\n"
                "  建议在 ASan/UBSan 构建下运行以捕获内存错误。\n",
                argv[0], sizeof(kSuites) / sizeof(kSuites[0]), iters);
            return 2;
        }
    }

    std::printf("TLS 记录层 fuzz 回归：seed=0x%llx iters/pair=%zu\n",
                (unsigned long long)seed, iters);
    int failures = known_crash_regressions();
    if (failures != 0) {
        std::fprintf(stderr, "FAIL: 已知缺陷回归 %d 项失败\n", failures);
        return 1;
    }
    failures = run_regression(seed, iters, verbose);
    if (failures == 0) {
        std::printf("PASS: 全部 %zu 个会话对通过，无崩溃/越界/失败\n",
                    sizeof(kSuites) / sizeof(kSuites[0]) * 2);
        return 0;
    }
    std::fprintf(stderr, "FAIL: %d 个会话对失败\n", failures);
    return 1;
}
#endif  // JP_FUZZ_LIBFUZZER
