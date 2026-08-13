/**
 * fuzz_tls_handshake.cpp — TLS 消息层 fuzz（记录层周边路径）
 *
 * 覆盖 tls_decrypt 之外的三个解析入口：
 *
 *   1. TLS 1.3 0-RTT early data 解密：tls13_decrypt_early_data()
 *      手工构造服务端会话（early_data_accepted + early 写密钥），
 *      tls13_encrypt_early_data() 生成真实早数据记录作为变异基底。
 *
 *   2. TLS 1.3 服务端 flight 解析：tls13_process_server_flight()
 *      真实握手（Ed25519 证书）后，变异加密 flight（记录层+握手消息
 *      双重边界）喂给客户端状态。
 *
 *   3. TLS 1.2 服务端 flight 解析：tls12_process_server_flight()
 *      真实握手（RSA 证书）后，变异明文 flight（ServerHello/Cert/
 *      SKX/ServerHelloDone 消息边界）喂给客户端状态。
 *
 * 模式与 fuzz_tls_record / fuzz_dtls_record 相同：确定性回归（默认）
 * + libFuzzer（-DJP_FUZZ_LIBFUZZER）。ASan/UBSan 下运行捕获内存错误。
 */

#include "tls.hpp"
#include "ed25519.hpp"
#include "rsa.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
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
// Part 1：TLS 1.3 early data 解密会话
// ──────────────────────────────────────────────────────────────────────
const CipherSuite kEarlySuites[] = {
    CipherSuite::TLS_AES_128_GCM_SHA256,
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_AES_128_CCM_SHA256,
    CipherSuite::TLS_AES_128_CCM_8_SHA256,
    CipherSuite::TLS_SM4_GCM_SM3,
    CipherSuite::TLS_SM4_CCM_SM3,
};

struct EarlyPair {
    CipherSuite suite;
    tls_session enc;  // 客户端：加密 early data
    tls_session dec;  // 服务端：解密 early data
    const char* name;
};

EarlyPair make_early_pair(CipherSuite suite, Rng& rng) {
    EarlyPair p;
    p.suite = suite;
    uint8_t key[32], iv[12];
    for (auto& b : key) b = rng.byte();
    for (auto& b : iv)  b = rng.byte();

    auto fill = [&](tls_session& s, bool is_server) {
        s.ver = TLSVersion::V13;
        s.is_server = is_server;
        s.cipher_suite = suite;
        s.early_data_accepted = true;
        std::memcpy(s.client_early_write_key, key, 32);
        std::memcpy(s.client_early_write_iv, iv, 12);
        s.client_early_seq = 0;
    };
    fill(p.enc, false);
    fill(p.dec, true);
    return p;
}

std::vector<uint8_t> fresh_early_record(EarlyPair& p, size_t len) {
    std::vector<uint8_t> payload(len);
    for (auto& b : payload) b = (uint8_t)(&b - payload.data());
    tls_session tmp = p.enc;
    return tls13_encrypt_early_data(tmp, payload.data(), payload.size());
}

void fuzz_early(EarlyPair& p, const std::vector<uint8_t>& input) {
    ContentType ct;
    std::vector<uint8_t> out;
    (void)tls13_decrypt_early_data(p.dec, input.data(), input.size(), ct, out);
}

// ──────────────────────────────────────────────────────────────────────
// Part 2/3：TLS 1.3 / 1.2 服务端 flight 解析会话
// ──────────────────────────────────────────────────────────────────────
struct HandshakePair {
    tls_session client;         // 已发 ClientHello 的客户端状态（fuzz 时拷贝）
    std::vector<uint8_t> valid_flight;   // 真实服务端 flight（变异基底）
    const char* name;
};

std::unique_ptr<tls_certificate> make_ed25519_cert() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "fuzz.local";
    cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);
    return cert;
}

// TLS 1.3：Ed25519 证书 + X25519，生成加密服务端 flight
bool prepare_tls13(HandshakePair& p) {
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("fuzz.local", make_ed25519_cert());

    p.client.server_name = "fuzz.local";
    std::vector<uint8_t> ch;
    if (!tls13_make_client_hello(p.client, ch)) return false;
    tls_session server;
    if (!tls13_make_server_flight(server, ch.data(), ch.size(), p.valid_flight, cert_mgr))
        return false;
    return !p.valid_flight.empty();
}

// TLS 1.2：RSA 证书，生成明文服务端 flight
bool prepare_tls12(HandshakePair& p, std::vector<uint8_t>& pre_master) {
    tls_certificate_manager cert_mgr;
    auto cert = make_ed25519_cert();
    cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    rsa_keygen(cert->pub.rsa, cert->priv.rsa);
    cert_mgr.add_certificate("fuzz.local", std::move(cert));

    p.client.server_name = "fuzz.local";
    std::vector<uint8_t> ch;
    if (!tls12_make_client_hello(p.client, ch)) return false;

    pre_master.assign(48, 0);
    pre_master[0] = 0x03;
    pre_master[1] = 0x03;
    uint8_t encrypted_pms[256];
    const tls_certificate* cert_ptr = cert_mgr.get_default_certificate();
    if (!cert_ptr) return false;
    // rsa_encrypt 填充 encrypted_pms（RSA-2048 密文 256 字节）
    rsa_encrypt(cert_ptr->pub.rsa, std::span<const uint8_t>(pre_master.data(), 48),
                encrypted_pms);

    tls_session server;
    uint8_t decrypted_pms[48];
    if (!tls12_make_server_flight(server, ch.data(), ch.size(), p.valid_flight,
                                  encrypted_pms, sizeof(encrypted_pms), decrypted_pms,
                                  cert_mgr))
        return false;
    return !p.valid_flight.empty();
}

// ──────────────────────────────────────────────────────────────────────
// 通用 flight 变异
// ──────────────────────────────────────────────────────────────────────
std::vector<uint8_t> mutate_flight(const std::vector<uint8_t>& valid, Rng& rng) {
    const size_t op = rng.below(9);
    std::vector<uint8_t> m = valid;

    switch (op) {
        case 0: {  // 比特翻转
            unsigned flips = 1 + rng.below(8);
            for (unsigned i = 0; i < flips && !m.empty(); ++i)
                m[rng.below(m.size())] ^= (uint8_t)(1u << rng.below(8));
            break;
        }
        case 1: {  // 截断
            if (m.size() > 1)
                m.resize(m.size() - 1 - rng.below(std::min<size_t>(m.size() - 1, 64)));
            break;
        }
        case 2: {  // 追加垃圾
            size_t n = 1 + rng.below(128);
            for (size_t i = 0; i < n; ++i) m.push_back(rng.byte());
            break;
        }
        case 3: {  // 篡改随机位置的长度字段（record 头 2B 或握手消息头 3B）
            if (m.size() >= 8) {
                size_t off = rng.below(m.size() - 2);
                uint16_t len = (uint16_t)rng.below(65536);
                m[off] = (uint8_t)(len >> 8);
                m[off + 1] = (uint8_t)len;
            }
            break;
        }
        case 4: {  // 篡改 record 头长度字段（前 5 字节）
            if (m.size() >= 5) {
                uint16_t len = (uint16_t)rng.below(65536);
                m[3] = (uint8_t)(len >> 8);
                m[4] = (uint8_t)len;
            }
            break;
        }
        case 5: {  // 篡改握手消息长度字段（offset 5..8，TLS 1.3 内层）
            if (m.size() >= 9) {
                uint32_t len = (uint32_t)rng.below(0x1000000);
                m[5] = (uint8_t)(len >> 16);
                m[6] = (uint8_t)(len >> 8);
                m[7] = (uint8_t)len;
            }
            break;
        }
        case 6: {  // 随机重写一段连续区域
            if (m.size() >= 4) {
                size_t off = rng.below(m.size() - 2);
                size_t n = 1 + rng.below(std::min<size_t>(m.size() - off, 64));
                for (size_t i = 0; i < n; ++i) m[off + i] = rng.byte();
            }
            break;
        }
        case 7: {  // 多 flight 拼接
            size_t n = 2 + rng.below(2);
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

// ──────────────────────────────────────────────────────────────────────
// 回归主流程
// ──────────────────────────────────────────────────────────────────────
int run_handshake_regression(uint64_t seed, size_t iters, bool verbose) {
    Rng rng(seed);
    int failures = 0;

    // ── Part 1: early data ──
    for (auto suite : kEarlySuites) {
        EarlyPair p = make_early_pair(suite, rng);

        std::vector<uint8_t> valid = fresh_early_record(p, 64);
        ContentType ct;
        std::vector<uint8_t> out;
        tls_session check = p.dec;
        if (!tls13_decrypt_early_data(check, valid.data(), valid.size(), ct, out) || out.empty()) {
            std::fprintf(stderr, "[SELF-CHECK FAIL] early data 解密失败 suite=%d\n", (int)suite);
            ++failures;
            continue;
        }

        for (size_t i = 0; i < iters; ++i) {
            ++p.enc.client_early_seq;
            std::vector<uint8_t> input;
            unsigned kind = rng.below(100);
            if (kind < 50) {
                size_t n = rng.below(4096);
                input.assign(n, 0);
                for (auto& b : input) b = rng.byte();
            } else if (kind < 65) {
                input = {};  // 空 / 残头边界
                for (size_t j = 0; j < rng.below(6); ++j) input.push_back(rng.byte());
            } else if (kind < 90) {
                input = mutate_flight(fresh_early_record(p, 1 + rng.below(2048)), rng);
            } else {
                input = valid;
            }
            fuzz_early(p, input);
        }
        if (verbose) std::printf("  early data %-24s %zu 迭代完成\n", "", iters);
    }

    // ── Part 2: TLS 1.3 server flight ──
    {
        HandshakePair p;
        p.name = "TLS1.3 server flight";
        if (!prepare_tls13(p)) {
            std::fprintf(stderr, "[PREP FAIL] TLS 1.3 握手准备失败\n");
            return 1;
        }
        // 自检：未变异的 flight 必须解析成功
        {
            tls_session c = p.client;
            std::vector<uint8_t> cf;
            if (!tls13_process_server_flight(c, p.valid_flight.data(), p.valid_flight.size(),
                                             cf, nullptr)) {
                std::fprintf(stderr, "[SELF-CHECK FAIL] TLS 1.3 有效 flight 解析失败\n");
                ++failures;
            }
        }
        for (size_t i = 0; i < iters; ++i) {
            tls_session c = p.client;  // 每次隔离状态
            std::vector<uint8_t> input = mutate_flight(p.valid_flight, rng);
            std::vector<uint8_t> cf;
            (void)tls13_process_server_flight(c, input.data(), input.size(), cf, nullptr);
        }
        if (verbose) std::printf("  %-24s %zu 迭代完成\n", p.name, iters);
    }

    // ── Part 3: TLS 1.2 server flight ──
    {
        HandshakePair p;
        p.name = "TLS1.2 server flight";
        std::vector<uint8_t> pre_master;
        if (!prepare_tls12(p, pre_master)) {
            std::fprintf(stderr, "[PREP FAIL] TLS 1.2 握手准备失败\n");
            return 1;
        }
        {
            tls_session c = p.client;
            std::vector<uint8_t> cf;
            if (!tls12_process_server_flight(c, p.valid_flight.data(), p.valid_flight.size(),
                                             pre_master.data(), pre_master.size(), cf)) {
                std::fprintf(stderr, "[SELF-CHECK FAIL] TLS 1.2 有效 flight 解析失败\n");
                ++failures;
            }
        }
        for (size_t i = 0; i < iters; ++i) {
            tls_session c = p.client;
            std::vector<uint8_t> input = mutate_flight(p.valid_flight, rng);
            std::vector<uint8_t> cf;
            (void)tls12_process_server_flight(c, input.data(), input.size(),
                                              pre_master.data(), pre_master.size(), cf);
        }
        if (verbose) std::printf("  %-24s %zu 迭代完成\n", p.name, iters);
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
    static Rng rng(0x0DDBA11FACE5EEDULL);
    unsigned kind = data[0] % 3;
    const uint8_t* rec = data + 1;
    size_t rec_len = size - 1;
    if (rec_len > 65540) rec_len = 65540;

    static EarlyPair* ep = nullptr;
    static CipherSuite ep_suite = CipherSuite::UNKNOWN;
    if (kind == 0) {
        CipherSuite suite = kEarlySuites[data[0] % (sizeof(kEarlySuites) / sizeof(kEarlySuites[0]))];
        if (ep == nullptr || ep_suite != suite) {
            if (ep) delete ep;
            ep = new EarlyPair(make_early_pair(suite, rng));
            ep_suite = suite;
        }
        fuzz_early(*ep, std::vector<uint8_t>(rec, rec + rec_len));
        return 0;
    }

    static HandshakePair* h13 = nullptr;
    static HandshakePair* h12 = nullptr;
    static std::vector<uint8_t>* pms12 = nullptr;
    if (kind == 1) {
        if (h13 == nullptr) { h13 = new HandshakePair(); h13->name = "13"; prepare_tls13(*h13); }
        tls_session c = h13->client;
        std::vector<uint8_t> cf;
        (void)tls13_process_server_flight(c, rec, rec_len, cf, nullptr);
        return 0;
    }
    if (h12 == nullptr) {
        h12 = new HandshakePair(); h12->name = "12";
        pms12 = new std::vector<uint8_t>();
        prepare_tls12(*h12, *pms12);
    }
    tls_session c = h12->client;
    std::vector<uint8_t> cf;
    (void)tls12_process_server_flight(c, rec, rec_len, pms12->data(), pms12->size(), cf);
    return 0;
}
#else

int main(int argc, char** argv) {
    uint64_t seed = 0xA5A5A5A5C3C3C3C3ULL;
    size_t iters = 10000;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--seed" && i + 1 < argc) seed = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--iters" && i + 1 < argc) iters = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--verbose") verbose = true;
        else {
            std::fprintf(stderr,
                "用法: %s [--seed N] [--iters N] [--verbose]\n"
                "  TLS 消息层 fuzz 回归（early data + 1.3/1.2 server flight 解析）\n"
                "  建议在 ASan/UBSan 构建下运行以捕获内存错误。\n", argv[0]);
            return 2;
        }
    }

    std::printf("TLS 消息层 fuzz 回归：seed=0x%llx iters=%zu\n",
                (unsigned long long)seed, iters);
    int failures = run_handshake_regression(seed, iters, verbose);
    if (failures == 0) {
        std::printf("PASS: early data + TLS1.3/TLS1.2 flight 解析全部通过\n");
        return 0;
    }
    std::fprintf(stderr, "FAIL: %d 项失败\n", failures);
    return 1;
}
#endif  // JP_FUZZ_LIBFUZZER
