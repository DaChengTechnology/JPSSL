/**
 * test_tls_stability.cpp -- TLS 稳定性 / 长稳 (soak) 测试
 *
 * 目的：在单次运行内反复执行握手与加密数据传输，暴露
 *   1. 重复握手 / 会话重建过程中的状态串扰与崩溃;
 *   2. 记录层长时间、大流量传输下的完整性错误（大消息自动分片为
 *      <=16KiB record，接收侧自动合并还原）;
 *   3. 0-RTT / PSK 会话恢复机制的稳定性;
 *   4. socket 封装层端到端握手 + 数据传输的稳定性;
 *   5. 多线程并发握手下的稳定性（可选，--threads N）;
 *   6. 进程内存占用增长（泄漏启发式检测）。
 *
 * 覆盖场景：
 *   A. TLS 1.3 内存内完整握手 × N（轮换 Ed25519 / ECDSA P-256 / RSA-2048 证书）
 *   B. TLS 1.2 (RSA) 内存内完整握手 × M
 *   C. TLS 1.3 NewSessionTicket + PSK 恢复 + 0-RTT early data × K
 *   D. TLS-over-TCP socket 握手 + 双向分块数据 × S
 *   E. 并发 worker（每 worker 独立 listener + 客户端）各执行 S 轮（--threads > 1）
 *
 * 迭代次数可通过命令行参数或环境变量覆盖，默认值适合 CTest 快速执行：
 *   JPSSL_STRESS_ITERS / --iters           TLS 1.3 内存握手轮数 (默认 150)
 *   JPSSL_STRESS_TLS12_ITERS / --tls12-iters TLS 1.2 内存握手轮数 (默认 50)
 *   JPSSL_STRESS_PSK_ITERS / --psk-iters    PSK 恢复轮数 (默认 30)
 *   JPSSL_STRESS_SOCKET_ITERS / --socket-iters socket 握手轮数 (默认 20)
 *   JPSSL_STRESS_THREADS / --threads        并发 worker 数 (默认 1 = 不启用)
 *   JPSSL_STRESS_LEAK_MB / --leak-mb        内存增长失败阈值 MiB (默认 128, 0 = 关闭)
 *   --seed N                                确定性数据种子
 *   --quiet                                 仅输出摘要
 */

#include "tls.hpp"
#include "tls_socket.hpp"
#include "ecdsa.hpp"
#include "ed25519.hpp"
#include "rsa.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "jpssl_memory.hpp"
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#else
#include <fstream>
#include <sstream>
#endif

using namespace jpssl;
using namespace jpssl::tls;

namespace {

// ========================================================================
//  配置与统计
// ========================================================================

struct Options {
    long long iters = 150;          // TLS 1.3 内存握手
    long long tls12_iters = 50;     // TLS 1.2 内存握手
    long long psk_iters = 30;       // PSK 恢复
    long long socket_iters = 20;    // socket 握手
    int threads = 1;                // 并发 worker（1 = 关闭并发阶段）
    size_t leak_threshold_mb = 128; // 内存增长阈值，0 = 关闭
    uint64_t seed = 0x9E3779B97F4A7C15ULL;
    bool quiet = false;
};

std::atomic<long long> g_failures{0};
std::mutex g_log_mutex;

void report_fail(const char* msg, long long iter, const char* detail = "") {
    g_failures.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::fprintf(stderr, "  FAIL [iter %lld] %s %s\n", iter, msg, detail);
}

struct PhaseStats {
    long long iters = 0;
    long long ok = 0;
    long long fail = 0;
    double total_ms = 0.0;
    double min_ms = 0.0;
    double max_ms = 0.0;
    size_t bytes = 0;  // 单向传输字节数

    void add(double ms, bool success, size_t bytes_this_iter = 0) {
        ++iters;
        total_ms += ms;
        if (success) ++ok; else ++fail;
        if (iters == 1 || ms < min_ms) min_ms = ms;
        if (ms > max_ms) max_ms = ms;
        bytes += bytes_this_iter;
    }

    void print(const char* title, bool quiet) const {
        if (quiet) return;
        double avg = iters ? total_ms / iters : 0.0;
        double mb = (double)bytes / (1024.0 * 1024.0);
        double rate = total_ms > 1.0 ? mb * 2.0 * 1000.0 / total_ms : 0.0;
        std::printf("--- %s\n", title);
        std::printf("    iters=%lld ok=%lld fail=%lld total=%.1fms "
                    "avg=%.3fms min=%.3fms max=%.3fms data=%.1fMiB rate=%.1fMiB/s\n",
                    iters, ok, fail, total_ms, avg, min_ms, max_ms, mb, rate);
    }
};

// ========================================================================
//  工具：时间 / 内存 / 数据完整性
// ========================================================================

double now_ms() {
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

size_t current_rss_bytes() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return (size_t)pmc.WorkingSetSize;
    return 0;
#else
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            std::istringstream ss(line.substr(6));
            long kb = 0;
            ss >> kb;
            return (size_t)kb * 1024;
        }
    }
    return 0;
#endif
}

uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

void fill_pattern(uint8_t* p, size_t n, uint64_t seed, uint64_t offset) {
    uint64_t x = seed ^ (offset * 0x9E3779B97F4A7C15ULL);
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        p[i] = (uint8_t)(x >> 32);
    }
}

// TLS record 分片大小：贴近真实栈的 2^14 上限，同时避免本库
// 16 位 record 长度字段溢出。
constexpr size_t RECORD_CHUNK = 16384;

// ========================================================================
//  证书准备
// ========================================================================

struct CertSet {
    const char* name;
    tls_certificate_manager mgr;
};

void add_cert(CertSet& cs, SignatureAlgorithm alg) {
    auto cert = jpssl::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = alg;
    switch (alg) {
        case SignatureAlgorithm::ED25519:
            ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);
            break;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            ecdsa_p256_keygen(cert->pub.ecdsa_p256, cert->priv.ecdsa_p256);
            break;
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
            rsa_keygen(cert->pub.rsa, cert->priv.rsa);
            break;
        default:
            break;
    }
    cs.mgr.add_certificate("localhost", std::move(cert));
}

std::array<CertSet, 3> build_cert_sets() {
    std::array<CertSet, 3> sets{};
    sets[0].name = "Ed25519";
    add_cert(sets[0], SignatureAlgorithm::ED25519);
    sets[1].name = "ECDSA P-256";
    add_cert(sets[1], SignatureAlgorithm::ECDSA_SECP256R1_SHA256);
    sets[2].name = "RSA-2048";
    add_cert(sets[2], SignatureAlgorithm::RSA_PKCS1_SHA256);
    return sets;
}

// ========================================================================
//  内存内记录层传输：tx 分块加密 -> rx 分块解密 + 完整性校验
// ========================================================================

// 整条消息往返：tls_encrypt 自动分片（>16KiB -> 多条 record），
// tls_decrypt 自动合并还原并校验完整性。
bool transfer_message(tls_session& tx, tls_session& rx,
                      const uint8_t* data, size_t len,
                      long long iter, const char* dir) {
    auto records = tls_encrypt(tx, ContentType::APPLICATION_DATA, data, len);
    if (records.empty()) {
        report_fail("tls_encrypt 返回空 record", iter, dir);
        return false;
    }
    ContentType ct;
    std::vector<uint8_t> plain;
    if (!tls_decrypt(rx, records.data(), records.size(), ct, plain)) {
        report_fail("tls_decrypt 失败", iter, dir);
        return false;
    }
    if (ct != ContentType::APPLICATION_DATA || plain.size() != len) {
        report_fail("record 内容类型/长度不一致", iter, dir);
        return false;
    }
    if (fnv1a(plain.data(), plain.size()) != fnv1a(data, len)) {
        report_fail("解密数据完整性校验失败", iter, dir);
        return false;
    }
    return true;
}

// ========================================================================
//  阶段 A：TLS 1.3 内存内完整握手 + 双向分块数据传输
// ========================================================================

void run_tls13_stress(const std::array<CertSet, 3>& sets, const Options& opt,
                      PhaseStats& stats, size_t& rss_baseline) {
    const size_t bytes_per_iter = 128 * 1024;
    const long long warmup = std::min(10LL, opt.iters);

    for (long long i = 0; i < opt.iters; ++i) {
        const CertSet& cs = sets[(size_t)i % sets.size()];
        double t0 = now_ms();
        bool ok = true;

        tls_session client, server;
        client.server_name = "localhost";
        std::vector<uint8_t> ch, sf, cf;

        if (!tls13_make_client_hello(client, ch)) {
            report_fail("TLS1.3 ClientHello 生成失败", i, cs.name);
            ok = false;
        }
        if (ok && !tls13_make_server_flight(server, ch.data(), ch.size(), sf, cs.mgr)) {
            report_fail("TLS1.3 ServerFlight 生成失败", i, cs.name);
            ok = false;
        }
        if (ok && !tls13_process_server_flight(client, sf.data(), sf.size(), cf, &cs.mgr)) {
            report_fail("TLS1.3 客户端处理 ServerFlight 失败", i, cs.name);
            ok = false;
        }
        if (ok && !tls13_process_client_finished(server, cf.data(), cf.size())) {
            report_fail("TLS1.3 服务端校验 ClientFinished 失败", i, cs.name);
            ok = false;
        }

        if (ok) {
            std::vector<uint8_t> payload(bytes_per_iter);
            fill_pattern(payload.data(), payload.size(), opt.seed, (uint64_t)i);
            if (!transfer_message(client, server, payload.data(), payload.size(), i, "client->server") ||
                !transfer_message(server, client, payload.data(), payload.size(), i, "server->client")) {
                ok = false;
            }
        }

        if (i == warmup) rss_baseline = current_rss_bytes();
        if (!opt.quiet && (i + 1) % std::max(1LL, opt.iters / 10) == 0) {
            std::printf("[tls13] iter %lld/%lld fail=%lld\n", i + 1, opt.iters, stats.fail);
            std::fflush(stdout);
        }
        stats.add(now_ms() - t0, ok, bytes_per_iter);
    }
}

// ========================================================================
//  阶段 B：TLS 1.2 (RSA) 内存内完整握手 + 记录层往返
// ========================================================================

void run_tls12_stress(const CertSet& rsa, const Options& opt, PhaseStats& stats) {
    const size_t bytes_per_iter = 64 * 1024;
    for (long long i = 0; i < opt.tls12_iters; ++i) {
        double t0 = now_ms();
        bool ok = true;

        tls_session client, server;
        client.server_name = "localhost";
        std::vector<uint8_t> ch;
        if (!tls12_make_client_hello(client, ch)) {
            report_fail("TLS1.2 ClientHello 生成失败", i, "rsa");
            ok = false;
        }

        uint8_t pre_master[48] = {};
        fill_pattern(pre_master, 48, opt.seed, (uint64_t)i);
        pre_master[0] = 0x03;
        pre_master[1] = 0x03;
        uint8_t encrypted_pms[256];
        const tls_certificate* cert = rsa.mgr.get_default_certificate();
        if (ok && cert) {
            rsa_encrypt(cert->pub.rsa,
                        jpssl::span<const uint8_t>(pre_master, 48), encrypted_pms);
        } else if (ok) {
            report_fail("TLS1.2 未找到 RSA 证书", i, "rsa");
            ok = false;
        }

        std::vector<uint8_t> server_resp;
        uint8_t decrypted_pms[48];
        if (ok && !tls12_make_server_flight(server, ch.data(), ch.size(), server_resp,
                                            encrypted_pms, sizeof(encrypted_pms),
                                            decrypted_pms, rsa.mgr)) {
            report_fail("TLS1.2 ServerFlight 生成失败", i, "rsa");
            ok = false;
        }
        if (ok && std::memcmp(pre_master, decrypted_pms, 48) != 0) {
            report_fail("TLS1.2 RSA 解密 pre_master 不一致", i, "rsa");
            ok = false;
        }

        std::vector<uint8_t> cf;
        if (ok && !tls12_process_server_flight(client, server_resp.data(), server_resp.size(),
                                               pre_master, 48, cf)) {
            report_fail("TLS1.2 客户端处理 ServerFlight 失败", i, "rsa");
            ok = false;
        }
        if (ok && !tls12_process_client_finished(server, cf.data(), cf.size())) {
            report_fail("TLS1.2 服务端校验 ClientFinished 失败", i, "rsa");
            ok = false;
        }

        if (ok) {
            std::vector<uint8_t> payload(bytes_per_iter);
            fill_pattern(payload.data(), payload.size(), opt.seed, (uint64_t)i * 3 + 1);
            if (!transfer_message(client, server, payload.data(), payload.size(), i, "tls12 c->s")) {
                ok = false;
            }
        }

        if (!opt.quiet && (i + 1) % std::max(1LL, opt.tls12_iters / 10) == 0) {
            std::printf("[tls12] iter %lld/%lld fail=%lld\n", i + 1, opt.tls12_iters, stats.fail);
            std::fflush(stdout);
        }
        stats.add(now_ms() - t0, ok, bytes_per_iter);
    }
}

// ========================================================================
//  阶段 C：TLS 1.3 NewSessionTicket + PSK 恢复 + 0-RTT early data
// ========================================================================

void copy_psk_state(const tls_session& src, tls_session& dst) {
    dst.psk_valid = src.psk_valid;
    dst.psk_identity_len = src.psk_identity_len;
    if (src.psk_identity_len) {
        std::memcpy(dst.psk_identity, src.psk_identity, src.psk_identity_len);
    }
    size_t hlen = tls_hash_len(src.cipher_suite);
    if (hlen) std::memcpy(dst.psk_value, src.psk_value, hlen);
    dst.ticket_age_add = src.ticket_age_add;
    dst.ticket_issue_time = src.ticket_issue_time;
    dst.cipher_suite = src.cipher_suite;
}

void run_psk_stress(const CertSet& ed, const Options& opt, PhaseStats& stats) {
    for (long long i = 0; i < opt.psk_iters; ++i) {
        double t0 = now_ms();
        bool ok = true;

        // 1) 完整握手
        tls_session client, server;
        client.server_name = "localhost";
        std::vector<uint8_t> ch, sf, cf;
        if (!tls13_make_client_hello(client, ch) ||
            !tls13_make_server_flight(server, ch.data(), ch.size(), sf, ed.mgr) ||
            !tls13_process_server_flight(client, sf.data(), sf.size(), cf, &ed.mgr) ||
            !tls13_process_client_finished(server, cf.data(), cf.size())) {
            report_fail("PSK 前置完整握手失败", i, "ed25519");
            ok = false;
        }

        // 2) NewSessionTicket + 客户端存储 PSK
        std::vector<uint8_t> ticket;
        if (ok && !tls13_make_new_session_ticket(server, ticket)) {
            report_fail("NewSessionTicket 生成失败", i, "");
            ok = false;
        }
        if (ok && !tls13_store_psk(client, ticket.data(), ticket.size())) {
            report_fail("客户端存储 PSK 失败", i, "");
            ok = false;
        }

        // 3) 复制 PSK 状态并恢复会话
        tls_session client2, server2;
        client2.server_name = "localhost";
        client2.cipher_suite = client.cipher_suite;
        copy_psk_state(client, client2);
        copy_psk_state(server, server2);
        server2.is_server = true;

        std::vector<uint8_t> psk_ch;
        if (ok && !tls13_make_psk_client_hello(client2, psk_ch)) {
            report_fail("PSK ClientHello 生成失败", i, "");
            ok = false;
        }
        bool accept_early = false;
        if (ok && !tls13_process_psk_client_hello(server2, psk_ch.data(), psk_ch.size(), accept_early)) {
            report_fail("服务端拒绝 PSK 会话", i, "");
            ok = false;
        }
        if (ok && !accept_early) {
            report_fail("服务端未接受 early data", i, "");
            ok = false;
        }

        // 4) 0-RTT early data 往返
        if (ok) {
            const char early_msg[] = "stability 0-RTT payload";
            auto early_enc = tls13_encrypt_early_data(client2, (const uint8_t*)early_msg,
                                                      sizeof(early_msg) - 1);
            ContentType early_ct;
            std::vector<uint8_t> early_dec;
            if (!tls13_decrypt_early_data(server2, early_enc.data(), early_enc.size(),
                                          early_ct, early_dec) ||
                early_dec.size() != sizeof(early_msg) - 1 ||
                std::memcmp(early_dec.data(), early_msg, sizeof(early_msg) - 1) != 0) {
                report_fail("0-RTT early data 往返失败", i, "");
                ok = false;
            }
        }

        // 5) EndOfEarlyData
        if (ok) {
            auto eoed = tls13_make_end_of_early_data();
            if (!tls13_process_end_of_early_data(client2, eoed.data(), eoed.size())) {
                report_fail("EndOfEarlyData 处理失败", i, "");
                ok = false;
            }
        }

        if (!opt.quiet && (i + 1) % std::max(1LL, opt.psk_iters / 10) == 0) {
            std::printf("[psk ] iter %lld/%lld fail=%lld\n", i + 1, opt.psk_iters, stats.fail);
            std::fflush(stdout);
        }
        stats.add(now_ms() - t0, ok, 0);
    }
}

// ========================================================================
//  阶段 D：socket 端到端握手 + 双向分块数据
// ========================================================================

// 返回值：0 = 成功；1 = 数据往返失败（可继续下一轮）；-1 = 连接失败（阶段终止）
int socket_echo_once(tls_listener& listener, const tls_certificate_manager& srv_mgr,
                     const tls_certificate_manager& cli_mgr, uint16_t port,
                     long long iter, uint64_t seed) {
    const size_t bytes = 64 * 1024;
    struct ServerResult {
        bool ok = false;
        std::string err;
    } srv;

    std::thread server_thread([&] {
        tls_connection conn;
        std::string e;
        if (!listener.accept(conn, srv_mgr, &e)) {
            srv.err = "accept: " + e;
            return;
        }
        // 接收 bytes 并原样回显
        size_t remaining = bytes;
        while (remaining > 0) {
            std::vector<uint8_t> recv_buf;
            if (!conn.recv(recv_buf, &e)) {
                srv.err = "server recv: " + e;
                return;
            }
            if (!conn.send(recv_buf.data(), recv_buf.size(), &e)) {
                srv.err = "server send: " + e;
                return;
            }
            remaining -= recv_buf.size();
        }
        conn.close();
        srv.ok = true;
    });

    bool ok = true;
    std::vector<uint8_t> payload(bytes);
    fill_pattern(payload.data(), payload.size(), seed, (uint64_t)iter);
    std::vector<uint8_t> echoed;
    echoed.reserve(bytes);

    tls_connection client;
    std::string err;
    if (!client.connect("127.0.0.1", port, &cli_mgr, &err)) {
        report_fail("socket 客户端连接/握手失败", iter, err.c_str());
        // 服务端线程仍阻塞在 accept，关闭 listener 使其返回并结束线程
        listener.close();
        server_thread.join();
        return -1;
    }

    if (ok) {
        for (size_t off = 0; off < bytes; off += RECORD_CHUNK) {
            size_t n = std::min(RECORD_CHUNK, bytes - off);
            if (!client.send(payload.data() + off, n, &err)) {
                report_fail("socket 客户端发送失败", iter, err.c_str());
                ok = false;
                break;
            }
            std::vector<uint8_t> resp;
            if (!client.recv(resp, &err)) {
                report_fail("socket 客户端接收失败", iter, err.c_str());
                ok = false;
                break;
            }
            if (resp.size() != n || fnv1a(resp.data(), resp.size()) != fnv1a(payload.data() + off, n)) {
                report_fail("socket 回显数据完整性校验失败", iter, "");
                ok = false;
                break;
            }
            echoed.insert(echoed.end(), resp.begin(), resp.end());
        }
    }
    if (client.is_open()) client.close();
    server_thread.join();

    if (ok && !srv.ok) {
        report_fail("socket 服务端失败", iter, srv.err.c_str());
        ok = false;
    }
    return ok ? 0 : 1;
}

void run_socket_stress(const CertSet& ed, const Options& opt, PhaseStats& stats) {
    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) {
        report_fail("socket listener 监听失败", -1, err.c_str());
        return;
    }
    uint16_t port = listener.local_port();
    if (port == 0) {
        report_fail("socket listener 未分配端口", -1, "");
        return;
    }

    for (long long i = 0; i < opt.socket_iters; ++i) {
        double t0 = now_ms();
        int rc = socket_echo_once(listener, ed.mgr, ed.mgr, port, i, opt.seed);
        if (!opt.quiet && (i + 1) % std::max(1LL, opt.socket_iters / 10) == 0) {
            std::printf("[sock] iter %lld/%lld fail=%lld\n", i + 1, opt.socket_iters, stats.fail);
            std::fflush(stdout);
        }
        stats.add(now_ms() - t0, rc == 0, 64 * 1024);
        if (rc < 0) break;  // 连接失败：listener 已关闭，终止 socket 阶段
    }
    listener.close();
}

// ========================================================================
//  阶段 E：并发 worker（每个 worker 独立 listener + 客户端循环）
// ========================================================================

long long run_concurrent_worker(const tls_certificate_manager& srv_mgr,
                                const tls_certificate_manager& cli_mgr,
                                long long iters, uint64_t seed) {
    long long local_fail = 0;
    std::atomic<bool> abort{false};
    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) {
        report_fail("并发 worker listener 失败", -1, err.c_str());
        return 1;
    }
    uint16_t port = listener.local_port();

    std::thread server_thread([&] {
        for (long long i = 0; i < iters; ++i) {
            tls_connection conn;
            std::string e;
            if (!listener.accept(conn, srv_mgr, &e)) {
                if (!abort.load()) report_fail("并发 accept 失败", i, e.c_str());
                return;
            }
            std::vector<uint8_t> recv_buf;
            if (conn.recv(recv_buf, &e) && conn.send(recv_buf.data(), recv_buf.size(), &e)) {
                conn.close();
            } else {
                report_fail("并发服务端收发失败", i, e.c_str());
            }
        }
    });

    for (long long i = 0; i < iters; ++i) {
        std::vector<uint8_t> payload(RECORD_CHUNK);
        fill_pattern(payload.data(), payload.size(), seed, (uint64_t)(port) * 1000003 + (uint64_t)i);
        tls_connection client;
        std::string e;
        if (!client.connect("127.0.0.1", port, &cli_mgr, &e)) {
            report_fail("并发客户端连接失败", i, e.c_str());
            ++local_fail;
            abort.store(true);
            break;
        }
        bool send_ok = client.send(payload.data(), payload.size(), &e);
        std::vector<uint8_t> resp;
        bool recv_ok = send_ok && client.recv(resp, &e);
        client.close();
        if (!send_ok || !recv_ok ||
            resp.size() != payload.size() ||
            fnv1a(resp.data(), resp.size()) != fnv1a(payload.data(), payload.size())) {
            report_fail("并发数据往返失败", i, e.c_str());
            ++local_fail;
        }
    }

    listener.close();  // 若客户端提前退出，解除服务端线程在 accept 上的阻塞
    server_thread.join();
    return local_fail;
}

// ========================================================================
//  命令行 / 环境变量
// ========================================================================

long long get_env_ll(const char* name, long long dflt) {
    const char* v = std::getenv(name);
    if (!v || !*v) return dflt;
    return atoll(v);
}

void print_usage(const char* prog) {
    std::printf(
        "用法: %s [选项]\n"
        "  --iters N            TLS 1.3 内存握手轮数 (默认 150)\n"
        "  --tls12-iters N      TLS 1.2 内存握手轮数 (默认 50)\n"
        "  --psk-iters N        PSK/0-RTT 恢复轮数 (默认 30)\n"
        "  --socket-iters N     socket 握手轮数 (默认 20)\n"
        "  --threads N          并发 worker 数 (默认 1 = 关闭并发阶段)\n"
        "  --leak-mb N          内存增长失败阈值 MiB (默认 128, 0 = 关闭)\n"
        "  --seed N             确定性数据种子\n"
        "  --quiet              仅输出摘要\n"
        "  --help               显示本帮助\n"
        "环境变量: JPSSL_STRESS_ITERS / JPSSL_STRESS_TLS12_ITERS / JPSSL_STRESS_PSK_ITERS /\n"
        "          JPSSL_STRESS_SOCKET_ITERS / JPSSL_STRESS_THREADS / JPSSL_STRESS_LEAK_MB\n",
        prog);
}

bool parse_args(int argc, char** argv, Options& opt) {
    opt.iters = get_env_ll("JPSSL_STRESS_ITERS", opt.iters);
    opt.tls12_iters = get_env_ll("JPSSL_STRESS_TLS12_ITERS", opt.tls12_iters);
    opt.psk_iters = get_env_ll("JPSSL_STRESS_PSK_ITERS", opt.psk_iters);
    opt.socket_iters = get_env_ll("JPSSL_STRESS_SOCKET_ITERS", opt.socket_iters);
    {
        long long t = get_env_ll("JPSSL_STRESS_THREADS", opt.threads);
        opt.threads = (int)t;
    }
    {
        long long m = get_env_ll("JPSSL_STRESS_LEAK_MB", (long long)opt.leak_threshold_mb);
        opt.leak_threshold_mb = m > 0 ? (size_t)m : 0;
    }

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto num_arg = [&](const char* flag, long long& out) -> bool {
            std::string f = flag;
            if (a == f && i + 1 < argc) { out = atoll(argv[++i]); return true; }
            if (a.rfind(f + "=", 0) == 0) { out = atoll(a.c_str() + f.size() + 1); return true; }
            return false;
        };
        if (num_arg("--iters", opt.iters)) continue;
        if (num_arg("--tls12-iters", opt.tls12_iters)) continue;
        if (num_arg("--psk-iters", opt.psk_iters)) continue;
        if (num_arg("--socket-iters", opt.socket_iters)) continue;
        long long tmp;
        if (num_arg("--threads", tmp)) { opt.threads = (int)tmp; continue; }
        if (num_arg("--leak-mb", tmp)) {
            opt.leak_threshold_mb = tmp > 0 ? (size_t)tmp : 0;
            continue;
        }
        if (num_arg("--seed", (long long&)opt.seed)) continue;
        if (a == "--quiet") { opt.quiet = true; continue; }
        if (a == "--help") { print_usage(argv[0]); return false; }
        std::fprintf(stderr, "未知参数: %s (--help 查看用法)\n", a.c_str());
        return false;
    }
    return true;
}

} // namespace

// ========================================================================
//  入口
// ========================================================================

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) return 2;

    std::string init_err;
    if (!tls_socket_init(&init_err)) {
        std::fprintf(stderr, "tls_socket_init 失败: %s\n", init_err.c_str());
        return 1;
    }

    const size_t rss_start = current_rss_bytes();
    size_t rss_baseline = rss_start;
    size_t rss_peak = rss_start;

    if (!opt.quiet) {
        std::printf("=== jpssl TLS stability test ===\n");
        std::printf("  tls13=%lld tls12=%lld psk=%lld socket=%lld threads=%d leak_mb=%llu seed=0x%llx\n",
                    opt.iters, opt.tls12_iters, opt.psk_iters, opt.socket_iters,
                    opt.threads, (unsigned long long)opt.leak_threshold_mb,
                    (unsigned long long)opt.seed);
        std::fflush(stdout);
    }

    auto cert_sets = build_cert_sets();
    if (!opt.quiet) {
        std::printf("[phase] cert sets ready\n");
        std::fflush(stdout);
    }

    PhaseStats stats_tls13;
    run_tls13_stress(cert_sets, opt, stats_tls13, rss_baseline);
    stats_tls13.print("TLS 1.3 in-memory handshake (Ed25519/ECDSA/RSA)", opt.quiet);
    if (!opt.quiet) {
        std::printf("[phase] tls13 done\n");
        std::fflush(stdout);
    }
    rss_peak = std::max(rss_peak, current_rss_bytes());

    const CertSet* rsa_set = nullptr;
    for (const auto& cs : cert_sets) {
        if (std::strcmp(cs.name, "RSA-2048") == 0) rsa_set = &cs;
    }
    PhaseStats stats_tls12;
    if (rsa_set) run_tls12_stress(*rsa_set, opt, stats_tls12);
    stats_tls12.print("TLS 1.2 in-memory handshake (RSA)", opt.quiet);
    if (!opt.quiet) {
        std::printf("[phase] tls12 done\n");
        std::fflush(stdout);
    }
    rss_peak = std::max(rss_peak, current_rss_bytes());

    PhaseStats stats_psk;
    run_psk_stress(cert_sets[0], opt, stats_psk);
    stats_psk.print("TLS 1.3 PSK resume / 0-RTT", opt.quiet);
    if (!opt.quiet) {
        std::printf("[phase] psk done\n");
        std::fflush(stdout);
    }
    rss_peak = std::max(rss_peak, current_rss_bytes());

    PhaseStats stats_socket;
    run_socket_stress(cert_sets[0], opt, stats_socket);
    stats_socket.print("TLS-over-TCP socket handshake + echo", opt.quiet);
    if (!opt.quiet) {
        std::printf("[phase] socket done\n");
        std::fflush(stdout);
    }
    rss_peak = std::max(rss_peak, current_rss_bytes());

    if (opt.threads > 1) {
        double t0 = now_ms();
        long long worker_fails = 0;
        std::vector<std::thread> workers;
        for (int w = 0; w < opt.threads; ++w) {
            workers.emplace_back([&, w] {
                worker_fails += run_concurrent_worker(cert_sets[0].mgr, cert_sets[0].mgr,
                                                      opt.socket_iters, opt.seed + (uint64_t)w * 0x9E37);
            });
        }
        for (auto& t : workers) t.join();
        PhaseStats cs;
        cs.iters = opt.socket_iters * opt.threads;
        cs.total_ms = now_ms() - t0;
        cs.ok = cs.iters - worker_fails;
        cs.fail = worker_fails;
        cs.print("Concurrent TLS handshake workers", opt.quiet);
        if (worker_fails > 0) g_failures.fetch_add(worker_fails);
        rss_peak = std::max(rss_peak, current_rss_bytes());
    }

    const size_t rss_end = current_rss_bytes();
    const long long growth_mb =
        (long long)((rss_end > rss_baseline ? rss_end - rss_baseline : 0) / (1024 * 1024));
    if (opt.leak_threshold_mb > 0 && (size_t)growth_mb > opt.leak_threshold_mb) {
        report_fail("检测到进程内存持续增长，疑似泄漏", -1,
                    (std::to_string(growth_mb) + " MiB > 阈值 " +
                     std::to_string(opt.leak_threshold_mb) + " MiB").c_str());
    }
    if (!opt.quiet) {
        std::printf("--- memory ---\n");
        std::printf("    start=%lluMiB baseline=%lluMiB end=%lluMiB peak=%lluMiB growth=%lldMiB\n",
                    (unsigned long long)(rss_start / (1024 * 1024)),
                    (unsigned long long)(rss_baseline / (1024 * 1024)),
                    (unsigned long long)(rss_end / (1024 * 1024)),
                    (unsigned long long)(rss_peak / (1024 * 1024)), growth_mb);
    }

    const long long fails = g_failures.load();
    std::printf("================================================\n");
    std::printf("  TLS stability result: %s (%lld failure%s)\n",
                fails == 0 ? "OK" : "FAILED", fails, fails == 1 ? "" : "s");
    std::printf("================================================\n");
    return fails == 0 ? 0 : 1;
}
