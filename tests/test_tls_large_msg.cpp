/**
 * test_tls_large_msg.cpp -- TLS 大消息自动分片 / 合并测试
 *
 * 覆盖：
 *   1. 内存内 TLS 1.3：>16KiB 明文自动拆分为多条 record，
 *      tls_decrypt 一次调用自动合并还原（边界 16384 / 16385 / 65535 /
 *      65536 / 256KiB）；
 *   2. 内存内 TLS 1.2 (RSA)：同样验证分片与合并；
 *   3. socket 端到端：一次 send(128KiB) 自动分片，对端一次 recv() 合并还原，
 *      回显后再合并回客户端。
 *
 * 每条 record 明文上限 TLS_MAX_RECORD_PLAINTEXT = 16384（RFC 5246/8446）。
 */

#include "tls.hpp"
#include "tls_socket.hpp"
#include "ed25519.hpp"
#include "rsa.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; std::exit(1); } \
} while (0)

static uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void fill_pattern(uint8_t* p, size_t n, uint64_t seed, uint64_t offset) {
    uint64_t x = seed ^ (offset * 0x9E3779B97F4A7C15ULL);
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        p[i] = (uint8_t)(x >> 32);
    }
}

// 统计字节流中的完整 record 数（0 表示不是完整的 record 流）
static size_t count_records(const std::vector<uint8_t>& buf) {
    size_t n = 0, off = 0;
    while (off < buf.size()) {
        if (buf.size() - off < 5) return 0;
        size_t rlen = ((size_t)buf[off + 3] << 8) | buf[off + 4];
        if (off + 5 + rlen > buf.size()) return 0;
        ++n;
        off += 5 + rlen;
    }
    return n;
}

static std::unique_ptr<tls_certificate> make_ed25519_cert() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);
    return cert;
}

// ========================================================================
//  1) TLS 1.3 内存内大消息分片 + 合并
// ========================================================================

static void test_tls13_large_messages() {
    std::printf("\n=== TLS 1.3 in-memory large message (split+merge) ===\n");

    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", make_ed25519_cert());

    tls_session client, server;
    client.server_name = "localhost";
    std::vector<uint8_t> ch, sf, cf;
    TEST("TLS1.3 ClientHello", tls13_make_client_hello(client, ch));
    TEST("TLS1.3 ServerFlight",
         tls13_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr));
    TEST("TLS1.3 client process server flight",
         tls13_process_server_flight(client, sf.data(), sf.size(), cf, &cert_mgr));
    TEST("TLS1.3 server verify finished",
         tls13_process_client_finished(server, cf.data(), cf.size()));

    const size_t sizes[] = { 16384, 16385, 65535, 65536, 262144 };
    const char* size_names[] = { "16KiB exact", "16KiB+1", "64KiB-1",
                                 "64KiB (16-bit 长度边界)", "256KiB" };

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        size_t len = sizes[s];
        std::vector<uint8_t> payload(len);
        fill_pattern(payload.data(), payload.size(), 0x1122334455667788ULL, (uint64_t)s);

        std::vector<uint8_t> wire = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                                payload.data(), payload.size());
        TEST("encrypt 非空", !wire.empty());

        size_t expected_records = (len + TLS_MAX_RECORD_PLAINTEXT - 1) / TLS_MAX_RECORD_PLAINTEXT;
        char msg[128];
        std::snprintf(msg, sizeof(msg), "%s: 拆分为 %zu 条 record", size_names[s], expected_records);
        TEST(msg, count_records(wire) == expected_records);

        ContentType ct;
        std::vector<uint8_t> plain;
        bool dec_ok = tls_decrypt(server, wire.data(), wire.size(), ct, plain);
        TEST("decrypt 合并成功", dec_ok);
        if (dec_ok) {
            std::snprintf(msg, sizeof(msg), "%s: 合并后长度一致 (%zu)", size_names[s], len);
            TEST(msg, ct == ContentType::APPLICATION_DATA && plain.size() == len);
            std::snprintf(msg, sizeof(msg), "%s: 合并内容完整", size_names[s]);
            TEST(msg, fnv1a(plain.data(), plain.size()) == fnv1a(payload.data(), payload.size()));
        }
    }
}

// ========================================================================
//  2) TLS 1.2 内存内大消息分片 + 合并
// ========================================================================

static void test_tls12_large_message() {
    std::printf("\n=== TLS 1.2 in-memory large message (split+merge) ===\n");

    tls_certificate_manager cert_mgr;
    auto cert = make_ed25519_cert();
    cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    rsa_keygen(cert->pub.rsa, cert->priv.rsa);
    cert_mgr.add_certificate("localhost", std::move(cert));

    tls_session client, server;
    client.server_name = "localhost";
    std::vector<uint8_t> ch;
    TEST("TLS1.2 ClientHello", tls12_make_client_hello(client, ch));

    uint8_t pre_master[48] = {};
    pre_master[0] = 0x03;
    pre_master[1] = 0x03;
    uint8_t encrypted_pms[256];
    const tls_certificate* cert_ptr = cert_mgr.get_default_certificate();
    TEST("TLS1.2 RSA 证书存在", cert_ptr != nullptr);
    rsa_encrypt(cert_ptr->pub.rsa, std::span<const uint8_t>(pre_master, 48), encrypted_pms);

    std::vector<uint8_t> server_resp;
    uint8_t decrypted_pms[48];
    TEST("TLS1.2 ServerFlight",
         tls12_make_server_flight(server, ch.data(), ch.size(), server_resp,
                                  encrypted_pms, sizeof(encrypted_pms), decrypted_pms, cert_mgr));
    TEST("TLS1.2 RSA pre_master 一致", std::memcmp(pre_master, decrypted_pms, 48) == 0);

    std::vector<uint8_t> cf;
    TEST("TLS1.2 client process server flight",
         tls12_process_server_flight(client, server_resp.data(), server_resp.size(),
                                     pre_master, 48, cf));
    TEST("TLS1.2 server verify finished",
         tls12_process_client_finished(server, cf.data(), cf.size()));

    const size_t len = 100 * 1024;
    std::vector<uint8_t> payload(len);
    fill_pattern(payload.data(), payload.size(), 0xDEADBEEFCAFEF00DULL, 1);

    std::vector<uint8_t> wire = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                            payload.data(), payload.size());
    size_t expected_records = (len + TLS_MAX_RECORD_PLAINTEXT - 1) / TLS_MAX_RECORD_PLAINTEXT;
    TEST("TLS1.2 100KiB 拆分为 7 条 record", count_records(wire) == expected_records);

    ContentType ct;
    std::vector<uint8_t> plain;
    TEST("TLS1.2 decrypt 合并成功", tls_decrypt(server, wire.data(), wire.size(), ct, plain));
    TEST("TLS1.2 合并长度一致", ct == ContentType::APPLICATION_DATA && plain.size() == len);
    TEST("TLS1.2 合并内容完整", fnv1a(plain.data(), plain.size()) == fnv1a(payload.data(), payload.size()));
}

// ========================================================================
//  3) socket 端到端：一次 send(128KiB) 自动分片，对端一次 recv() 合并
// ========================================================================

static void test_socket_large_message() {
    std::printf("\n=== TLS socket large message (128KiB, one send / one recv) ===\n");

    uint8_t pub[32], priv[64];  // Ed25519 私钥 64 字节（seed + 扩展）
    ed25519_keygen(pub, priv);
    tls_certificate_manager server_mgr, client_mgr;

    auto sc = make_ed25519_cert();
    std::memcpy(sc->pub.ed25519, pub, 32);
    std::memcpy(sc->priv.ed25519, priv, 64);
    auto cc = make_ed25519_cert();
    std::memcpy(cc->pub.ed25519, pub, 32);
    std::memcpy(cc->priv.ed25519, priv, 64);
    server_mgr.add_certificate("localhost", std::move(sc));
    client_mgr.add_certificate("localhost", std::move(cc));

    tls_listener listener;
    std::string err;
    TEST("listener listen", listener.listen(0, "127.0.0.1", &err));
    uint16_t port = listener.local_port();
    TEST("listener port assigned", port != 0);

    const size_t len = 128 * 1024;
    struct ServerResult {
        bool ok = false;
        size_t recv_calls = 0;
        std::string recv_err;
    } srv;

    std::thread server_thread([&] {
        tls_connection conn;
        std::string e;
        if (!listener.accept(conn, server_mgr, &e)) {
            srv.recv_err = "accept: " + e;
            return;
        }
        // 合并接收完整 128KiB
        std::vector<uint8_t> all;
        while (all.size() < len) {
            std::vector<uint8_t> chunk;
            if (!conn.recv(chunk, &e)) {
                srv.recv_err = "server recv: " + e;
                return;
            }
            ++srv.recv_calls;
            all.insert(all.end(), chunk.begin(), chunk.end());
        }
        if (all.size() != len) {
            srv.recv_err = "server received size mismatch";
            return;
        }
        // 完整性由客户端最终校验，这里原样回显
        if (!conn.send(all.data(), all.size(), &e)) {
            srv.recv_err = "server send: " + e;
            return;
        }
        conn.close();
        srv.ok = true;
    });

    std::vector<uint8_t> payload(len);
    fill_pattern(payload.data(), payload.size(), 0x0123456789ABCDEFULL, 7);

    tls_connection client;
    bool connected = client.connect("127.0.0.1", port, &server_mgr, &err);
    if (!connected) std::fprintf(stderr, "  connect err: %s\n", err.c_str());
    TEST("client connect+handshake", connected);
    TEST("client send 128KiB (自动分片)", client.send(payload.data(), payload.size(), &err));

    // 合并接收回显的完整 128KiB
    size_t recv_calls = 0;
    std::vector<uint8_t> echoed;
    while (echoed.size() < payload.size()) {
        std::vector<uint8_t> chunk;
        TEST("client recv echo", client.recv(chunk, &err));
        ++recv_calls;
        echoed.insert(echoed.end(), chunk.begin(), chunk.end());
    }
    client.close();
    server_thread.join();

    TEST("server ok", srv.ok);
    if (!srv.ok) std::fprintf(stderr, "  server error: %s\n", srv.recv_err.c_str());
    TEST("server 一次 recv() 合并 128KiB", srv.recv_calls == 1);
    TEST("client 一次 recv() 合并 128KiB", recv_calls == 1);
    TEST("回显内容完整", fnv1a(echoed.data(), echoed.size()) == fnv1a(payload.data(), payload.size()));
    listener.close();
}

// ========================================================================
//  入口
// ========================================================================

int main() {
    std::string err;
    TEST("socket init", tls_socket_init(&err));

    test_tls13_large_messages();
    test_tls12_large_message();
    test_socket_large_message();

    std::printf("\n================================================\n");
    std::printf("  Result: %d passed, %d failed", pass, fail);
    std::printf(fail == 0 ? " OK\n" : " FAILED\n");
    std::printf("================================================\n");
    return fail > 0 ? 1 : 0;
}
