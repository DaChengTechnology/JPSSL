/**
 * test_dtls_wolfssl_interop.cpp - jpssl DTLS 1.2/1.3 <-> wolfSSL DTLS 1.2/1.3 互操作合规性测试
 *
 *   方向 A：jpssl DTLS 服务器 <-> wolfSSL DTLS 客户端（wolfSSL 校验 jpssl 证书链）
 *   方向 B：wolfSSL DTLS 服务器 <-> jpssl DTLS 客户端（jpssl 校验 wolfSSL 证书链）
 *
 *   DTLS 1.2（RFC 6347）：ECDHE-ECDSA-AES128-GCM-SHA256 / ECDHE-ECDSA-CHACHA20-POLY1305
 *   DTLS 1.3（RFC 9147）：TLS_AES_128_GCM_SHA256 / TLS_CHACHA20_POLY1305_SHA256
 *
 *   每个方向断言：握手成功、协商套件与目标一致、双向应用数据一致。
 *   需要 wolfSSL 构建产物（JP_WOLFSSL_PREFIX）与测试证书目录（JP_WOLFSSL_CERT_DIR），
 *   由 tests/CMakeLists.txt 传入编译定义。
 */
#include "test_utils.hpp"
#include "dtls.hpp"
#include "ecdsa.hpp"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include "jpssl_memory.hpp"
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#endif

using namespace jpssl;
using namespace jpssl::dtls;
using namespace jpssl::tls;

// ============================================================
//  平台 socket 适配
// ============================================================

#ifdef _WIN32
using jp_sock_t = SOCKET;
static void sock_close(jp_sock_t fd) { closesocket(fd); }
#else
using jp_sock_t = int;
static void sock_close(jp_sock_t fd) { ::close(fd); }
#endif

static void set_socket_timeouts(jp_sock_t fd, int seconds = 8) {
    timeval tv{};
    tv.tv_sec = seconds; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, (int)sizeof(tv));
}

// ============================================================
//  文件 / 错误辅助
// ============================================================

static bool read_file(const char* path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return !out.empty();
}

static std::string wolf_err_code(int e) {
    char buf[256];
    wolfSSL_ERR_error_string_n((unsigned long)e, buf, sizeof(buf));
    return std::string(buf);
}

// ============================================================
//  证书辅助
// ============================================================

// jpssl 服务器自签证书（ECDSA P-256，CN/SAN=dtls.test，CA=true）
static tls_certificate_manager make_jpssl_cert_mgr(const char* dns) {
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    x509::x509_builder b;
    x509::DistinguishedName dn;
    dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), dns});
    b.set_subject(dn).set_issuer(dn);
    uint8_t ser[8] = {0x52, 0x52, 0x52, 0x52};
    b.set_serial(ser, 8);
    uint64_t now = (uint64_t)time(nullptr);
    b.set_validity(now - 3600, now + 365 * 86400);
    b.set_key(x509::KeyType::ECDSA_P256, pub, 64);
    b.set_ca(true);
    b.add_san_dns(dns);
    auto der = b.build_and_sign(x509::KeyType::ECDSA_P256, priv, 32);

    tls_certificate_manager mgr;
    auto cert = jpssl::make_unique<tls_certificate>();
    cert->subject_name = dns;
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    memcpy(cert->pub.ecdsa_p256, pub, 64);
    memcpy(cert->priv.ecdsa_p256, priv, 32);
    cert->cert_data = der.to_der();
    mgr.add_certificate(dns, std::move(cert));
    return mgr;
}

// wolfSSL 测试证书路径（编译期由 CMake 注入）
#ifndef JP_WOLFSSL_CERT_DIR
#define JP_WOLFSSL_CERT_DIR ""
#endif

static std::string wolfssl_cert_path(const char* name) {
    std::string p = JP_WOLFSSL_CERT_DIR;
    if (!p.empty() && p.back() != '/' && p.back() != '\\') p += "/";
    p += name;
    return p;
}

// ============================================================
//  wolfSSL 读写（处理 WANT_READ/WANT_WRITE）
// ============================================================

static bool wolf_read_full(WOLFSSL* ssl, uint8_t* buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        int n = wolfSSL_read(ssl, buf + got, (int)(want - got));
        if (n <= 0) {
            int e = wolfSSL_get_error(ssl, n);
            if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        got += (size_t)n;
    }
    return true;
}

static bool wolf_write_all(WOLFSSL* ssl, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = wolfSSL_write(ssl, data + sent, (int)(len - sent));
        if (n <= 0) {
            int e = wolfSSL_get_error(ssl, n);
            if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

// ============================================================
//  方向 A：jpssl DTLS 服务器 <-> wolfSSL DTLS 客户端
// ============================================================

static bool dtls_jpssl_server_wolf_client(DTLSVersion ver, CipherSuite cs,
                                          const char* w_name, std::string& why) {
    auto cert_mgr = make_jpssl_cert_mgr("dtls.test");

    dtls_connection srv;
    srv.set_version(ver);
    srv.set_cipher_suite(cs);
    if (ver == DTLSVersion::V12) srv.set_key_share_group(NamedGroup::secp256r1);
    if (!srv.bind(0, "127.0.0.1")) { why = "jpssl bind failed"; return false; }
    uint16_t port = srv.local_port();

    std::atomic<bool> srv_ok{false};
    std::string srv_err;
    std::thread srv_th([&] {
        if (!srv.server_handshake(cert_mgr)) {
            srv_err = "server_handshake failed: " + srv.last_error();
            return;
        }
        std::vector<uint8_t> buf;
        if (!srv.recv(buf)) { srv_err = "server recv failed"; return; }
        static const char ping[] = "ping";
        if (buf.size() != sizeof(ping) - 1 ||
            std::memcmp(buf.data(), ping, sizeof(ping) - 1) != 0) {
            srv_err = "server recv mismatch";
            return;
        }
        static const char pong[] = "pong-from-jpssl";
        if (!srv.send((const uint8_t*)pong, sizeof(pong) - 1)) {
            srv_err = "server send failed";
            return;
        }
        srv_ok = true;
    });

    WOLFSSL_METHOD* m = (ver == DTLSVersion::V13)
        ? wolfDTLSv1_3_client_method() : wolfDTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(m);
    if (!ctx) { why = "wolfSSL_CTX_new failed"; srv_th.join(); return false; }
    if (wolfSSL_CTX_set_cipher_list(ctx, w_name) != WOLFSSL_SUCCESS) {
        why = std::string("wolfSSL_CTX_set_cipher_list failed: ") + w_name;
        wolfSSL_CTX_free(ctx); srv_th.join(); return false;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, nullptr);
    const tls_certificate* jc = cert_mgr.get_default_certificate();
    if (!jc || jc->cert_data.empty() ||
        wolfSSL_CTX_load_verify_buffer(ctx, jc->cert_data.data(),
                                       (long)jc->cert_data.size(),
                                       WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        why = "failed to add jpssl cert to wolfSSL store";
        wolfSSL_CTX_free(ctx); srv_th.join(); return false;
    }

    jp_sock_t fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == (jp_sock_t)-1) { why = "socket failed"; wolfSSL_CTX_free(ctx); srv_th.join(); return false; }
    set_socket_timeouts(fd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        why = "connect failed"; sock_close(fd); wolfSSL_CTX_free(ctx); srv_th.join(); return false;
    }

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) { why = "wolfSSL_new failed"; sock_close(fd); wolfSSL_CTX_free(ctx); srv_th.join(); return false; }
    wolfSSL_set_fd(ssl, (int)fd);

    bool ok = false;
    int cr = wolfSSL_connect(ssl);
    if (cr == WOLFSSL_SUCCESS) {
        const char* got = wolfSSL_get_cipher_name(ssl);
        ok = got && std::strcmp(got, w_name) == 0;
        if (!ok) why = std::string("wolfSSL client negotiated wrong suite: ") + (got ? got : "(null)");
        static const char ping[] = "ping";
        static const char pong[] = "pong-from-jpssl";
        uint8_t rbuf[64] = {0};
        ok = ok && wolf_write_all(ssl, (const uint8_t*)ping, sizeof(ping) - 1);
        ok = ok && wolf_read_full(ssl, rbuf, sizeof(pong) - 1) &&
             std::memcmp(rbuf, pong, sizeof(pong) - 1) == 0;
        if (!ok && why.empty()) why = "wolfSSL client data exchange failed";
    } else {
        int e = wolfSSL_get_error(ssl, cr);
        why = "wolfSSL_connect failed: " + wolf_err_code(e) +
              " (code " + std::to_string(e) + ") srv_err=" + srv_err;
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    sock_close(fd);
    srv_th.join();

    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "jpssl server failed" : srv_err; }
    return ok;
}

// ============================================================
//  方向 B：wolfSSL DTLS 服务器 <-> jpssl DTLS 客户端
// ============================================================

static bool dtls_wolf_server_jpssl_client(DTLSVersion ver, CipherSuite cs,
                                          const char* w_name, std::string& why) {
    // 与方向 A 一致使用 ECDSA 套件，故服务器证书用 ECDSA 的 server-ecc.pem /
    // ecc-key.pem（默认 server-cert.pem 是 RSA，会与 ECDSA 套件不匹配），
    // 信任锚用签它的 ca-ecc-cert.pem。
    std::string cert_path = wolfssl_cert_path("server-ecc.pem");
    std::string key_path  = wolfssl_cert_path("ecc-key.pem");
    std::string ca_path   = wolfssl_cert_path("ca-ecc-cert.pem");

    WOLFSSL_METHOD* m = (ver == DTLSVersion::V13)
        ? wolfDTLSv1_3_server_method() : wolfDTLSv1_2_server_method();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(m);
    if (!ctx) { why = "wolfSSL_CTX_new failed"; return false; }
    // RFC 6347 允许服务器跳过 HelloVerifyRequest cookie 交换（OpenSSL 互通测试同策略）
    wolfSSL_CTX_clear_options(ctx, WOLFSSL_OP_COOKIE_EXCHANGE);
    if (wolfSSL_CTX_set_cipher_list(ctx, w_name) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_certificate_file(ctx, cert_path.c_str(), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        why = "wolfSSL server ctx/cert setup failed: " + cert_path;
        wolfSSL_CTX_free(ctx); return false;
    }

    jp_sock_t lfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (lfd == (jp_sock_t)-1) { why = "socket failed"; wolfSSL_CTX_free(ctx); return false; }
    set_socket_timeouts(lfd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::bind(lfd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        why = "bind failed"; sock_close(lfd); wolfSSL_CTX_free(ctx); return false;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (sockaddr*)&addr, &alen);
    uint16_t port = ntohs(addr.sin_port);

    std::atomic<bool> srv_ok{false};
    std::string srv_err;
    std::thread srv_th([&] {
        WOLFSSL* ssl = wolfSSL_new(ctx);
        if (!ssl) { srv_err = "wolfSSL_new failed"; return; }
        // RFC 9147 允许服务器跳过 HRR cookie 验证（与 DTLS 1.2 关 cookie 同策略），
        // 否则 wolfSSL 服务器默认对 DTLS 1.3 发 HRR+cookie，而 jpssl 客户端暂不支持 HRR。
        if (ver == DTLSVersion::V13) wolfSSL_disable_hrr_cookie(ssl);
        wolfSSL_set_fd(ssl, (int)lfd);
        int ar = wolfSSL_accept(ssl);
        if (ar == WOLFSSL_SUCCESS) {
            const char* got = wolfSSL_get_cipher_name(ssl);
            static const char ping[] = "ping";
            static const char pong[] = "pong-from-wolf";
            uint8_t rbuf[64] = {0};
            if (got && std::strcmp(got, w_name) == 0 &&
                wolf_read_full(ssl, rbuf, sizeof(ping) - 1) &&
                std::memcmp(rbuf, ping, sizeof(ping) - 1) == 0 &&
                wolf_write_all(ssl, (const uint8_t*)pong, sizeof(pong) - 1)) {
                srv_ok = true;
            } else {
                srv_err = std::string("wolfSSL server exchange failed, suite=") +
                          (got ? got : "(null)");
            }
        } else {
            int e = wolfSSL_get_error(ssl, ar);
            srv_err = "wolfSSL_accept failed: " + wolf_err_code(e) +
                      " (code " + std::to_string(e) + ")";
        }
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    });

    std::vector<uint8_t> ca;
    if (!read_file(ca_path.c_str(), ca)) {
        why = "read ca-cert.pem failed: " + ca_path;
        srv_th.join(); sock_close(lfd); wolfSSL_CTX_free(ctx); return false;
    }
    std::string pem((const char*)ca.data(), ca.size());
    tls_trust_store trust = tls_trust_store::from_pem(pem);

    dtls_connection cli;
    cli.set_version(ver);
    cli.set_server_name("www.wolfssl.com");
    cli.set_cipher_suite(cs);

    bool ok = false;
    if (cli.connect("127.0.0.1", port, &trust)) {
        ok = cli.session().cipher_suite == cs;
        static const char ping[] = "ping";
        static const char pong[] = "pong-from-wolf";
        std::vector<uint8_t> buf;
        ok = ok && cli.send((const uint8_t*)ping, sizeof(ping) - 1) &&
             cli.recv(buf) &&
             buf.size() == sizeof(pong) - 1 &&
             std::memcmp(buf.data(), pong, sizeof(pong) - 1) == 0;
        if (!ok) why = "jpssl client data exchange failed";
    } else {
        why = "jpssl client connect failed: " + cli.last_error();
    }

    srv_th.join();
    sock_close(lfd);
    wolfSSL_CTX_free(ctx);

    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "wolfSSL server failed" : srv_err; }
    if (!ok && !srv_err.empty()) why += " srv_err=" + srv_err;
    return ok;
}

// ============================================================
//  测试入口
// ============================================================

struct dtls_wolf_case {
    DTLSVersion ver;
    CipherSuite cs;
    const char* w_name;
    const char* label;
};

static const dtls_wolf_case kWolfCases[] = {
    { DTLSVersion::V12, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-ECDSA-AES128-GCM-SHA256", "DTLS 1.2 AES128-GCM" },
    { DTLSVersion::V12, CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-ECDSA-CHACHA20-POLY1305", "DTLS 1.2 CHACHA20-POLY1305" },
    { DTLSVersion::V13, CipherSuite::TLS_AES_128_GCM_SHA256,
      "TLS13-AES128-GCM-SHA256", "DTLS 1.3 AES128-GCM" },
    { DTLSVersion::V13, CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
      "TLS13-CHACHA20-POLY1305-SHA256", "DTLS 1.3 CHACHA20-POLY1305" },
};

void test_dtls_wolfssl_interop() {
#ifdef LIBWOLFSSL_VERSION_STRING
    std::printf("\n=== DTLS 1.2/1.3 套件 x wolfSSL %s 互操作 ===\n", LIBWOLFSSL_VERSION_STRING);
#else
    std::printf("\n=== DTLS 1.2/1.3 套件 x wolfSSL 互操作 ===\n");
#endif
    // 调试用：设置环境变量 WOLF_CASE=<n> 只跑第 n 个方向（0..7），便于逐用例抓包
    int only_case = -1;
    if (const char* oc = std::getenv("WOLF_CASE")) only_case = std::atoi(oc);
    int pass = 0, fail = 0;
    int idx = 0;
    for (const auto& e : kWolfCases) {
        {
            if (only_case >= 0 && only_case != idx) { ++idx; }
            else {
            std::string why;
            bool r = dtls_jpssl_server_wolf_client(e.ver, e.cs, e.w_name, why);
            std::string tag = std::string("A jpssl-server <-> wolfssl-client ") + e.label;
            if (r) { ++pass; std::cout << "  \xE2\x9C\x93 " << tag << std::endl; }
            else { ++fail; std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl; }
            ++idx;
            }
        }
        {
            if (only_case >= 0 && only_case != idx) { ++idx; }
            else {
            std::string why;
            bool r = dtls_wolf_server_jpssl_client(e.ver, e.cs, e.w_name, why);
            std::string tag = std::string("B wolfssl-server <-> jpssl-client ") + e.label;
            if (r) { ++pass; std::cout << "  \xE2\x9C\x93 " << tag << std::endl; }
            else { ++fail; std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl; }
            ++idx;
            }
        }
    }
    std::printf("  DTLS 1.2/1.3 wolfSSL interop: %d pass, %d fail (%d 套件 x 2 方向)\n",
                pass, fail, (int)(sizeof(kWolfCases) / sizeof(kWolfCases[0])));
    TEST("DTLS 1.2/1.3 wolfSSL 互操作全部通过", fail == 0);
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    wolfSSL_Init();
    RUN_TEST(test_dtls_wolfssl_interop);
    int rc = test_summary();
    wolfSSL_Cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
