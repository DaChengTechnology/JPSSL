/**
 * test_tls_openssl_interop.cpp — jpssl ↔ OpenSSL TLS 1.3 互操作测试
 *
 * 覆盖本机 OpenSSL 支持的 TLS 1.3 加密套件（逐套件探测，不可用时 SKIP）：
 *   TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384
 *   TLS_CHACHA20_POLY1305_SHA256 / TLS_AES_128_CCM_SHA256
 *   TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3（RFC 8998，OpenSSL ≥ 3.x 部分版本支持）
 *
 * 每个套件验证两个方向：
 *   A. jpssl 服务端 ↔ OpenSSL 客户端（OpenSSL 指定单个 ciphersuite 连接）
 *   B. OpenSSL 服务端 ↔ jpssl 客户端（jpssl 指定目标套件连接）
 * 每个方向断言：握手成功、协商套件与目标一致、双向应用数据一致。
 *
 * 注意：OpenSSL 3.0.x 默认构建不含 TLS_AES_128_CCM_SHA256 与 RFC 8998
 *       SM 套件（SSL_CTX_set_ciphersuites 报 no cipher match），此时该套件
 *       标记 SKIP —— 内部往返正确性由 test_tls.cpp 的组合矩阵覆盖。
 *
 * 编译需要链接 OpenSSL (libssl + libcrypto)。
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "tls_socket.hpp"
#include "ecdsa.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

// ═══════════════════════════════════════════════════════════════════════
//  辅助
// ═══════════════════════════════════════════════════════════════════════

// 目标套件 → OpenSSL ciphersuite 名
static const char* ossl_cs_name(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:       return "TLS_AES_128_GCM_SHA256";
        case CipherSuite::TLS_AES_256_GCM_SHA384:       return "TLS_AES_256_GCM_SHA384";
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256: return "TLS_CHACHA20_POLY1305_SHA256";
        case CipherSuite::TLS_AES_128_CCM_SHA256:       return "TLS_AES_128_CCM_SHA256";
        case CipherSuite::TLS_SM4_GCM_SM3:              return "TLS_SM4_GCM_SM3";
        case CipherSuite::TLS_SM4_CCM_SM3:              return "TLS_SM4_CCM_SM3";
        default: return nullptr;
    }
}

static const char* cs_short_name(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:       return "AES128-GCM-SHA256";
        case CipherSuite::TLS_AES_256_GCM_SHA384:       return "AES256-GCM-SHA384";
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256: return "CHACHA20-POLY1305-SHA256";
        case CipherSuite::TLS_AES_128_CCM_SHA256:       return "AES128-CCM-SHA256";
        case CipherSuite::TLS_SM4_GCM_SM3:              return "SM4-GCM-SM3";
        case CipherSuite::TLS_SM4_CCM_SM3:              return "SM4-CCM-SM3";
        default: return "?";
    }
}

// jpssl 服务端证书（ECDSA P-256，自持密钥）
static std::unique_ptr<tls_certificate> make_jpssl_ecdsa_cert() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(cert->pub.ecdsa_p256, cert->priv.ecdsa_p256);
    return cert;
}

// OpenSSL 生成 ECDSA P-256 密钥对；公钥 x||y 64 字节导出到 xy_buf。
// 返回 OpenSSL EVP_PKEY（含私钥，供服务端签名）。
static EVP_PKEY* ossl_gen_ecdsa_p256(uint8_t xy_buf[64]) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return nullptr;
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);

    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!eckey) { EVP_PKEY_free(pkey); return nullptr; }
    const EC_GROUP* grp = EC_KEY_get0_group(eckey);
    const EC_POINT* pt = EC_KEY_get0_public_key(eckey);
    BIGNUM* x = BN_new(); BIGNUM* y = BN_new();
    if (!grp || !pt || !x || !y ||
        EC_POINT_get_affine_coordinates_GFp(grp, pt, x, y, nullptr) != 1 ||
        BN_bn2binpad(x, xy_buf, 32) != 32 ||
        BN_bn2binpad(y, xy_buf + 32, 32) != 32) {
        BN_free(x); BN_free(y); EC_KEY_free(eckey); EVP_PKEY_free(pkey);
        return nullptr;
    }
    BN_free(x); BN_free(y); EC_KEY_free(eckey);
    return pkey;
}

// OpenSSL 自签证书（ECDSA P-256），CN=localhost
static X509* ossl_self_signed(EVP_PKEY* pkey) {
    X509* x = X509_new();
    if (!x) return nullptr;
    X509_set_version(x, 2);  // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), -60);
    X509_gmtime_adj(X509_get_notAfter(x), 60L * 60 * 24 * 30);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, name);
    if (X509_sign(x, pkey, EVP_sha256()) <= 0) {
        X509_free(x);
        return nullptr;
    }
    return x;
}

// 用单个 TLS 1.3 ciphersuite 配置 OpenSSL 上下文；返回 false 表示该套件
// 本机 OpenSSL 不支持（no cipher match）—— 测试应 SKIP 而非失败。
static bool ossl_ctx_set_tls13_only(SSL_CTX* ctx, const char* cs_name) {
    // min/max 均为 TLS 1.3 即保证不协商 TLS 1.2（无需再清 TLS 1.2 套件；
    // TLS 1.3-only 下 SSL_CTX_set_cipher_list 会因无可用 TLS 1.2 套件返回 0）
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return SSL_CTX_set_ciphersuites(ctx, cs_name) == 1;
}

static void set_socket_timeouts(int fd) {
    timeval tv{};
    tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// 循环读取恰好 want 字节
static bool ssl_read_full(SSL* ssl, uint8_t* buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        int n = SSL_read(ssl, buf + got, (int)(want - got));
        if (n <= 0) {
            int e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        got += (size_t)n;
    }
    return true;
}

static bool ssl_write_all(SSL* ssl, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, data + sent, (int)(len - sent));
        if (n <= 0) {
            int e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  方向 A：jpssl 服务端 ↔ OpenSSL 客户端
// ═══════════════════════════════════════════════════════════════════════

static bool interop_jpssl_server_ossl_client(CipherSuite cs, std::string& why) {
    const char* cs_name = ossl_cs_name(cs);
    if (!cs_name) { why = "no ossl suite name"; return false; }

    // 先探测本机 OpenSSL 是否支持该套件（失败直接 SKIP，不启动任何线程）
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { why = "SSL_CTX_new failed"; return false; }
    if (!ossl_ctx_set_tls13_only(ctx, cs_name)) {
        SSL_CTX_free(ctx);
        why = "SKIP: OpenSSL 不支持该套件";
        return true;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // jpssl 服务端
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", make_jpssl_ecdsa_cert());
    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) { why = "jpssl listen: " + err; SSL_CTX_free(ctx); return false; }
    uint16_t port = listener.local_port();

    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::atomic<bool> stop{false};
    std::thread srv_th([&] {
        // 等待连接就绪（带超时，避免主线程异常路径 join 永久阻塞）
        for (int i = 0; i < 80; ++i) {
            if (stop.load()) return;
            if (listener.wait_readable(100)) break;
        }
        if (stop.load()) return;
        tls_connection conn;
        if (!listener.accept(conn, cert_mgr, &err)) { srv_err = "accept: " + err; return; }
        // 接收 OpenSSL 客户端数据
        std::vector<uint8_t> buf;
        if (!conn.recv(buf, &err)) { srv_err = "recv: " + err; return; }
        static const char expect[] = "ping-from-ossl-client";
        if (buf.size() != sizeof(expect) - 1 ||
            std::memcmp(buf.data(), expect, sizeof(expect) - 1) != 0) {
            srv_err = "jpssl server recv mismatch";
            return;
        }
        // 回包
        static const char resp[] = "pong-from-jpssl-server";
        if (!conn.send((const uint8_t*)resp, sizeof(resp) - 1, &err)) {
            srv_err = "send: " + err;
            return;
        }
        srv_ok = true;
    });

    // OpenSSL 客户端
    bool ok = false;

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { why = "socket failed"; SSL_CTX_free(ctx); srv_th.join(); return false; }
    set_socket_timeouts(fd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        why = "connect failed"; ::close(fd); SSL_CTX_free(ctx);
        stop = true; srv_th.join(); return false;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, "localhost");
    if (SSL_connect(ssl) == 1) {
        // 协商套件校验
        const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
        const char* got = c ? SSL_CIPHER_get_name(c) : nullptr;
        if (got && std::strcmp(got, cs_name) == 0) {
            static const char ping[] = "ping-from-ossl-client";
            static const char expect_resp[] = "pong-from-jpssl-server";
            uint8_t rbuf[64] = {0};
            if (ssl_write_all(ssl, (const uint8_t*)ping, sizeof(ping) - 1) &&
                ssl_read_full(ssl, rbuf, sizeof(expect_resp) - 1) &&
                std::memcmp(rbuf, expect_resp, sizeof(expect_resp) - 1) == 0) {
                ok = true;
            } else {
                why = "ossl client data exchange failed";
            }
        } else {
            why = "ossl client negotiated wrong suite: " + std::string(got ? got : "(null)");
        }
    } else {
        unsigned long e = ERR_peek_last_error();
        why = "SSL_connect failed: " + std::string(ERR_error_string(e, nullptr));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(fd);
    SSL_CTX_free(ctx);
    srv_th.join();

    if (!ok && why.empty()) why = srv_err.empty() ? "unknown" : srv_err;
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "jpssl server failed" : srv_err; }
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════
//  方向 B：OpenSSL 服务端 ↔ jpssl 客户端
// ═══════════════════════════════════════════════════════════════════════

static bool interop_ossl_server_jpssl_client(CipherSuite cs, std::string& why) {
    const char* cs_name = ossl_cs_name(cs);
    if (!cs_name) { why = "no ossl suite name"; return false; }

    // OpenSSL 服务端密钥对 + 自签证书；公钥同时放入 jpssl 端预期证书
    uint8_t xy[64];
    EVP_PKEY* pkey = ossl_gen_ecdsa_p256(xy);
    if (!pkey) { why = "ossl keygen failed"; return false; }
    X509* x509 = ossl_self_signed(pkey);
    if (!x509) { EVP_PKEY_free(pkey); why = "ossl cert failed"; return false; }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { why = "SSL_CTX_new failed"; X509_free(x509); EVP_PKEY_free(pkey); return false; }
    if (!ossl_ctx_set_tls13_only(ctx, cs_name)) {
        SSL_CTX_free(ctx); X509_free(x509); EVP_PKEY_free(pkey);
        why = "SKIP: OpenSSL 不支持该套件";
        return true;
    }
    SSL_CTX_use_certificate(ctx, x509);
    SSL_CTX_use_PrivateKey(ctx, pkey);

    // 监听
    int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { why = "socket failed"; SSL_CTX_free(ctx); X509_free(x509); EVP_PKEY_free(pkey); return false; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::bind(lfd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(lfd, 4) != 0) {
        why = "bind/listen failed"; ::close(lfd); SSL_CTX_free(ctx); X509_free(x509); EVP_PKEY_free(pkey); return false;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (sockaddr*)&addr, &alen);
    uint16_t port = ntohs(addr.sin_port);

    // 服务端线程：accept + SSL_accept + 数据交换
    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::thread srv_th([&] {
        pollfd pfd{lfd, POLLIN, 0};
        if (::poll(&pfd, 1, 8000) <= 0) { srv_err = "accept timeout"; return; }
        int cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd < 0) { srv_err = "accept failed"; return; }
        set_socket_timeouts(cfd);
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cfd);
        if (SSL_accept(ssl) == 1) {
            const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
            const char* got = c ? SSL_CIPHER_get_name(c) : nullptr;
            if (got && std::strcmp(got, cs_name) == 0) {
                static const char expect[] = "ping-from-jpssl-client";
                static const char resp[] = "pong-from-ossl-server";
                uint8_t rbuf[64] = {0};
                if (ssl_read_full(ssl, rbuf, sizeof(expect) - 1) &&
                    std::memcmp(rbuf, expect, sizeof(expect) - 1) == 0 &&
                    ssl_write_all(ssl, (const uint8_t*)resp, sizeof(resp) - 1)) {
                    srv_ok = true;
                } else {
                    srv_err = "ossl server data exchange failed";
                }
            } else {
                srv_err = std::string("ossl server negotiated wrong suite: ") + (got ? got : "(null)");
            }
        } else {
            srv_err = "SSL_accept failed";
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(cfd);
    });

    // jpssl 客户端：预期证书（公钥与 OpenSSL 服务端配对）
    tls_certificate_manager cli_mgr;
    auto expect_cert = std::make_unique<tls_certificate>();
    expect_cert->subject_name = "localhost";
    expect_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(expect_cert->pub.ecdsa_p256, xy, 64);
    cli_mgr.add_certificate("localhost", std::move(expect_cert));

    bool ok = false;
    tls_connection conn;
    conn.session().cipher_suite = cs;
    std::string err;
    if (conn.connect("localhost", port, &cli_mgr, &err)) {
        if (conn.session().cipher_suite == cs) {
            static const char ping[] = "ping-from-jpssl-client";
            static const char expect_resp[] = "pong-from-ossl-server";
            if (conn.send((const uint8_t*)ping, sizeof(ping) - 1, &err)) {
                std::vector<uint8_t> buf;
                if (conn.recv(buf, &err) &&
                    buf.size() == sizeof(expect_resp) - 1 &&
                    std::memcmp(buf.data(), expect_resp, sizeof(expect_resp) - 1) == 0) {
                    ok = true;
                } else {
                    why = "jpssl client recv failed: " + err;
                }
            } else {
                why = "jpssl client send failed: " + err;
            }
        } else {
            why = "jpssl client negotiated wrong suite";
        }
    } else {
        why = "jpssl client connect failed: " + err;
    }

    srv_th.join();
    ::close(lfd);
    SSL_CTX_free(ctx);
    X509_free(x509);
    EVP_PKEY_free(pkey);

    if (!ok && why.empty()) why = srv_err.empty() ? "unknown" : srv_err;
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "ossl server failed" : srv_err; }
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试入口
// ═══════════════════════════════════════════════════════════════════════

void test_tls13_openssl_interop() {
    std::printf("\n=== TLS 1.3 加密套件 × OpenSSL 互操作 ===\n");

    const CipherSuite suites[] = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_AES_128_CCM_SHA256,
        CipherSuite::TLS_SM4_GCM_SM3,
        CipherSuite::TLS_SM4_CCM_SM3,
    };
    const int kTotal = (int)(sizeof(suites) / sizeof(suites[0]));
    int pass = 0, skip = 0, fail = 0;

    for (CipherSuite cs : suites) {
        const char* short_name = cs_short_name(cs);

        // 方向 A：jpssl 服务端 ↔ OpenSSL 客户端
        {
            std::string why;
            bool r = interop_jpssl_server_ossl_client(cs, why);
            std::string tag = std::string("A jpssl-server <-> ossl-client ") + short_name;
            if (r && why.rfind("SKIP", 0) == 0) {
                ++skip;
                std::cout << "  - " << tag << " : " << why << std::endl;
            } else if (r) {
                ++pass;
                std::cout << "  ✓ " << tag << std::endl;
            } else {
                ++fail;
                std::cout << "  ✗ " << tag << " — " << why << std::endl;
            }
        }

        // 方向 B：OpenSSL 服务端 ↔ jpssl 客户端
        {
            std::string why;
            bool r = interop_ossl_server_jpssl_client(cs, why);
            std::string tag = std::string("B ossl-server <-> jpssl-client ") + short_name;
            if (r && why.rfind("SKIP", 0) == 0) {
                ++skip;
                std::cout << "  - " << tag << " : " << why << std::endl;
            } else if (r) {
                ++pass;
                std::cout << "  ✓ " << tag << std::endl;
            } else {
                ++fail;
                std::cout << "  ✗ " << tag << " — " << why << std::endl;
            }
        }
    }

    std::printf("  OpenSSL interop: %d pass, %d skip, %d fail (共 %d 套件 × 2 方向)\n",
                pass, skip, fail, kTotal);
    TEST("TLS 1.3 OpenSSL 互操作: 可用套件全部通过", fail == 0);
}

// 直接可执行入口（同时保持 test_utils 框架兼容）
#ifndef JPSSL_INTEROP_NO_MAIN
int main() {
    test_tls13_openssl_interop();
    return test_summary();
}
#endif
