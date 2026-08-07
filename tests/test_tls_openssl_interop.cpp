/**
 * test_tls_openssl_interop.cpp — jpssl ↔ OpenSSL 互操作测试
 *
 * 覆盖两大部分：
 *   A. TLS 1.3（RFC 8446 / RFC 8998）：本机 OpenSSL 支持的套件逐套探测，
 *      不可用时 SKIP：
 *      TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384
 *      TLS_CHACHA20_POLY1305_SHA256 / TLS_AES_128_CCM_SHA256
 *      TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3（RFC 8998，标准 OpenSSL 无实现 → SKIP）
 *   B. TLS 1.2（RFC 5246）：jpssl 服务端 ↔ OpenSSL 客户端，
 *      覆盖 jpssl 服务端支持的 8 个套件（ECDHE-ECDSA / ECDHE-RSA / RSA）。
 *
 * 每个方向断言：握手成功、协商套件与目标一致、双向应用数据一致。
 * 平台：Windows (Winsock) + Linux (POSIX socket)。
 *
 * 编译需要链接 OpenSSL (libssl + libcrypto)。
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "tls_socket.hpp"
#include "ecdsa.hpp"
#include "rsa.hpp"
#include "sm2.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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

// ============================================================
//  平台 socket 适配
// ============================================================

#ifdef _WIN32
using jp_sock_t = SOCKET;
static void sock_close(jp_sock_t fd) { closesocket(fd); }
static int do_poll(pollfd* fds, int n, int timeout_ms) {
    return WSAPoll(fds, (ULONG)n, timeout_ms);
}
#else
using jp_sock_t = int;
static void sock_close(jp_sock_t fd) { ::close(fd); }
static int do_poll(pollfd* fds, int n, int timeout_ms) {
    return ::poll(fds, (nfds_t)n, timeout_ms);
}
#endif

static void set_socket_timeouts(jp_sock_t fd) {
    timeval tv{};
    tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, (int)sizeof(tv));
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

// 收集 OpenSSL 错误队列全文（用于定位握手失败原因）
static std::string ossl_errors() {
    std::string out;
    unsigned long e = 0;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        out += buf;
        out += "\n";
    }
    return out;
}

// ============================================================
//  证书辅助
// ============================================================

// jpssl 服务端证书（ECDSA P-256，自持密钥）
static std::unique_ptr<tls_certificate> make_jpssl_ecdsa_cert() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(cert->pub.ecdsa_p256, cert->priv.ecdsa_p256);
    return cert;
}

// jpssl 服务端证书（RSA-2048，自持密钥）
static std::unique_ptr<tls_certificate> make_jpssl_rsa_cert() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    if (!rsa_keygen(cert->pub.rsa, cert->priv.rsa)) return nullptr;
    return cert;
}

// jpssl 服务端证书（SM2，RFC 8998 国密套件要求）
static std::unique_ptr<tls_certificate> make_jpssl_sm2_cert() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::SM2_SM3;
    sm2_keygen(cert->pub.sm2, cert->priv.sm2);
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

// OpenSSL 生成 RSA-2048 密钥对；公钥 n/e 以 256/3 字节大端导出。
// 返回 OpenSSL EVP_PKEY（含私钥）。
static EVP_PKEY* ossl_gen_rsa_2048(uint8_t n_buf[256], uint8_t e_buf[3]) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);

    BIGNUM* n = nullptr, * e = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, "n", &n) != 1 ||
        EVP_PKEY_get_bn_param(pkey, "e", &e) != 1) {
        BN_free(n); BN_free(e); EVP_PKEY_free(pkey);
        return nullptr;
    }
    int n_len = BN_bn2binpad(n, n_buf, 256);
    int e_len = BN_bn2binpad(e, e_buf, 3);
    BN_free(n); BN_free(e);
    if (n_len != 256 || e_len != 3) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    return pkey;
}

// OpenSSL 自签证书，CN=localhost
static X509* ossl_self_signed(EVP_PKEY* pkey) {
    X509* x = X509_new();
    if (!x) return nullptr;
    X509_set_version(x, 2);  // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), -60);
    X509_gmtime_adj(X509_get_notAfter(x), 60L * 60 * 24 * 30);
    X509_set_pubkey(x, pkey);
    // OpenSSL 4.x 起 X509_get_subject_name 返回 const，X509_set_issuer_name 需要非 const
    X509_NAME* name = const_cast<X509_NAME*>(X509_get_subject_name(x));
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, name);
    if (X509_sign(x, pkey, EVP_sha256()) <= 0) {
        X509_free(x);
        return nullptr;
    }
    return x;
}

// ============================================================
//  套件命名
// ============================================================

// 目标套件 → OpenSSL ciphersuite 名称（TLS 1.3）
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

// TLS 1.2 套件表：OpenSSL cipher list 名称 + 服务端证书类型
struct tls12_suite_entry {
    CipherSuite cs;
    const char* ossl_name;
    bool need_ecdsa_cert;
};

static const tls12_suite_entry kTLS12Suites[] = {
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-ECDSA-AES128-GCM-SHA256", true },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      "ECDHE-ECDSA-AES256-GCM-SHA384", true },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-ECDSA-CHACHA20-POLY1305", true },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-RSA-AES128-GCM-SHA256", false },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      "ECDHE-RSA-AES256-GCM-SHA384", false },
    { CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-RSA-CHACHA20-POLY1305", false },
    { CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
      "AES128-GCM-SHA256", false },
    { CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
      "AES256-GCM-SHA384", false },
};

static const char* cs_short_name(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:       return "AES128-GCM-SHA256";
        case CipherSuite::TLS_AES_256_GCM_SHA384:       return "AES256-GCM-SHA384";
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256: return "CHACHA20-POLY1305-SHA256";
        case CipherSuite::TLS_AES_128_CCM_SHA256:       return "AES128-CCM-SHA256";
        case CipherSuite::TLS_SM4_GCM_SM3:              return "SM4-GCM-SM3";
        case CipherSuite::TLS_SM4_CCM_SM3:              return "SM4-CCM-SM3";
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: return "ECDHE-ECDSA-AES128-GCM-SHA256";
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: return "ECDHE-ECDSA-AES256-GCM-SHA384";
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: return "ECDHE-ECDSA-CHACHA20-POLY1305";
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:     return "ECDHE-RSA-AES128-GCM-SHA256";
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:     return "ECDHE-RSA-AES256-GCM-SHA384";
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: return "ECDHE-RSA-CHACHA20-POLY1305";
        case CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256:           return "AES128-GCM-SHA256";
        case CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384:           return "AES256-GCM-SHA384";
        default: return "?";
    }
}

// 用单个 TLS 1.3 ciphersuite 配置 OpenSSL 上下文；返回 false 表示本机
// OpenSSL 不支持（no cipher match）—— 测试应 SKIP 而非失败。
static bool ossl_ctx_set_tls13_only(SSL_CTX* ctx, const char* cs_name) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return SSL_CTX_set_ciphersuites(ctx, cs_name) == 1;
}

// 用单个 TLS 1.2 cipher 配置 OpenSSL 上下文
static bool ossl_ctx_set_tls12_only(SSL_CTX* ctx, const char* cipher_name) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    return SSL_CTX_set_cipher_list(ctx, cipher_name) == 1;
}

// ============================================================
//  方向 A：jpssl 服务端（TLS 1.2）↔ OpenSSL 客户端
// ============================================================

static bool interop_tls12_jpssl_server_ossl_client(const tls12_suite_entry& e, std::string& why) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { why = "SSL_CTX_new failed"; return false; }
    if (!ossl_ctx_set_tls12_only(ctx, e.ossl_name)) {
        SSL_CTX_free(ctx);
        why = std::string("SKIP: OpenSSL 不支持该 cipher: ") + e.ossl_name;
        return true;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // jpssl 服务端证书（按套件选择 ECDSA 或 RSA）
    tls_certificate_manager cert_mgr;
    auto cert = e.need_ecdsa_cert ? make_jpssl_ecdsa_cert() : make_jpssl_rsa_cert();
    if (!cert) { why = "jpssl cert generation failed"; SSL_CTX_free(ctx); return false; }
    cert_mgr.add_certificate("localhost", std::move(cert));

    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) {
        why = "jpssl listen: " + err; SSL_CTX_free(ctx); return false;
    }
    uint16_t port = listener.local_port();

    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::atomic<bool> stop{false};
    std::thread srv_th([&] {
        for (int i = 0; i < 80; ++i) {
            if (stop.load()) return;
            if (listener.wait_readable(100)) break;
        }
        if (stop.load()) return;
        tls_connection conn;
        if (!listener.accept(conn, cert_mgr, &err)) { srv_err = "accept: " + err; return; }
        std::vector<uint8_t> buf;
        if (!conn.recv(buf, &err)) { srv_err = "recv: " + err; return; }
        static const char expect[] = "ping-from-ossl-client";
        if (buf.size() != sizeof(expect) - 1 ||
            std::memcmp(buf.data(), expect, sizeof(expect) - 1) != 0) {
            srv_err = "jpssl server recv mismatch";
            return;
        }
        static const char resp[] = "pong-from-jpssl-server";
        if (!conn.send((const uint8_t*)resp, sizeof(resp) - 1, &err)) {
            srv_err = "send: " + err;
            return;
        }
        srv_ok = true;
    });

    bool ok = false;
    jp_sock_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd == (jp_sock_t)-1) { why = "socket failed"; SSL_CTX_free(ctx); stop = true; srv_th.join(); return false; }
    set_socket_timeouts(fd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        why = "connect failed"; sock_close(fd); SSL_CTX_free(ctx);
        stop = true; srv_th.join(); return false;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)fd);
    SSL_set_tlsext_host_name(ssl, "localhost");
    if (SSL_connect(ssl) == 1) {
        const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
        const char* got = c ? SSL_CIPHER_get_name(c) : nullptr;
        if (got && std::strcmp(got, e.ossl_name) == 0) {
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
        why = "SSL_connect failed:\n" + ossl_errors() + "server: " + srv_err;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    sock_close(fd);
    SSL_CTX_free(ctx);
    stop = true;
    srv_th.join();

    if (!ok && why.empty()) why = srv_err.empty() ? "unknown" : srv_err;
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "jpssl server failed" : srv_err; }
    return ok;
}

// ============================================================
//  方向 A：jpssl 服务端（TLS 1.3）↔ OpenSSL 客户端
// ============================================================

static bool interop_jpssl_server_ossl_client(CipherSuite cs, std::string& why) {
    const char* cs_name = ossl_cs_name(cs);
    if (!cs_name) { why = "no ossl suite name"; return false; }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { why = "SSL_CTX_new failed"; return false; }
    if (!ossl_ctx_set_tls13_only(ctx, cs_name)) {
        SSL_CTX_free(ctx);
        why = "SKIP: OpenSSL 不支持该套件";
        return true;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // RFC 8998：SM 套件要求客户端提供 curveSM2 key_share；
    // OpenSSL 默认只声明 supported_groups 而不发 share，需强制其发送。
    if (tls_use_sm3(cs) && SSL_CTX_set1_groups_list(ctx, "SM2") != 1) {
        SSL_CTX_free(ctx);
        why = "SKIP: OpenSSL 不支持 curveSM2 group";
        return true;
    }
    tls_certificate_manager cert_mgr;
    if (tls_use_sm3(cs))
        cert_mgr.add_certificate("localhost", make_jpssl_sm2_cert());
    else
        cert_mgr.add_certificate("localhost", make_jpssl_ecdsa_cert());
    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) { why = "jpssl listen: " + err; SSL_CTX_free(ctx); return false; }
    uint16_t port = listener.local_port();

    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::atomic<bool> stop{false};
    std::thread srv_th([&] {
        for (int i = 0; i < 80; ++i) {
            if (stop.load()) return;
            if (listener.wait_readable(100)) break;
        }
        if (stop.load()) return;
        tls_connection conn;
        if (!listener.accept(conn, cert_mgr, &err)) { srv_err = "accept: " + err; return; }
        std::vector<uint8_t> buf;
        if (!conn.recv(buf, &err)) { srv_err = "recv: " + err; return; }
        static const char expect[] = "ping-from-ossl-client";
        if (buf.size() != sizeof(expect) - 1 ||
            std::memcmp(buf.data(), expect, sizeof(expect) - 1) != 0) {
            srv_err = "jpssl server recv mismatch";
            return;
        }
        static const char resp[] = "pong-from-jpssl-server";
        if (!conn.send((const uint8_t*)resp, sizeof(resp) - 1, &err)) {
            srv_err = "send: " + err;
            return;
        }
        srv_ok = true;
    });

    bool ok = false;
    jp_sock_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd == (jp_sock_t)-1) { why = "socket failed"; SSL_CTX_free(ctx); stop = true; srv_th.join(); return false; }
    set_socket_timeouts(fd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        why = "connect failed"; sock_close(fd); SSL_CTX_free(ctx);
        stop = true; srv_th.join(); return false;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)fd);
    SSL_set_tlsext_host_name(ssl, "localhost");
    if (SSL_connect(ssl) == 1) {
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
        unsigned long errcode = ERR_peek_last_error();
        why = "SSL_connect failed:\n" + ossl_errors() + "server: " + srv_err;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    sock_close(fd);
    SSL_CTX_free(ctx);
    stop = true;
    srv_th.join();

    if (!ok && why.empty()) why = srv_err.empty() ? "unknown" : srv_err;
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "jpssl server failed" : srv_err; }
    return ok;
}

// ============================================================
//  方向 B：OpenSSL 服务端（TLS 1.3）↔ jpssl 客户端
// ============================================================

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

    jp_sock_t lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd == (jp_sock_t)-1) { why = "socket failed"; SSL_CTX_free(ctx); X509_free(x509); EVP_PKEY_free(pkey); return false; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::bind(lfd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(lfd, 4) != 0) {
        why = "bind/listen failed"; sock_close(lfd); SSL_CTX_free(ctx); X509_free(x509); EVP_PKEY_free(pkey); return false;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (sockaddr*)&addr, &alen);
    uint16_t port = ntohs(addr.sin_port);

    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::thread srv_th([&] {
        pollfd pfd{ lfd, POLLIN, 0 };
        if (do_poll(&pfd, 1, 8000) <= 0) { srv_err = "accept timeout"; return; }
        jp_sock_t cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd == (jp_sock_t)-1) { srv_err = "accept failed"; return; }
        set_socket_timeouts(cfd);
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, (int)cfd);
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
        sock_close(cfd);
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
    sock_close(lfd);
    SSL_CTX_free(ctx);
    X509_free(x509);
    EVP_PKEY_free(pkey);

    if (!ok && why.empty()) why = srv_err.empty() ? "unknown" : srv_err;
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "ossl server failed" : srv_err; }
    return ok;
}

// ============================================================
//  测试入口
// ============================================================

void test_tls12_openssl_interop() {
    std::printf("\n=== TLS 1.2 套件 × OpenSSL 互操作（jpssl 服务端 ↔ OpenSSL 客户端）===\n");
    const int kTotal = (int)(sizeof(kTLS12Suites) / sizeof(kTLS12Suites[0]));
    int pass = 0, skip = 0, fail = 0;

    for (const auto& e : kTLS12Suites) {
        std::string why;
        bool r = interop_tls12_jpssl_server_ossl_client(e, why);
        std::string tag = std::string("A jpssl-server <-> ossl-client ") + e.ossl_name;
        if (r && why.rfind("SKIP", 0) == 0) {
            ++skip;
            std::cout << "  - " << tag << " : " << why << std::endl;
        } else if (r) {
            ++pass;
            std::cout << "  \xE2\x9C\x93 " << tag << std::endl;
        } else {
            ++fail;
            std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl;
        }
    }

    std::printf("  TLS 1.2 OpenSSL interop: %d pass, %d skip, %d fail (共 %d 套件)\n",
                pass, skip, fail, kTotal);
    TEST("TLS 1.2 OpenSSL 互操作可用套件全部通过", fail == 0);
}

void test_tls13_openssl_interop() {
    std::printf("\n=== TLS 1.3 套件 × OpenSSL 互操作 ===\n");

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
                std::cout << "  \xE2\x9C\x93 " << tag << std::endl;
            } else {
                ++fail;
                std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl;
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
                std::cout << "  \xE2\x9C\x93 " << tag << std::endl;
            } else {
                ++fail;
                std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl;
            }
        }
    }

    std::printf("  OpenSSL interop: %d pass, %d skip, %d fail (共 %d 套件 × 2 方向)\n",
                pass, skip, fail, kTotal);
    TEST("TLS 1.3 OpenSSL 互操作可用套件全部通过", fail == 0);
}

// 直接可执行入口（同时保持 test_utils 框架兼容）
#ifndef JPSSL_INTEROP_NO_MAIN
int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    test_tls12_openssl_interop();
    test_tls13_openssl_interop();
    int rc = test_summary();
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
#endif
