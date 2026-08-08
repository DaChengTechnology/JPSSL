/**
 * test_dtls13_openssl_interop.cpp — jpssl DTLS 1.3 (RFC 9147) ↔ OpenSSL 互通测试
 *
 *   A. jpssl DTLS 1.3 服务端 ↔ OpenSSL DTLS 1.3 客户端
 *   B. OpenSSL DTLS 1.3 服务端 ↔ jpssl DTLS 1.3 客户端
 *
 * OpenSSL 4.0.0 尚未实现 DTLS 1.3：头文件没有 DTLS1_3_VERSION（仅 DTLS1_0/1.2），
 * DTLS_MAX_VERSION 仍是 DTLS1_2_VERSION，s_server 也没有 -dtls1_3 选项。
 * 因此本测试在编译期判定：OpenSSL 无 DTLS 1.3 支持时输出 SKIP 并视为通过；
 * 一旦上游 OpenSSL 增加 DTLS 1.3（定义 DTLS1_3_VERSION），真实互通用例即被启用。
 */
#include "test_utils.hpp"
#include "dtls.hpp"
#include "ecdsa.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
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

#ifdef _WIN32
using jp_sock_t = SOCKET;
static void sock_close(jp_sock_t fd) { closesocket(fd); }
#else
using jp_sock_t = int;
static void sock_close(jp_sock_t fd) { ::close(fd); }
#endif

static std::string ossl_errors() {
    std::string out;
    unsigned long e = 0;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        out += buf; out += "\n";
    }
    return out;
}

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
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = dns;
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    memcpy(cert->pub.ecdsa_p256, pub, 64);
    memcpy(cert->priv.ecdsa_p256, priv, 32);
    cert->cert_data = der.to_der();
    mgr.add_certificate(dns, std::move(cert));
    return mgr;
}

static EVP_PKEY* ossl_gen_ecdsa_p256() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509* ossl_self_signed_dtls(EVP_PKEY* pkey) {
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x2d);
    X509_gmtime_adj(X509_get_notBefore(x), -60);
    X509_gmtime_adj(X509_get_notAfter(x), 60L * 60 * 24 * 30);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = const_cast<X509_NAME*>(X509_get_subject_name(x));
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)"dtls.test", -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, x, x, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_alt_name,
                                              (char*)"DNS:dtls.test");
    if (ext) { X509_add_ext(x, ext, -1); X509_EXTENSION_free(ext); }
    X509_EXTENSION* bc = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_basic_constraints,
                                             (char*)"critical,CA:TRUE");
    if (bc) { X509_add_ext(x, bc, -1); X509_EXTENSION_free(bc); }
    if (X509_sign(x, pkey, EVP_sha256()) <= 0) { X509_free(x); return nullptr; }
    return x;
}

static std::string x509_to_pem(X509* x) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, x);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string out(data ? data : "", len > 0 ? (size_t)len : 0);
    BIO_free(bio);
    return out;
}

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

#ifdef DTLS1_3_VERSION
// ============================================================
//  OpenSSL 支持 DTLS 1.3 时的真实互通用例
// ============================================================

// A：jpssl DTLS 1.3 服务端 ↔ OpenSSL DTLS 1.3 客户端
static bool dtls13_jpssl_server_ossl_client(CipherSuite cs, const char* ossl_name,
                                            std::string& why) {
    auto cert_mgr = make_jpssl_cert_mgr("dtls.test");
    dtls_connection srv;
    srv.set_version(DTLSVersion::V13);
    srv.set_cipher_suite(cs);
    if (!srv.bind(0, "127.0.0.1")) { why = "jpssl bind failed"; return false; }
    uint16_t port = srv.local_port();

    std::atomic<bool> srv_ok{false};
    std::string srv_err;
    std::thread srv_th([&] {
        if (!srv.server_handshake(cert_mgr)) { srv_err = "server_handshake failed: " + srv.last_error(); return; }
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

    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) { why = "SSL_CTX_new failed"; srv_th.join(); return false; }
    SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION);
    if (SSL_CTX_set_ciphersuites(ctx, ossl_name) != 1) {
        why = std::string("SSL_CTX_set_ciphersuites: ") + ossl_name + "\n" + ossl_errors();
        SSL_CTX_free(ctx); srv_th.join(); return false;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    const tls_certificate* jc = cert_mgr.get_default_certificate();
    if (jc && !jc->cert_data.empty()) {
        const uint8_t* p = jc->cert_data.data();
        X509* x = d2i_X509(nullptr, &p, (long)jc->cert_data.size());
        if (!x || !X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), x)) {
            why = "failed to add jpssl cert to ossl store\n" + ossl_errors();
            if (x) X509_free(x);
            SSL_CTX_free(ctx); srv_th.join(); return false;
        }
        X509_free(x);
    }

    jp_sock_t fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == (jp_sock_t)-1) { why = "socket failed"; SSL_CTX_free(ctx); srv_th.join(); return false; }
    timeval tv{}; tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, (int)sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        why = "connect failed"; sock_close(fd); SSL_CTX_free(ctx); srv_th.join(); return false;
    }
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)fd);
    SSL_set_tlsext_host_name(ssl, "dtls.test");
    bool ok = false;
    if (SSL_connect(ssl) == 1) {
        const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
        const char* got = c ? SSL_CIPHER_get_name(c) : nullptr;
        ok = got && std::strcmp(got, ossl_name) == 0;
        if (!ok) why = std::string("ossl client negotiated wrong suite: ") + (got ? got : "(null)");
        static const char ping[] = "ping";
        static const char pong[] = "pong-from-jpssl";
        uint8_t rbuf[64] = {0};
        ok = ok && ssl_write_all(ssl, (const uint8_t*)ping, sizeof(ping) - 1);
        ok = ok && ssl_read_full(ssl, rbuf, sizeof(pong) - 1) &&
             std::memcmp(rbuf, pong, sizeof(pong) - 1) == 0;
        if (!ok && why.empty()) why = "ossl client data exchange failed";
    } else {
        why = "SSL_connect failed:\n" + ossl_errors();
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    sock_close(fd);
    srv_th.join();
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "jpssl server failed" : srv_err; }
    return ok;
}

// B：OpenSSL DTLS 1.3 服务端 ↔ jpssl DTLS 1.3 客户端
static bool dtls13_ossl_server_jpssl_client(CipherSuite cs, const char* ossl_name,
                                            std::string& why) {
    EVP_PKEY* pkey = ossl_gen_ecdsa_p256();
    if (!pkey) { why = "ossl keygen failed"; return false; }
    X509* x = ossl_self_signed_dtls(pkey);
    if (!x) { EVP_PKEY_free(pkey); why = "ossl cert failed"; return false; }
    std::string pem = x509_to_pem(x);

    SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) { why = "SSL_CTX_new failed"; X509_free(x); EVP_PKEY_free(pkey); return false; }
    SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION);
    SSL_CTX_clear_options(ctx, SSL_OP_COOKIE_EXCHANGE);
    if (SSL_CTX_set_ciphersuites(ctx, ossl_name) != 1 ||
        SSL_CTX_use_certificate(ctx, x) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        why = "ossl server ctx/cert setup failed:\n" + ossl_errors();
        SSL_CTX_free(ctx); X509_free(x); EVP_PKEY_free(pkey); return false;
    }

    jp_sock_t lfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (lfd == (jp_sock_t)-1) { why = "socket failed"; SSL_CTX_free(ctx); X509_free(x); EVP_PKEY_free(pkey); return false; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET; addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::bind(lfd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        why = "bind failed"; sock_close(lfd); SSL_CTX_free(ctx); X509_free(x); EVP_PKEY_free(pkey); return false;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (sockaddr*)&addr, &alen);
    uint16_t port = ntohs(addr.sin_port);

    std::atomic<bool> srv_ok{false};
    std::string srv_err;
    std::thread srv_th([&] {
        BIO* bio = BIO_new_dgram((int)lfd, BIO_NOCLOSE);
        if (!bio) { srv_err = "BIO_new_dgram failed"; return; }
        SSL* ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);
        if (SSL_accept(ssl) == 1) {
            const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
            const char* got = c ? SSL_CIPHER_get_name(c) : nullptr;
            static const char ping[] = "ping";
            static const char pong[] = "pong-from-ossl";
            uint8_t rbuf[64] = {0};
            if (got && std::strcmp(got, ossl_name) == 0 &&
                ssl_read_full(ssl, rbuf, sizeof(ping) - 1) &&
                std::memcmp(rbuf, ping, sizeof(ping) - 1) == 0 &&
                ssl_write_all(ssl, (const uint8_t*)pong, sizeof(pong) - 1)) {
                srv_ok = true;
            } else {
                srv_err = std::string("ossl server exchange failed, suite=") +
                          (got ? got : "(null)") + "\n" + ossl_errors();
            }
        } else {
            srv_err = "SSL_accept failed:\n" + ossl_errors();
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
    });

    tls_trust_store trust = tls_trust_store::from_pem(pem);
    dtls_connection cli;
    cli.set_version(DTLSVersion::V13);
    cli.set_server_name("dtls.test");
    cli.set_cipher_suite(cs);

    bool ok = false;
    if (cli.connect("127.0.0.1", port, &trust)) {
        ok = cli.session().cipher_suite == cs;
        static const char ping[] = "ping";
        static const char pong[] = "pong-from-ossl";
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
    SSL_CTX_free(ctx);
    X509_free(x);
    EVP_PKEY_free(pkey);
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "ossl server failed" : srv_err; }
    return ok;
}
#endif  // DTLS1_3_VERSION

void test_dtls13_openssl_interop() {
    std::printf("\n=== DTLS 1.3 套件 x OpenSSL 互操作 ===\n");
#ifdef DTLS1_3_VERSION
    struct dtls13_case {
        CipherSuite cs;
        const char* ossl_name;
    };
    static const dtls13_case kCases[] = {
        { CipherSuite::TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256" },
        { CipherSuite::TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256" },
    };
    int pass = 0, fail = 0;
    for (const auto& e : kCases) {
        std::string why;
        bool r = dtls13_jpssl_server_ossl_client(e.cs, e.ossl_name, why);
        std::string tag = std::string("A jpssl-server <-> ossl-client ") + e.ossl_name;
        if (r) { ++pass; std::cout << "  \xE2\x9C\x93 " << tag << std::endl; }
        else { ++fail; std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl; }
    }
    for (const auto& e : kCases) {
        std::string why;
        bool r = dtls13_ossl_server_jpssl_client(e.cs, e.ossl_name, why);
        std::string tag = std::string("B ossl-server <-> jpssl-client ") + e.ossl_name;
        if (r) { ++pass; std::cout << "  \xE2\x9C\x93 " << tag << std::endl; }
        else { ++fail; std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl; }
    }
    std::printf("  DTLS 1.3 OpenSSL interop: %d pass, %d fail\n", pass, fail);
    TEST("DTLS 1.3 OpenSSL 互操作全部通过", fail == 0);
#else
    std::printf("  SKIP: 本 OpenSSL (%s) 未实现 DTLS 1.3（RFC 9147）\n",
                OpenSSL_version(OPENSSL_VERSION));
    std::printf("  原因：头文件无 DTLS1_3_VERSION，DTLS_MAX_VERSION 仍为 DTLS1_2；\n");
    std::printf("  实测 jpssl DTLS 1.3 ClientHello 被 OpenSSL DTLS 服务端以 'no shared cipher' 拒绝。\n");
    TEST("DTLS 1.3 OpenSSL 互操作（OpenSSL 无 DTLS 1.3 支持，跳过）", true);
#endif
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    RUN_TEST(test_dtls13_openssl_interop);
    int rc = test_summary();
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
