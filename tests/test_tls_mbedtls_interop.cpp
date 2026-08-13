/**
 * test_tls_mbedtls_interop.cpp - jpssl <-> Mbed TLS TLS 1.2 / 1.3 全量互操作
 *
 * TLS 1.3（RFC 8446）：
 *   TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 /
 *   TLS_CHACHA20_POLY1305_SHA256 / TLS_AES_128_CCM_SHA256 /
 *   TLS_AES_128_CCM_8_SHA256
 *
 * TLS 1.2（RFC 5246）：
 *   ECDHE-ECDSA / ECDHE-RSA / DHE-RSA / RSA × AES-GCM / CHACHA20 / AES-CBC
 *   DHE-PSK / PSK × AES-GCM / CHACHA20 / AES-CBC
 *
 * 每个套件 × 两个方向（A: jpssl server <-> Mbed TLS client，
 * B: Mbed TLS server <-> jpssl client）× 31 种长度
 * （含大量非 8/16 字节对齐边界：1..17、31/32/33、63/64/65、127/128/129、
 * 255/256/257、1023/1024/1025、16383/16384/16385、65535/65536/65537）。
 *
 * 需要 Mbed TLS 3.6+（MBEDTLS_SSL_PROTO_TLS1_3，默认配置即可）：
 *   cmake -DJP_MBEDTLS_PREFIX=<install>
 *
 * 测试证书：tests/certs/tls/（EC P-256 CA + ECDSA/RSA leaf，CN/SAN=localhost）。
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "tls_socket.hpp"
#include "dh.hpp"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#include <atomic>
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
using namespace jpssl::tls;

#ifndef JPSSL_TLS_CERT_DIR
#define JPSSL_TLS_CERT_DIR "tests/certs/tls"
#endif

static const char* MB_CA_CERT    = JPSSL_TLS_CERT_DIR "/ca.pem";
static const char* MB_ECDSA_CERT = JPSSL_TLS_CERT_DIR "/server-ecdsa.pem";
static const char* MB_ECDSA_KEY  = JPSSL_TLS_CERT_DIR "/server-ecdsa-key.pem";
static const char* MB_RSA_CERT   = JPSSL_TLS_CERT_DIR "/server-rsa.pem";
static const char* MB_RSA_KEY    = JPSSL_TLS_CERT_DIR "/server-rsa-key.pem";

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

static void set_socket_timeouts(jp_sock_t fd, int seconds = 15) {
    timeval tv{};
    tv.tv_sec = seconds; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, (int)sizeof(tv));
}

// ============================================================
//  Mbed TLS 全局 RNG 与 socket BIO
// ============================================================

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static bool g_rng_ok = false;

static void mbed_rng_init() {
    if (g_rng_ok) return;
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    g_rng_ok = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func,
                                     &g_entropy, nullptr, 0) == 0;
}

static int mbed_send_cb(void* ctx, const unsigned char* buf, size_t len) {
    jp_sock_t fd = *(jp_sock_t*)ctx;
    int n = ::send(fd, (const char*)buf, (int)len, 0);
    return n <= 0 ? MBEDTLS_ERR_NET_SEND_FAILED : n;
}

static int mbed_recv_cb(void* ctx, unsigned char* buf, size_t len) {
    jp_sock_t fd = *(jp_sock_t*)ctx;
    int n = ::recv(fd, (char*)buf, (int)len, 0);
    if (n == 0) return MBEDTLS_ERR_SSL_CONN_EOF;
    return n <= 0 ? MBEDTLS_ERR_NET_RECV_FAILED : n;
}

static std::string mbed_err(int ret) {
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    return std::string(buf);
}

// Mbed TLS 3.6 已删除 MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN；
// 用运行时套件列表预检是否编译了该套件。
static bool mbed_suite_supported(int id) {
    const int* list = mbedtls_ssl_list_ciphersuites();
    for (; *list != 0; ++list)
        if (*list == id) return true;
    return false;
}

// Mbed TLS 要求 ciphersuite 数组在配置生命周期内有效；
// 测试为单线程顺序执行，静态数组即可。
static const int* mbed_suite_list(int id) {
    static int ids[2];
    ids[0] = id;
    ids[1] = 0;
    return ids;
}

// ============================================================
//  套件表
// ============================================================

enum KeyKind { KEY_ECDSA, KEY_RSA, KEY_PSK };

struct Suite {
    CipherSuite cs;
    int mbed_id;            // Mbed TLS ciphersuite id
    const char* short_name;
    bool tls13;
    KeyKind key;
};

static const Suite kSuites[] = {
    // ---- TLS 1.3 ----
    { CipherSuite::TLS_AES_128_GCM_SHA256,
      MBEDTLS_TLS1_3_AES_128_GCM_SHA256, "AES128-GCM", true, KEY_ECDSA },
    { CipherSuite::TLS_AES_256_GCM_SHA384,
      MBEDTLS_TLS1_3_AES_256_GCM_SHA384, "AES256-GCM", true, KEY_ECDSA },
    { CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
      MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256, "CHACHA20-POLY1305", true, KEY_ECDSA },
    { CipherSuite::TLS_AES_128_CCM_SHA256,
      MBEDTLS_TLS1_3_AES_128_CCM_SHA256, "AES128-CCM", true, KEY_ECDSA },
    { CipherSuite::TLS_AES_128_CCM_8_SHA256,
      MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256, "AES128-CCM-8", true, KEY_ECDSA },
    // ---- TLS 1.2 ----
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-ECDSA-CHACHA20", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM", false, KEY_RSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE-RSA-AES256-GCM", false, KEY_RSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-RSA-CHACHA20", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, "DHE-RSA-AES128-GCM", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, "DHE-RSA-AES256-GCM", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "DHE-RSA-CHACHA20", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, "DHE-RSA-AES128-CBC", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, "DHE-RSA-AES256-CBC", false, KEY_RSA },
    { CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256, "RSA-AES128-GCM", false, KEY_RSA },
    { CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, "RSA-AES256-GCM", false, KEY_RSA },
    { CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
      MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256, "RSA-AES128-CBC", false, KEY_RSA },
    { CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
      MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256, "RSA-AES256-CBC", false, KEY_RSA },
    { CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, "DHE-PSK-AES128-GCM", false, KEY_PSK },
    { CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384, "DHE-PSK-AES256-GCM", false, KEY_PSK },
    { CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
      MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256, "DHE-PSK-CHACHA20", false, KEY_PSK },
    { CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, "DHE-PSK-AES128-CBC", false, KEY_PSK },
    { CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, "DHE-PSK-AES256-CBC", false, KEY_PSK },
    { CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256, "PSK-AES128-GCM", false, KEY_PSK },
    { CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384, "PSK-AES256-GCM", false, KEY_PSK },
    { CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
      MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256, "PSK-CHACHA20", false, KEY_PSK },
    { CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256,
      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256, "PSK-AES128-CBC", false, KEY_PSK },
    { CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384,
      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384, "PSK-AES256-CBC", false, KEY_PSK },
};

static const size_t kLengths[] = {
    1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33,
    63, 64, 65, 127, 128, 129, 255, 256, 257,
    1000, 1001, 1024, 1025,
    16383, 16384, 16385,
    65535, 65536, 65537
};

static const char kPskIdentity[] = "jpssl-mbedtls-test";
static const uint8_t kPskValue[] = {
    0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
    0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30
};

// ============================================================
//  证书 / 工具
// ============================================================

static const char* srv_cert_path(KeyKind k) {
    return k == KEY_ECDSA ? MB_ECDSA_CERT : MB_RSA_CERT;
}

static const char* srv_key_path(KeyKind k) {
    return k == KEY_ECDSA ? MB_ECDSA_KEY : MB_RSA_KEY;
}

static bool suite_uses_dhe(CipherSuite cs) {
    return cs == CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384;
}

// Mbed TLS 端数据往返（长度前缀协议）。
static bool mbed_send_len_data(mbedtls_ssl_context* ssl,
                               const uint8_t* data, size_t len) {
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),  (uint8_t)len
    };
    auto write_all = [&](const uint8_t* p, size_t n) -> bool {
        size_t sent = 0;
        while (sent < n) {
            int r = mbedtls_ssl_write(ssl, p + sent, n - sent);
            if (r <= 0) return false;
            sent += (size_t)r;
        }
        return true;
    };
    return write_all(hdr, 4) && write_all(data, len);
}

static bool mbed_recv_exact(mbedtls_ssl_context* ssl, uint8_t* out, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = mbedtls_ssl_read(ssl, out + got, len - got);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

static bool mbed_exchange(mbedtls_ssl_context* ssl, size_t len) {
    std::vector<uint8_t> buf(len);
    for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)(i * 31 + 7);
    if (!mbed_send_len_data(ssl, buf.data(), len)) return false;
    uint8_t hdr[4];
    if (!mbed_recv_exact(ssl, hdr, 4)) return false;
    size_t rlen = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) |
                  ((size_t)hdr[2] << 8) | hdr[3];
    if (rlen != len) return false;
    std::vector<uint8_t> got(len);
    if (!mbed_recv_exact(ssl, got.data(), len)) return false;
    return std::memcmp(buf.data(), got.data(), len) == 0;
}

static bool mbed_exchange_all(mbedtls_ssl_context* ssl) {
    for (size_t len : kLengths)
        if (!mbed_exchange(ssl, len)) return false;
    return true;
}

// jpssl 端精确字节读取（conn.recv 可能一次返回多条记录合并数据）。
class JpByteReader {
public:
    explicit JpByteReader(tls_connection& conn) : conn_(conn) {}

    bool read_exact(std::vector<uint8_t>& out, size_t n, std::string& err) {
        out.clear();
        while (out.size() < n) {
            if (pos_ < buf_.size()) {
                size_t take = std::min(n - out.size(), buf_.size() - pos_);
                out.insert(out.end(), buf_.begin() + pos_, buf_.begin() + pos_ + take);
                pos_ += take;
            } else {
                buf_.clear();
                pos_ = 0;
                if (!conn_.recv(buf_, &err)) return false;
            }
        }
        return true;
    }

private:
    tls_connection& conn_;
    std::vector<uint8_t> buf_;
    size_t pos_ = 0;
};

static bool jp_exchange(tls_connection& conn, JpByteReader& reader,
                        size_t len, std::string& err) {
    std::vector<uint8_t> buf(len);
    for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)(i * 31 + 7);
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),  (uint8_t)len
    };
    if (!conn.send(hdr, 4, &err)) return false;
    if (!conn.send(buf.data(), len, &err)) return false;

    std::vector<uint8_t> rhdr, got;
    if (!reader.read_exact(rhdr, 4, err)) return false;
    size_t rlen = ((size_t)rhdr[0] << 24) | ((size_t)rhdr[1] << 16) |
                  ((size_t)rhdr[2] << 8) | rhdr[3];
    if (rlen != len) return false;
    if (!reader.read_exact(got, len, err)) return false;
    return std::memcmp(buf.data(), got.data(), len) == 0;
}

static bool jp_exchange_all(tls_connection& conn, JpByteReader& reader,
                            std::string& err) {
    for (size_t len : kLengths)
        if (!jp_exchange(conn, reader, len, err)) return false;
    return true;
}

// ============================================================
//  Mbed TLS 上下文
// ============================================================

static int mbed_setup_common(mbedtls_ssl_config& conf, int endpoint,
                             const Suite& s, bool server) {
    int ret = mbedtls_ssl_config_defaults(&conf, endpoint,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) return ret;
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
    // 限定版本：TLS 1.3 = 3,4；TLS 1.2 = 3,3。
    unsigned char minor = s.tls13 ? MBEDTLS_SSL_MINOR_VERSION_4
                                  : MBEDTLS_SSL_MINOR_VERSION_3;
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, minor);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, minor);
    mbedtls_ssl_conf_ciphersuites(&conf, mbed_suite_list(s.mbed_id));
    if (s.key == KEY_PSK) {
        mbedtls_ssl_conf_psk(&conf, kPskValue, sizeof(kPskValue),
                             (const unsigned char*)kPskIdentity,
                             sizeof(kPskIdentity) - 1);
    }
    if (server) {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        if (suite_uses_dhe(s.cs)) {
            using jpssl::dh::ffdhe2048_p;
            using jpssl::dh::FFDHE2048_BYTES;
            static const uint8_t g = 2;
            int dret = mbedtls_ssl_conf_dh_param_bin(&conf, ffdhe2048_p,
                                                     FFDHE2048_BYTES, &g, 1);
            if (dret != 0) return dret;
        }
    } else {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    return 0;
}

// ============================================================
//  方向 A：jpssl 服务端 <-> Mbed TLS 客户端
// ============================================================

static bool interop_jpssl_server_mbed_client(const Suite& s, std::string& why) {
    mbed_rng_init();
    if (!g_rng_ok) { why = "mbedtls RNG init failed"; return false; }

    tls_psk_store psk_store;
    tls_certificate_manager cert_mgr;
    std::unique_ptr<tls_certificate> srv_cert;
    if (s.key == KEY_PSK) {
        psk_store.add(kPskIdentity,
                      std::vector<uint8_t>(kPskValue, kPskValue + sizeof(kPskValue)));
    } else {
        std::string perr;
        srv_cert = tls_certificate::from_pem_file(srv_cert_path(s.key),
                                                  srv_key_path(s.key), &perr);
        if (!srv_cert) { why = "jpssl from_pem: " + perr; return false; }
        cert_mgr.add_certificate("localhost", std::move(srv_cert));
    }

    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) { why = "jpssl listen: " + err; return false; }
    uint16_t port = listener.local_port();

    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::atomic<bool> stop{false};
    std::thread srv_th([&] {
        for (int i = 0; i < 120 && !stop.load(); ++i) {
            if (listener.wait_readable(100)) break;
        }
        if (stop.load()) return;
        tls_connection conn;
        if (!s.tls13)
            conn.set_tls_version(TLSVersion::V12);
        bool accepted = s.key == KEY_PSK
            ? listener.accept(conn, cert_mgr, psk_store, &err)
            : listener.accept(conn, cert_mgr, &err);
        if (!accepted) { srv_err = "accept: " + err; return; }
        if (conn.session().cipher_suite != s.cs) {
            srv_err = "jpssl server negotiated wrong suite";
            return;
        }
        JpByteReader reader(conn);
        if (!jp_exchange_all(conn, reader, err)) {
            srv_err = "jpssl server data exchange failed: " + err;
            return;
        }
        srv_ok = true;
    });

    bool ok = false;
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    int ret = mbed_setup_common(conf, MBEDTLS_SSL_IS_CLIENT, s, false);
    if (ret != 0) {
        why = "mbedtls config setup failed: " + mbed_err(ret);
    } else if (!mbed_suite_supported(s.mbed_id)) {
        why = "SKIP: Mbed TLS 未编译该套件";
    } else {
        if (s.key != KEY_PSK) {
            ret = mbedtls_x509_crt_parse_file(&cacert, MB_CA_CERT);
            if (ret != 0) {
                why = "mbedtls parse CA failed: " + mbed_err(ret);
            } else {
                mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
            }
        }
        if (why.empty()) {
            ret = mbedtls_ssl_setup(&ssl, &conf);
            if (ret != 0) {
                why = "mbedtls_ssl_setup failed: " + mbed_err(ret);
            }
        }
        if (why.empty() &&
            mbedtls_ssl_set_hostname(&ssl, "localhost") != 0) {
            why = "mbedtls_ssl_set_hostname failed";
        }
        if (why.empty()) {
            jp_sock_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            if (fd == (jp_sock_t)-1 ||
                ::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
                why = "mbedtls client connect failed";
            } else {
                set_socket_timeouts(fd);
                mbedtls_ssl_set_bio(&ssl, &fd, mbed_send_cb, mbed_recv_cb, nullptr);
                while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
                    if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        why = "mbedtls handshake failed: " + mbed_err(ret);
                        break;
                    }
                }
                if (why.empty()) {
                    if (mbedtls_ssl_get_ciphersuite_id_from_ssl(&ssl) !=
                        (int)s.mbed_id) {
                        why = "mbedtls negotiated wrong suite";
                    } else if (!mbed_exchange_all(&ssl)) {
                        why = "mbedtls client data exchange failed";
                    } else {
                        ok = true;
                    }
                }
                sock_close(fd);
            }
        }
    }
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);

    stop = true;
    srv_th.join();
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "jpssl server failed" : srv_err; }
    if (!ok && !why.empty() && !srv_err.empty() &&
        why.find("server:") == std::string::npos)
        why += " | server: " + srv_err;
    return ok;
}

// ============================================================
//  方向 B：Mbed TLS 服务端 <-> jpssl 客户端
// ============================================================

static bool interop_mbed_server_jpssl_client(const Suite& s, std::string& why) {
    mbed_rng_init();
    if (!g_rng_ok) { why = "mbedtls RNG init failed"; return false; }

    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    int ret = mbed_setup_common(conf, MBEDTLS_SSL_IS_SERVER, s, true);
    if (ret != 0) {
        why = "mbedtls config setup failed: " + mbed_err(ret);
    } else if (!mbed_suite_supported(s.mbed_id)) {
        why = "SKIP: Mbed TLS 未编译该套件";
    } else if (s.key != KEY_PSK) {
        ret = mbedtls_x509_crt_parse_file(&srvcert, srv_cert_path(s.key));
        if (ret != 0) {
            why = "mbedtls parse cert failed: " + mbed_err(ret);
        } else {
            ret = mbedtls_pk_parse_keyfile(&pkey, srv_key_path(s.key), nullptr,
                                           mbedtls_ctr_drbg_random, &g_ctr_drbg);
            if (ret != 0) {
                why = "mbedtls parse key failed: " + mbed_err(ret);
            } else {
                ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
                if (ret != 0)
                    why = "mbedtls set own cert failed: " + mbed_err(ret);
            }
        }
    }

    if (why.empty()) {
        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret != 0) why = "mbedtls_ssl_setup failed: " + mbed_err(ret);
    }

    jp_sock_t lfd = (jp_sock_t)-1;
    uint16_t port = 0;
    if (why.empty()) {
        lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (lfd == (jp_sock_t)-1 ||
            ::bind(lfd, (sockaddr*)&addr, sizeof(addr)) != 0 ||
            ::listen(lfd, 4) != 0) {
            why = "bind/listen failed";
            if (lfd != (jp_sock_t)-1) sock_close(lfd);
            lfd = (jp_sock_t)-1;
        } else {
            socklen_t alen = sizeof(addr);
            getsockname(lfd, (sockaddr*)&addr, &alen);
            port = ntohs(addr.sin_port);
        }
    }

    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::thread srv_th;
    bool srv_started = false;
    if (why.empty()) {
        srv_started = true;
        srv_th = std::thread([&] {
        pollfd pfd{ lfd, POLLIN, 0 };
        if (do_poll(&pfd, 1, 10000) <= 0) { srv_err = "accept timeout"; return; }
        jp_sock_t cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd == (jp_sock_t)-1) { srv_err = "accept failed"; return; }
        set_socket_timeouts(cfd);
                mbedtls_ssl_set_bio(&ssl, &cfd, mbed_send_cb, mbed_recv_cb, nullptr);
                while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
                    if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        srv_err = "mbedtls_accept failed: " + mbed_err(ret);
                        break;
                    }
                }
        if (srv_err.empty()) {
            if (mbedtls_ssl_get_ciphersuite_id_from_ssl(&ssl) !=
                (int)s.mbed_id) {
                srv_err = "mbedtls negotiated wrong suite";
            } else if (!mbed_exchange_all(&ssl)) {
                srv_err = "mbedtls server data exchange failed";
            } else {
                srv_ok = true;
            }
        }
        sock_close(cfd);
        });
    }

    bool ok = false;
    if (why.empty()) {
        // jpssl 客户端：证书套件走预期证书路径；PSK 套件配置 tls12 PSK。
        tls_certificate_manager cli_mgr;
        if (s.key != KEY_PSK) {
            std::string perr;
            auto expect = tls_certificate::from_pem_file(srv_cert_path(s.key),
                                                         srv_key_path(s.key), &perr);
            if (!expect) {
                srv_th.join();
                mbedtls_ssl_free(&ssl);
                mbedtls_ssl_config_free(&conf);
                mbedtls_x509_crt_free(&srvcert);
                mbedtls_pk_free(&pkey);
                if (lfd != (jp_sock_t)-1) sock_close(lfd);
                why = "jpssl from_pem: " + perr;
                return false;
            }
            cli_mgr.add_certificate("localhost", std::move(expect));
        }

        tls_connection conn;
        conn.set_tls_version(s.tls13 ? TLSVersion::V13 : TLSVersion::V12);
        conn.session().cipher_suite = s.cs;
        if (s.key == KEY_PSK) {
            tls_session& ss = conn.session();
            ss.tls12_psk_valid = true;
            ss.tls12_psk_identity_len = sizeof(kPskIdentity) - 1;
            std::memcpy(ss.tls12_psk_identity, kPskIdentity, sizeof(kPskIdentity) - 1);
            ss.tls12_psk_value_len = sizeof(kPskValue);
            std::memcpy(ss.tls12_psk_value, kPskValue, sizeof(kPskValue));
        }
        std::string err;
        if (conn.connect("localhost", port, &cli_mgr, &err)) {
            if (conn.session().cipher_suite == s.cs) {
                JpByteReader reader(conn);
                if (jp_exchange_all(conn, reader, err)) {
                    ok = true;
                } else {
                    why = "jpssl client data exchange failed: " + err;
                }
            } else {
                why = "jpssl client negotiated wrong suite";
            }
        } else {
            why = "jpssl client connect failed: " + err;
        }
    }

    if (srv_started) srv_th.join();
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    if (lfd != (jp_sock_t)-1) sock_close(lfd);
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "mbedtls server failed" : srv_err; }
    if (!ok && !why.empty() && !srv_err.empty() &&
        why.find("server:") == std::string::npos)
        why += " | server: " + srv_err;
    return ok;
}

// ============================================================
//  测试入口
// ============================================================

void test_tls_mbedtls_interop_all() {
    std::printf("\n=== jpssl <-> Mbed TLS TLS 1.2/1.3 全量互操作 ===\n");
    const char* only_suite = std::getenv("JPSSL_MBED_SUITE");
    const char* only_dir = std::getenv("JPSSL_MBED_DIR");
    int pass = 0, skip = 0, fail = 0;
    for (const Suite& s : kSuites) {
        if (only_suite && std::strcmp(only_suite, s.short_name) != 0) continue;
        const char* ver = s.tls13 ? "TLS1.3" : "TLS1.2";
        if (!only_dir || std::strcmp(only_dir, "A") == 0) {
            std::string why;
            bool r = interop_jpssl_server_mbed_client(s, why);
            std::string tag = std::string("A jpssl-server <-> mbedtls-client ") +
                              ver + " " + s.short_name;
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
        if (!only_dir || std::strcmp(only_dir, "B") == 0) {
            std::string why;
            bool r = interop_mbed_server_jpssl_client(s, why);
            std::string tag = std::string("B mbedtls-server <-> jpssl-client ") +
                              ver + " " + s.short_name;
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
    std::printf("  Mbed TLS interop: %d pass, %d skip, %d fail"
                "（%zu 套件 × 2 方向 × %zu 长度）\n",
                pass, skip, fail,
                sizeof(kSuites) / sizeof(kSuites[0]),
                sizeof(kLengths) / sizeof(kLengths[0]));
    TEST("jpssl <-> Mbed TLS TLS 1.2/1.3 全量互操作全部通过", fail == 0);
}

#ifndef JPSSL_INTEROP_NO_MAIN
int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    test_tls_mbedtls_interop_all();
    int rc = test_summary();
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
#endif
