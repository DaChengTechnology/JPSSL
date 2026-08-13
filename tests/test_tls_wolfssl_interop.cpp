/**
 * test_tls_wolfssl_interop.cpp - jpssl <-> wolfSSL TLS 1.2 / 1.3 全量互操作
 *
 * TLS 1.3（RFC 8446 + RFC 8998 国密）：
 *   TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 /
 *   TLS_CHACHA20_POLY1305_SHA256 / TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3
 *
 * TLS 1.2（RFC 5246）：
 *   ECDHE-ECDSA / ECDHE-RSA / DHE-RSA × AES-GCM / CHACHA20 / AES-CBC
 *   DHE-PSK / PSK × AES-GCM / CHACHA20
 *
 * 每个套件 × 两个方向（A: jpssl server <-> wolfSSL client，
 * B: wolfSSL server <-> jpssl client）× 多长度数据往返
 * （1 / 100 / 1024 / 16384 / 65536 字节）。
 *
 * 需要 SM 版 wolfSSL（wolfSSL 5.x + wolfsm 实现）：
 *   cmake -DJP_WOLFSSL_PREFIX=<install>，wolfSSL 以
 *   /DWOLFSSL_SM2 /DWOLFSSL_SM3 /DWOLFSSL_SM4 /DWOLFSSL_SM4_ECB
 *   /DWOLFSSL_SM4_CBC /DWOLFSSL_SM4_CTR /DWOLFSSL_SM4_GCM
 *   /DWOLFSSL_SM4_CCM /DWOLFSSL_BASE16 构建，并把 wolfsm 的
 *   sm2.c/sm3.c/sm4.c(+头文件) 装入 wolfSSL 源码树、加入 CMake 源列表；
 *   另需 -DWOLFSSL_PSK=yes（否则 NO_PSK，PSK 套件不可用）。
 *
 * 已知 wolfSSL 5.9.2 缺陷（已打补丁）：证书链 SM2-with-SM3 验签时
 *   wc_ecc_sm2_create_digest(CERT_SIG_ID, 0, ...) 传了长度 0，
 *   而 OpenSSL 4.x 实际用完整默认 SM2 ID（"1234567812345678"）签名，
 *   导致 ASN_SIG_CONFIRM_E。补丁：wolfcrypt/src/asn.c 两处
 *   idSz 0 -> CERT_SIG_ID_SZ。
 *
 * 测试证书：
 *   tests/certs/sm2/  SM2（CA 自签 + leaf 签发均 SM2-with-SM3，CN/SAN=localhost）
 *   tests/certs/tls/  ECDSA P-256 / RSA-2048 leaf + EC CA（CN/SAN=localhost）
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "tls_socket.hpp"
#include "dh.hpp"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

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

#ifndef JPSSL_SM2_CERT_DIR
#define JPSSL_SM2_CERT_DIR "tests/certs/sm2"
#endif
#ifndef JPSSL_TLS_CERT_DIR
#define JPSSL_TLS_CERT_DIR "tests/certs/tls"
#endif

static const char* SM2_CA_CERT   = JPSSL_SM2_CERT_DIR "/ca-sm2.pem";
static const char* SM2_SRV_CERT  = JPSSL_SM2_CERT_DIR "/server-sm2-cert.pem";
static const char* SM2_SRV_KEY   = JPSSL_SM2_CERT_DIR "/server-sm2-key.pem";
static const char* TLS_CA_CERT   = JPSSL_TLS_CERT_DIR "/ca.pem";
static const char* ECDSA_SRV_CERT = JPSSL_TLS_CERT_DIR "/server-ecdsa.pem";
static const char* ECDSA_SRV_KEY  = JPSSL_TLS_CERT_DIR "/server-ecdsa-key.pem";
static const char* RSA_SRV_CERT  = JPSSL_TLS_CERT_DIR "/server-rsa.pem";
static const char* RSA_SRV_KEY   = JPSSL_TLS_CERT_DIR "/server-rsa-key.pem";

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

static std::string wolf_err(int e) {
    char buf[256];
    wolfSSL_ERR_error_string_n((unsigned long)e, buf, sizeof(buf));
    return std::string(buf);
}

// ============================================================
//  套件表
// ============================================================

enum KeyKind { KEY_SM2, KEY_ECDSA, KEY_RSA, KEY_PSK };

struct Suite {
    CipherSuite cs;
    const char* wolf_name;
    const char* iana_name;   // wolfSSL_get_cipher 返回的名称
    const char* short_name;
    bool tls13;
    KeyKind key;
};

static const Suite kSuites[] = {
    // ---- TLS 1.3 ----
    { CipherSuite::TLS_AES_128_GCM_SHA256,
      "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "AES128-GCM", true, KEY_ECDSA },
    { CipherSuite::TLS_AES_256_GCM_SHA384,
      "TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384", "AES256-GCM", true, KEY_ECDSA },
    { CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
      "TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "CHACHA20-POLY1305", true, KEY_ECDSA },
    { CipherSuite::TLS_SM4_GCM_SM3,
      "TLS_SM4_GCM_SM3", "TLS_SM4_GCM_SM3", "SM4-GCM-SM3", true, KEY_SM2 },
    { CipherSuite::TLS_SM4_CCM_SM3,
      "TLS_SM4_CCM_SM3", "TLS_SM4_CCM_SM3", "SM4-CCM-SM3", true, KEY_SM2 },
    // ---- TLS 1.2 ----
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-ECDSA-AES128-GCM-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "ECDHE-ECDSA-AES128-GCM", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      "ECDHE-ECDSA-AES256-GCM-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "ECDHE-ECDSA-AES256-GCM", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-ECDSA-CHACHA20-POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "ECDHE-ECDSA-CHACHA20", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "ECDHE-RSA-AES128-GCM", false, KEY_RSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      "ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "ECDHE-RSA-AES256-GCM", false, KEY_RSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-RSA-CHACHA20-POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "ECDHE-RSA-CHACHA20", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
      "DHE-RSA-AES128-GCM-SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
      "DHE-RSA-AES128-GCM", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
      "DHE-RSA-AES256-GCM-SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
      "DHE-RSA-AES256-GCM", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      "DHE-RSA-CHACHA20-POLY1305", "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "DHE-RSA-CHACHA20", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
      "DHE-RSA-AES128-SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
      "DHE-RSA-AES128-CBC", false, KEY_RSA },
    { CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
      "DHE-RSA-AES256-SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
      "DHE-RSA-AES256-CBC", false, KEY_RSA },
    { CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
      "DHE-PSK-AES128-GCM-SHA256", "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
      "DHE-PSK-AES128-GCM", false, KEY_PSK },
    { CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
      "DHE-PSK-AES256-GCM-SHA384", "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
      "DHE-PSK-AES256-GCM", false, KEY_PSK },
    { CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
      "DHE-PSK-CHACHA20-POLY1305", "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
      "DHE-PSK-CHACHA20", false, KEY_PSK },
    { CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
      "PSK-CHACHA20-POLY1305", "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
      "PSK-CHACHA20", false, KEY_PSK },
};

// 覆盖块/记录边界两侧的对齐与非对齐长度（8/16 字节对齐 + 前后 ±1）。
static const size_t kLengths[] = {
    1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33,
    63, 64, 65, 127, 128, 129, 255, 256, 257,
    1000, 1001, 1024, 1025,
    16383, 16384, 16385,
    65535, 65536, 65537
};

static const char kPskIdentity[] = "jpssl-wolfssl-test";
static const uint8_t kPskValue[] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00
};

// ============================================================
//  证书 / PSK 辅助
// ============================================================

static const char* srv_cert_path(KeyKind k) {
    switch (k) {
        case KEY_SM2:   return SM2_SRV_CERT;
        case KEY_ECDSA: return ECDSA_SRV_CERT;
        case KEY_RSA:   return RSA_SRV_CERT;
        default: return nullptr;
    }
}

static const char* srv_key_path(KeyKind k) {
    switch (k) {
        case KEY_SM2:   return SM2_SRV_KEY;
        case KEY_ECDSA: return ECDSA_SRV_KEY;
        case KEY_RSA:   return RSA_SRV_KEY;
        default: return nullptr;
    }
}

static const char* ca_path(KeyKind k) {
    return k == KEY_SM2 ? SM2_CA_CERT : TLS_CA_CERT;
}

static bool suite_uses_dhe(CipherSuite cs) {
    return cs == CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
           cs == CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 ||
           cs == CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
}

// 长度前缀协议：写 [4B 长度][载荷]，读回同样结构并校验。
static bool wolf_send_len_data(WOLFSSL* ssl, const uint8_t* data, size_t len) {
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),  (uint8_t)len
    };
    auto write_all = [&](const uint8_t* p, size_t n) -> bool {
        size_t sent = 0;
        while (sent < n) {
            int r = wolfSSL_write(ssl, p + sent, (int)(n - sent));
            if (r <= 0) {
                int e = wolfSSL_get_error(ssl, r);
                if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE) continue;
                return false;
            }
            sent += (size_t)r;
        }
        return true;
    };
    return write_all(hdr, 4) && write_all(data, len);
}

static bool wolf_recv_exact(WOLFSSL* ssl, uint8_t* out, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = wolfSSL_read(ssl, out + got, (int)(len - got));
        if (n <= 0) {
            int e = wolfSSL_get_error(ssl, n);
            if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        got += (size_t)n;
    }
    return true;
}

static bool wolf_exchange(WOLFSSL* ssl, size_t len) {
    std::vector<uint8_t> buf(len);
    for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)(i * 31 + 7);
    if (!wolf_send_len_data(ssl, buf.data(), len)) return false;
    uint8_t hdr[4];
    if (!wolf_recv_exact(ssl, hdr, 4)) return false;
    size_t rlen = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) |
                  ((size_t)hdr[2] << 8) | hdr[3];
    if (rlen != len) return false;
    std::vector<uint8_t> got(len);
    if (!wolf_recv_exact(ssl, got.data(), len)) return false;
    if (std::memcmp(buf.data(), got.data(), len) != 0) {
        if (std::getenv("JPSSL_WOLF_DEBUG"))
            std::fprintf(stderr, "WOLF len=%zu first_got=%02x first_exp=%02x\n",
                         len, got[0], buf[0]);
        return false;
    }
    return true;
}

// jpssl 端精确字节读取（conn.recv 可能一次返回多条记录合并数据，
// 剩余字节缓存在 reader 中供下次使用）。
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
    if (std::memcmp(buf.data(), got.data(), len) != 0) {
        if (std::getenv("JPSSL_WOLF_DEBUG"))
            std::fprintf(stderr, "JP len=%zu first_got=%02x first_exp=%02x\n",
                         len, got[0], buf[0]);
        return false;
    }
    return true;
}

// wolfSSL 端多长度往返。
static bool wolf_exchange_all(WOLFSSL* ssl) {
    for (size_t len : kLengths) {
        if (!wolf_exchange(ssl, len)) {
            if (std::getenv("JPSSL_WOLF_DEBUG"))
                std::fprintf(stderr, "WOLF_EXCHANGE_FAIL len=%zu\n", len);
            return false;
        }
    }
    return true;
}

// jpssl 端多长度往返。
static bool jp_exchange_all(tls_connection& conn, JpByteReader& reader,
                            std::string& err) {
    for (size_t len : kLengths) {
        if (!jp_exchange(conn, reader, len, err)) {
            if (std::getenv("JPSSL_WOLF_DEBUG"))
                std::fprintf(stderr, "JP_EXCHANGE_FAIL len=%zu err=%s\n",
                             len, err.c_str());
            return false;
        }
    }
    return true;
}

// ============================================================
//  wolfSSL 上下文
// ============================================================

static WOLFSSL_CTX* wolf_make_ctx(int is_server, const Suite& s) {
    WOLFSSL_METHOD* m = nullptr;
    if (s.tls13)
        m = is_server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method();
    else
        m = is_server ? wolfTLSv1_2_server_method() : wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(m);
    if (!ctx) return nullptr;
    if (wolfSSL_CTX_set_cipher_list(ctx, s.wolf_name) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return nullptr;
    }
    // RFC 8998：SM 套件要求客户端提供 curveSM2 key_share；
    // wolfSSL 默认把 PQC 混合组排在前面，这里显式设唯一 group。
    if (s.tls13 && s.key == KEY_SM2 && !is_server) {
        int sm2_group[] = { WOLFSSL_ECC_SM2P256V1 };
        if (wolfSSL_CTX_set_groups(ctx, sm2_group, 1) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return nullptr;
        }
    }
    return ctx;
}

static unsigned int psk_client_cb(WOLFSSL* ssl, const char* hint,
                                  char* identity, unsigned int id_max,
                                  unsigned char* key, unsigned int key_max) {
    (void)ssl; (void)hint;
    if (id_max < sizeof(kPskIdentity) - 1 || key_max < sizeof(kPskValue)) return 0;
    std::memcpy(identity, kPskIdentity, sizeof(kPskIdentity) - 1);
    std::memcpy(key, kPskValue, sizeof(kPskValue));
    return (unsigned int)sizeof(kPskValue);
}

static unsigned int psk_server_cb(WOLFSSL* ssl, const char* identity,
                                  unsigned char* key, unsigned int key_max) {
    (void)ssl; (void)identity;
    if (key_max < sizeof(kPskValue)) return 0;
    std::memcpy(key, kPskValue, sizeof(kPskValue));
    return (unsigned int)sizeof(kPskValue);
}

// 为 wolfSSL TLS 1.2 DHE 服务端设置 ffdhe2048 参数。
static bool wolf_set_ffdhe(WOLFSSL* ssl) {
    using jpssl::dh::ffdhe2048_p;
    using jpssl::dh::FFDHE2048_BYTES;
    static const uint8_t g = 2;
    return wolfSSL_SetTmpDH(ssl, ffdhe2048_p, FFDHE2048_BYTES, &g, 1) == WOLFSSL_SUCCESS;
}

// ============================================================
//  方向 A：jpssl 服务端 <-> wolfSSL 客户端
// ============================================================

static bool interop_jpssl_server_wolf_client(const Suite& s, std::string& why) {
    tls_psk_store psk_store;
    std::unique_ptr<tls_certificate> srv_cert;
    tls_certificate_manager cert_mgr;
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
    WOLFSSL_CTX* ctx = wolf_make_ctx(0, s);
    if (!ctx) { why = "SKIP: wolfSSL 不支持套件 " + std::string(s.short_name); }
    else {
        if (s.key != KEY_PSK) {
            if (wolfSSL_CTX_load_verify_locations(ctx, ca_path(s.key), nullptr) !=
                WOLFSSL_SUCCESS) {
                why = "wolfSSL load CA failed";
            } else {
                wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, nullptr);
            }
        }
        if (why.empty() &&
            wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "localhost", 9) !=
                WOLFSSL_SUCCESS) {
            why = "wolfSSL UseSNI failed";
        }
        if (why.empty()) {
            if (s.key == KEY_PSK)
                wolfSSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
            jp_sock_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            if (fd == (jp_sock_t)-1 ||
                ::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
                why = "wolfSSL client connect failed";
            } else {
                set_socket_timeouts(fd);
                WOLFSSL* ssl = wolfSSL_new(ctx);
                wolfSSL_set_fd(ssl, (int)fd);
                if (wolfSSL_connect(ssl) == WOLFSSL_SUCCESS) {
                    const char* got = wolfSSL_get_cipher(ssl);
                    if (got && std::strcmp(got, s.iana_name) == 0) {
                        if (wolf_exchange_all(ssl)) {
                            ok = true;
                        } else {
                            why = "wolfSSL client data exchange failed";
                        }
                    } else {
                        why = std::string("wolfSSL negotiated wrong suite: ") +
                              (got ? got : "(null)");
                    }
                } else {
                    int we = wolfSSL_get_error(ssl, -1);
                    why = "wolfSSL_connect failed: err=" + std::to_string(we) +
                          " " + wolf_err(we);
                }
                wolfSSL_free(ssl);
                sock_close(fd);
            }
        }
        wolfSSL_CTX_free(ctx);
    }

    stop = true;
    srv_th.join();
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "jpssl server failed" : srv_err; }
    if (!ok && !why.empty() && !srv_err.empty() &&
        why.find("server:") == std::string::npos)
        why += " | server: " + srv_err;
    return ok;
}

// ============================================================
//  方向 B：wolfSSL 服务端 <-> jpssl 客户端
// ============================================================

static bool interop_wolf_server_jpssl_client(const Suite& s, std::string& why) {
    WOLFSSL_CTX* ctx = wolf_make_ctx(1, s);
    if (!ctx) { why = "SKIP: wolfSSL 不支持套件 " + std::string(s.short_name); return true; }
    if (s.key == KEY_PSK) {
        wolfSSL_CTX_set_psk_server_callback(ctx, psk_server_cb);
    } else {
        if (wolfSSL_CTX_use_certificate_file(ctx, srv_cert_path(s.key),
                                             WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_use_PrivateKey_file(ctx, srv_key_path(s.key),
                                            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            why = "wolfSSL use cert/key failed";
            return false;
        }
    }

    jp_sock_t lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (lfd == (jp_sock_t)-1 ||
        ::bind(lfd, (sockaddr*)&addr, sizeof(addr)) != 0 ||
        ::listen(lfd, 4) != 0) {
        wolfSSL_CTX_free(ctx);
        sock_close(lfd);
        why = "bind/listen failed";
        return false;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (sockaddr*)&addr, &alen);
    uint16_t port = ntohs(addr.sin_port);

    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::thread srv_th([&] {
        pollfd pfd{ lfd, POLLIN, 0 };
        if (do_poll(&pfd, 1, 10000) <= 0) { srv_err = "accept timeout"; return; }
        jp_sock_t cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd == (jp_sock_t)-1) { srv_err = "accept failed"; return; }
        set_socket_timeouts(cfd);
        WOLFSSL* ssl = wolfSSL_new(ctx);
        wolfSSL_set_fd(ssl, (int)cfd);
        if (!s.tls13 && suite_uses_dhe(s.cs) && !wolf_set_ffdhe(ssl)) {
            srv_err = "wolfSSL SetTmpDH failed";
            wolfSSL_free(ssl);
            sock_close(cfd);
            return;
        }
        if (wolfSSL_accept(ssl) == WOLFSSL_SUCCESS) {
            const char* got = wolfSSL_get_cipher(ssl);
            if (got && std::strcmp(got, s.iana_name) == 0) {
                if (!wolf_exchange_all(ssl)) {
                    srv_err = "wolfSSL server data exchange failed";
                } else {
                    srv_ok = true;
                }
            } else {
                srv_err = std::string("wolfSSL negotiated wrong suite: ") +
                          (got ? got : "(null)");
            }
        } else {
            int we = wolfSSL_get_error(ssl, -1);
            srv_err = "wolfSSL_accept failed: err=" + std::to_string(we) +
                      " " + wolf_err(we);
        }
        wolfSSL_free(ssl);
        sock_close(cfd);
    });

    // jpssl 客户端：证书套件走预期证书路径（校验 ServerKeyExchange /
    // CertificateVerify 签名）；PSK 套件配置 tls12 PSK。
    tls_certificate_manager cli_mgr;
    if (s.key != KEY_PSK) {
        std::string perr;
        auto expect = tls_certificate::from_pem_file(srv_cert_path(s.key),
                                                     srv_key_path(s.key), &perr);
        if (!expect) {
            srv_th.join();
            wolfSSL_CTX_free(ctx);
            sock_close(lfd);
            why = "jpssl from_pem: " + perr;
            return false;
        }
        cli_mgr.add_certificate("localhost", std::move(expect));
    }

    bool ok = false;
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

    srv_th.join();
    wolfSSL_CTX_free(ctx);
    sock_close(lfd);
    if (ok && !srv_ok) { ok = false; why = srv_err.empty() ? "wolfSSL server failed" : srv_err; }
    if (!ok && !why.empty() && !srv_err.empty() &&
        why.find("server:") == std::string::npos)
        why += " | server: " + srv_err;
    return ok;
}

// ============================================================
//  测试入口
// ============================================================

void test_tls_wolfssl_interop_all() {
    std::printf("\n=== jpssl <-> wolfSSL TLS 1.2/1.3 全量互操作 ===\n");
    const char* only_suite = std::getenv("JPSSL_WOLF_SUITE");
    const char* only_dir = std::getenv("JPSSL_WOLF_DIR");
    int pass = 0, skip = 0, fail = 0;
    for (const Suite& s : kSuites) {
        if (only_suite && std::strcmp(only_suite, s.short_name) != 0) continue;
        const char* ver = s.tls13 ? "TLS1.3" : "TLS1.2";
        if (!only_dir || std::strcmp(only_dir, "A") == 0) {
            std::string why;
            bool r = interop_jpssl_server_wolf_client(s, why);
            std::string tag = std::string("A jpssl-server <-> wolfssl-client ") +
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
            bool r = interop_wolf_server_jpssl_client(s, why);
            std::string tag = std::string("B wolfssl-server <-> jpssl-client ") +
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
    std::printf("  wolfSSL interop: %d pass, %d skip, %d fail"
                "（%zu 套件 × 2 方向 × %zu 长度）\n",
                pass, skip, fail,
                sizeof(kSuites) / sizeof(kSuites[0]),
                sizeof(kLengths) / sizeof(kLengths[0]));
    TEST("jpssl <-> wolfSSL TLS 1.2/1.3 全量互操作全部通过", fail == 0);
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
    test_tls_wolfssl_interop_all();
    int rc = test_summary();
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
#endif
