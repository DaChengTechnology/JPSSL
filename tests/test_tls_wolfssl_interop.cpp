/**
 * test_tls_wolfssl_interop.cpp - jpssl TLS 1.3 <-> wolfSSL TLS 1.3
 * 国密互通测试（SM2-SM4-SM3，RFC 8998）
 *
 *   方向 A：jpssl 服务端（SM2 证书，SM2-SM3 CertificateVerify）
 *           <-> wolfSSL 客户端（CA 链校验 + curveSM2 密钥交换）
 *   方向 B：wolfSSL 服务端（SM2 证书，SM2-SM3 CertificateVerify）
 *           <-> jpssl 客户端（预期 SM2 证书校验 CertificateVerify）
 *
 *   套件：TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3
 *
 * 需要 SM 版 wolfSSL（wolfSSL 5.x + wolfsm 实现）：
 *   cmake -DJP_WOLFSSL_PREFIX=<install>，wolfSSL 以
 *   /DWOLFSSL_SM2 /DWOLFSSL_SM3 /DWOLFSSL_SM4 /DWOLFSSL_SM4_ECB
 *   /DWOLFSSL_SM4_CBC /DWOLFSSL_SM4_CTR /DWOLFSSL_SM4_GCM
 *   /DWOLFSSL_SM4_CCM /DWOLFSSL_BASE16 构建，并把 wolfsm 的
 *   sm2.c/sm3.c/sm4.c(+头文件) 装入 wolfSSL 源码树、加入 CMake 源列表。
 *
 * 已知 wolfSSL 5.9.2 缺陷（已打补丁）：证书链 SM2-with-SM3 验签时
 *   wc_ecc_sm2_create_digest(CERT_SIG_ID, 0, ...) 传了长度 0，
 *   而 OpenSSL 4.x 实际用完整默认 SM2 ID（"1234567812345678"）签名，
 *   导致 ASN_SIG_CONFIRM_E。补丁：wolfcrypt/src/asn.c 两处
 *   idSz 0 -> CERT_SIG_ID_SZ。
 *
 * 测试证书：tests/certs/sm2/（SM2 密钥，CA 自签 + leaf 签名均为
 * SM2-with-SM3；leaf SPKI 为 id-ecPublicKey + SM2 曲线参数，CN/SAN=localhost）。
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "tls_socket.hpp"
#include "sm2.hpp"

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

static const char* SM2_CA_CERT = JPSSL_SM2_CERT_DIR "/ca-sm2.pem";
static const char* SM2_SERVER_CERT = JPSSL_SM2_CERT_DIR "/server-sm2-cert.pem";
static const char* SM2_SERVER_KEY = JPSSL_SM2_CERT_DIR "/server-sm2-key.pem";

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

static void set_socket_timeouts(jp_sock_t fd, int seconds = 8) {
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
//  wolfSSL 上下文辅助
// ============================================================

static WOLFSSL_CTX* wolf_tls13_ctx(int is_server, const char* cs_name) {
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(is_server ? wolfTLSv1_3_server_method()
                                                : wolfTLSv1_3_client_method());
    if (!ctx) return nullptr;
    if (wolfSSL_CTX_set_cipher_list(ctx, cs_name) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return nullptr;
    }
    // RFC 8998：SM 套件要求客户端提供 curveSM2 key_share。
    // wolfSSL 默认会把 PQC 混合组（如 X25519MLKEM768）排在前面，
    // 这里显式把 curveSM2 设为唯一 group。
    if (!is_server) {
        int sm2_group[] = { WOLFSSL_ECC_SM2P256V1 };
        if (wolfSSL_CTX_set_groups(ctx, sm2_group, 1) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return nullptr;
        }
    }
    return ctx;
}

static const char* cs_short(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_SM4_GCM_SM3: return "SM4-GCM-SM3";
        case CipherSuite::TLS_SM4_CCM_SM3: return "SM4-CCM-SM3";
        default: return "?";
    }
}

static const char* wolf_cs_name(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_SM4_GCM_SM3: return "TLS_SM4_GCM_SM3";
        case CipherSuite::TLS_SM4_CCM_SM3: return "TLS_SM4_CCM_SM3";
        default: return nullptr;
    }
}

// ============================================================
//  方向 A：jpssl 服务端 <-> wolfSSL 客户端
// ============================================================

static bool interop_jpssl_server_wolf_client(CipherSuite cs, std::string& why) {
    // jpssl 服务端：SM2 证书 + 私钥（与测试资产一致）。
    std::string perr;
    auto srv_cert = tls_certificate::from_pem_file(SM2_SERVER_CERT, SM2_SERVER_KEY, &perr);
    if (!srv_cert) { why = "jpssl from_pem: " + perr; return false; }
    if (srv_cert->sig_alg != SignatureAlgorithm::SM2_SM3) {
        why = "jpssl cert is not SM2";
        return false;
    }
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", std::move(srv_cert));

    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) { why = "jpssl listen: " + err; return false; }
    uint16_t port = listener.local_port();

    // wolfSSL 客户端线程。
    std::string srv_err;
    std::atomic<bool> srv_ok{false};
    std::atomic<bool> stop{false};
    std::thread srv_th([&] {
        for (int i = 0; i < 80 && !stop.load(); ++i) {
            if (listener.wait_readable(100)) break;
        }
        if (stop.load()) return;
        tls_connection conn;
        if (!listener.accept(conn, cert_mgr, &err)) { srv_err = "accept: " + err; return; }
        if (conn.session().cipher_suite != cs) {
            srv_err = "jpssl server negotiated wrong suite";
            return;
        }
        std::vector<uint8_t> buf;
        if (!conn.recv(buf, &err)) { srv_err = "recv: " + err; return; }
        static const char expect[] = "ping-from-wolfssl-client";
        static const char resp[] = "pong-from-jpssl-server";
        if (buf.size() != sizeof(expect) - 1 ||
            std::memcmp(buf.data(), expect, sizeof(expect) - 1) != 0) {
            srv_err = "jpssl server recv mismatch";
            return;
        }
        if (!conn.send((const uint8_t*)resp, sizeof(resp) - 1, &err)) {
            srv_err = "send: " + err;
            return;
        }
        srv_ok = true;
    });

    bool ok = false;
    WOLFSSL_CTX* ctx = wolf_tls13_ctx(0, wolf_cs_name(cs));
    if (!ctx) { why = "SKIP: wolfSSL 不支持套件 " + std::string(cs_short(cs)); }
    else {
        if (std::getenv("JPSSL_WOLF_DEBUG"))
            wolfSSL_Debugging_ON();
        if (wolfSSL_CTX_load_verify_locations(ctx, SM2_CA_CERT, nullptr) != WOLFSSL_SUCCESS) {
            why = "wolfSSL load CA failed";
        } else {
            wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, nullptr);
            if (wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "localhost", 9) != WOLFSSL_SUCCESS) {
                why = "wolfSSL UseSNI failed";
            } else {
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
                        if (got && std::strcmp(got, wolf_cs_name(cs)) == 0) {
                            static const char ping[] = "ping-from-wolfssl-client";
                            static const char expect[] = "pong-from-jpssl-server";
                            char rbuf[64] = {0};
                            if (wolfSSL_write(ssl, ping, (int)sizeof(ping) - 1) == (int)sizeof(ping) - 1 &&
                                wolfSSL_read(ssl, rbuf, (int)sizeof(rbuf) - 1) > 0 &&
                                std::memcmp(rbuf, expect, sizeof(expect) - 1) == 0) {
                                ok = true;
                            } else {
                                why = "wolfSSL data exchange failed";
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

static bool interop_wolf_server_jpssl_client(CipherSuite cs, std::string& why) {
    const char* cs_name = wolf_cs_name(cs);
    if (!cs_name) { why = "no wolfSSL suite name"; return false; }

    WOLFSSL_CTX* ctx = wolf_tls13_ctx(1, cs_name);
    if (!ctx) { why = "SKIP: wolfSSL 不支持套件 " + std::string(cs_short(cs)); return true; }
    if (wolfSSL_CTX_use_certificate_file(ctx, SM2_SERVER_CERT, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, SM2_SERVER_KEY, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        why = "wolfSSL use cert/key failed";
        return false;
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
        if (do_poll(&pfd, 1, 8000) <= 0) { srv_err = "accept timeout"; return; }
        jp_sock_t cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd == (jp_sock_t)-1) { srv_err = "accept failed"; return; }
        set_socket_timeouts(cfd);
        WOLFSSL* ssl = wolfSSL_new(ctx);
        wolfSSL_set_fd(ssl, (int)cfd);
        if (wolfSSL_accept(ssl) == WOLFSSL_SUCCESS) {
            const char* got = wolfSSL_get_cipher(ssl);
            if (got && std::strcmp(got, wolf_cs_name(cs)) == 0) {
                static const char expect[] = "ping-from-jpssl-client";
                static const char resp[] = "pong-from-wolfssl-server";
                char rbuf[64] = {0};
                if (wolfSSL_read(ssl, rbuf, (int)sizeof(rbuf) - 1) == (int)sizeof(expect) - 1 &&
                    std::memcmp(rbuf, expect, sizeof(expect) - 1) == 0 &&
                    wolfSSL_write(ssl, resp, (int)sizeof(resp) - 1) == (int)sizeof(resp) - 1) {
                    srv_ok = true;
                } else {
                    srv_err = "wolfSSL server data exchange failed";
                }
            } else {
                srv_err = std::string("wolfSSL negotiated wrong suite: ") +
                          (got ? got : "(null)");
            }
        } else {
            srv_err = "wolfSSL_accept failed: " +
                      wolf_err(wolfSSL_get_error(ssl, 0));
        }
        wolfSSL_free(ssl);
        sock_close(cfd);
    });

    // jpssl 客户端：预期 SM2 证书（解析同一份测试资产），
    // 校验服务端 SM2-SM3 CertificateVerify。
    std::string perr;
    auto expect_cert = tls_certificate::from_pem_file(SM2_SERVER_CERT, SM2_SERVER_KEY, &perr);
    if (!expect_cert) {
        srv_th.join();
        wolfSSL_CTX_free(ctx);
        sock_close(lfd);
        why = "jpssl from_pem: " + perr;
        return false;
    }
    tls_certificate_manager cli_mgr;
    cli_mgr.add_certificate("localhost", std::move(expect_cert));

    bool ok = false;
    tls_connection conn;
    conn.session().cipher_suite = cs;
    std::string err;
    if (conn.connect("localhost", port, &cli_mgr, &err)) {
        if (conn.session().cipher_suite == cs) {
            static const char ping[] = "ping-from-jpssl-client";
            static const char expect_resp[] = "pong-from-wolfssl-server";
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

void test_tls13_sm_wolfssl_interop() {
    std::printf("\n=== TLS 1.3 SM2-SM4-SM3 x wolfSSL 互操作 ===\n");
    const CipherSuite suites[] = {
        CipherSuite::TLS_SM4_GCM_SM3,
        CipherSuite::TLS_SM4_CCM_SM3,
    };
    int pass = 0, skip = 0, fail = 0;
    for (CipherSuite cs : suites) {
        const char* name = cs_short(cs);
        {
            std::string why;
            bool r = interop_jpssl_server_wolf_client(cs, why);
            std::string tag = std::string("A jpssl-server <-> wolfssl-client ") + name;
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
        {
            std::string why;
            bool r = interop_wolf_server_jpssl_client(cs, why);
            std::string tag = std::string("B wolfssl-server <-> jpssl-client ") + name;
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
    std::printf("  wolfSSL interop: %d pass, %d skip, %d fail\n", pass, skip, fail);
    TEST("TLS 1.3 SM2-SM4-SM3 wolfSSL 互操作全部通过", fail == 0);
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
    test_tls13_sm_wolfssl_interop();
    int rc = test_summary();
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
#endif
