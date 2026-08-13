/**
 * test_tls_rustls_interop.cpp - jpssl <-> rustls TLS 1.2 / 1.3 全量互操作
 *
 * rustls 0.23（ring provider）支持的套件全集：
 *   TLS 1.3（RFC 8446）：
 *     TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 /
 *     TLS_CHACHA20_POLY1305_SHA256
 *   TLS 1.2（RFC 5246）：
 *     ECDHE-ECDSA / ECDHE-RSA × AES-128/256-GCM / CHACHA20
 *   （rustls 不提供 CBC、静态 RSA、DHE-RSA、PSK、AES-CCM 套件）
 *
 * 每个套件 × 两个方向（A: jpssl server <-> rustls client，
 * B: rustls server <-> jpssl client）× 31 种长度
 * （含大量非 8/16 字节对齐边界：1..17、31/32/33、63/64/65、127/128/129、
 * 255/256/257、1023/1024/1025、16383/16384/16385、65535/65536/65537）。
 *
 * rustls 端由独立 Rust 程序 tools/rustls_interop 实现（cargo 构建），
 * 通过 -DJP_RUSTLS_TOOL=<exe> 或环境变量 JPSSL_RUSTLS_BIN 指定路径；
 * CTest 通过 argv[1] 传入。
 *
 * 测试证书：tests/certs/tls/（EC P-256 CA + ECDSA/RSA leaf，CN/SAN=localhost）。
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "tls_socket.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#endif

using namespace jpssl;
using namespace jpssl::tls;

#ifndef JPSSL_TLS_CERT_DIR
#define JPSSL_TLS_CERT_DIR "tests/certs/tls"
#endif

static const char* RL_CA_CERT    = JPSSL_TLS_CERT_DIR "/ca.pem";
static const char* RL_ECDSA_CERT = JPSSL_TLS_CERT_DIR "/server-ecdsa.pem";
static const char* RL_ECDSA_KEY  = JPSSL_TLS_CERT_DIR "/server-ecdsa-key.pem";
static const char* RL_RSA_CERT   = JPSSL_TLS_CERT_DIR "/server-rsa.pem";
static const char* RL_RSA_KEY    = JPSSL_TLS_CERT_DIR "/server-rsa-key.pem";

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

// ============================================================
//  套件表（rustls 0.23 ring provider 实际支持的全集）
// ============================================================

enum KeyKind { KEY_ECDSA, KEY_RSA };

struct Suite {
    CipherSuite cs;
    const char* short_name;
    bool tls13;
    KeyKind key;
};

static const Suite kSuites[] = {
    // ---- TLS 1.3 ----
    { CipherSuite::TLS_AES_128_GCM_SHA256, "AES128-GCM", true, KEY_ECDSA },
    { CipherSuite::TLS_AES_256_GCM_SHA384, "AES256-GCM", true, KEY_ECDSA },
    { CipherSuite::TLS_CHACHA20_POLY1305_SHA256, "CHACHA20-POLY1305", true, KEY_ECDSA },
    // ---- TLS 1.2 ----
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-ECDSA-AES128-GCM", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      "ECDHE-ECDSA-AES256-GCM", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-ECDSA-CHACHA20", false, KEY_ECDSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-RSA-AES128-GCM", false, KEY_RSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      "ECDHE-RSA-AES256-GCM", false, KEY_RSA },
    { CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-RSA-CHACHA20", false, KEY_RSA },
};

static const size_t kLengths[] = {
    1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33,
    63, 64, 65, 127, 128, 129, 255, 256, 257,
    1000, 1001, 1024, 1025,
    16383, 16384, 16385,
    65535, 65536, 65537
};

static const char* rl_srv_cert_path(KeyKind k) {
    return k == KEY_ECDSA ? RL_ECDSA_CERT : RL_RSA_CERT;
}

static const char* rl_srv_key_path(KeyKind k) {
    return k == KEY_ECDSA ? RL_ECDSA_KEY : RL_RSA_KEY;
}

// ============================================================
//  jpssl 端数据往返（长度前缀协议）
// ============================================================

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
//  rustls 助手进程启动
// ============================================================

static std::string g_rustls_tool;

static const std::string& rustls_tool_path(int argc, char** argv) {
    if (!g_rustls_tool.empty()) return g_rustls_tool;
    const char* env = std::getenv("JPSSL_RUSTLS_BIN");
    if (env && *env) { g_rustls_tool = env; return g_rustls_tool; }
    if (argc > 1 && argv[1] && *argv[1]) { g_rustls_tool = argv[1]; return g_rustls_tool; }
    g_rustls_tool = "rustls_interop";
    return g_rustls_tool;
}

#ifdef _WIN32
static std::wstring utf8_to_utf16(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}
#endif

static bool run_process(const std::string& exe,
                        const std::vector<std::string>& args,
                        std::string& err, int& exit_code) {
#ifdef _WIN32
    std::string cmd = "\"" + exe + "\"";
    for (const auto& a : args) cmd += " \"" + a + "\"";
    std::wstring wcmd = utf8_to_utf16(cmd);
    std::vector<wchar_t> wbuf(wcmd.begin(), wcmd.end());
    wbuf.push_back(0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, wbuf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        err = "CreateProcess failed: " + std::to_string(GetLastError());
        return false;
    }
    CloseHandle(pi.hThread);
    DWORD wait = WaitForSingleObject(pi.hProcess, 60000);
    bool timed_out = wait == WAIT_TIMEOUT;
    if (timed_out) TerminateProcess(pi.hProcess, 1);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    if (timed_out) { err = "rustls process timeout"; return false; }
    exit_code = (int)code;
    return true;
#else
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(exe.c_str()));
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    pid_t pid = fork();
    if (pid < 0) { err = "fork failed"; return false; }
    if (pid == 0) {
        execvp(exe.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    for (int i = 0; i < 600; ++i) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status)) { exit_code = WEXITSTATUS(status); return true; }
            err = "rustls process crashed";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ::kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    err = "rustls process timeout";
    return false;
#endif
}

static bool rustls_client_run(const std::string& addr, const Suite& s,
                              const std::string& ca, std::string& err) {
    std::vector<std::string> args = {
        "client",
        "--addr", addr,
        "--suite", s.short_name,
        "--version", s.tls13 ? "1.3" : "1.2",
        "--ca", ca
    };
    int code = -1;
    if (!run_process(rustls_tool_path(0, nullptr), args, err, code))
        return false;
    if (code != 0) { err = "rustls client exited " + std::to_string(code); return false; }
    return true;
}

static bool rustls_server_run(uint16_t port, const Suite& s,
                              const std::string& cert, const std::string& key,
                              std::string& err) {
    std::vector<std::string> args = {
        "server",
        "--port", std::to_string(port),
        "--suite", s.short_name,
        "--version", s.tls13 ? "1.3" : "1.2",
        "--cert", cert,
        "--key", key
    };
    int code = -1;
    if (!run_process(rustls_tool_path(0, nullptr), args, err, code))
        return false;
    if (code != 0) { err = "rustls server exited " + std::to_string(code); return false; }
    return true;
}

// 取一个空闲端口（探测后立即关闭；测试场景下竞态可忽略）
static bool probe_free_port(uint16_t& port, std::string& err) {
    jp_sock_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd == (jp_sock_t)-1) { err = "socket failed"; return false; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::bind(fd, (sockaddr*)&addr, sizeof(addr)) != 0 ||
        ::listen(fd, 1) != 0) {
        sock_close(fd);
        err = "bind failed";
        return false;
    }
    socklen_t alen = sizeof(addr);
    getsockname(fd, (sockaddr*)&addr, &alen);
    port = ntohs(addr.sin_port);
    sock_close(fd);
    return true;
}

// ============================================================
//  方向 A：jpssl 服务端 <-> rustls 客户端
// ============================================================

static bool interop_jpssl_server_rustls_client(const Suite& s, std::string& why) {
    std::string perr;
    auto srv_cert = tls_certificate::from_pem_file(rl_srv_cert_path(s.key),
                                                   rl_srv_key_path(s.key), &perr);
    if (!srv_cert) { why = "jpssl from_pem: " + perr; return false; }
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", std::move(srv_cert));

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
        bool accepted = listener.accept(conn, cert_mgr, &err);
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

    std::string addr = "127.0.0.1:" + std::to_string(port);
    std::string rerr;
    bool rustls_ok = rustls_client_run(addr, s, RL_CA_CERT, rerr);

    stop = true;
    srv_th.join();
    if (rustls_ok && !srv_ok) {
        rustls_ok = false;
        rerr = srv_err.empty() ? "jpssl server failed" : srv_err;
    }
    if (!rustls_ok) why = rerr;
    return rustls_ok;
}

// ============================================================
//  方向 B：rustls 服务端 <-> jpssl 客户端
// ============================================================

static bool interop_rustls_server_jpssl_client(const Suite& s, std::string& why) {
    uint16_t port = 0;
    std::string err;
    if (!probe_free_port(port, err)) { why = "probe port: " + err; return false; }

    std::string serr;
    std::atomic<bool> srv_done{false};
    std::atomic<bool> srv_ok{false};
    // rustls 服务端进程需等 jpssl 客户端连接后才退出，
    // 因此必须在后台线程中等待其退出，主线程同时发起客户端连接。
    std::thread srv_th([&] {
        srv_ok = rustls_server_run(port, s, rl_srv_cert_path(s.key),
                                   rl_srv_key_path(s.key), serr);
        srv_done = true;
    });

    std::string perr;
    auto expect = tls_certificate::from_pem_file(rl_srv_cert_path(s.key),
                                                 rl_srv_key_path(s.key), &perr);
    if (!expect) {
        srv_th.join();
        why = "jpssl from_pem: " + perr;
        return false;
    }
    tls_certificate_manager cli_mgr;
    cli_mgr.add_certificate("localhost", std::move(expect));

    bool ok = false;
    std::string cerr;
    for (int i = 0; i < 100 && !srv_done.load(); ++i) {
        tls_connection conn;
        conn.set_tls_version(s.tls13 ? TLSVersion::V13 : TLSVersion::V12);
        conn.session().cipher_suite = s.cs;
        if (conn.connect("localhost", port, &cli_mgr, &cerr)) {
            if (conn.session().cipher_suite == s.cs) {
                JpByteReader reader(conn);
                if (jp_exchange_all(conn, reader, cerr)) {
                    ok = true;
                } else {
                    why = "jpssl client data exchange failed: " + cerr;
                }
            } else {
                why = "jpssl client negotiated wrong suite";
            }
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!ok && why.empty())
        why = "jpssl client connect failed: " + cerr;

    srv_th.join();
    if (ok && !srv_ok) {
        ok = false;
        why = serr.empty() ? "rustls server failed" : serr;
    } else if (!ok && !serr.empty() && why.find("server:") == std::string::npos) {
        why += " | rustls: " + serr;
    }
    return ok;
}

// ============================================================
//  测试入口
// ============================================================

void test_tls_rustls_interop_all(int argc, char** argv) {
    std::printf("\n=== jpssl <-> rustls TLS 1.2/1.3 全量互操作 ===\n");
    std::printf("    rustls tool: %s\n", rustls_tool_path(argc, argv).c_str());
    const char* only_suite = std::getenv("JPSSL_RUSTLS_SUITE");
    const char* only_dir = std::getenv("JPSSL_RUSTLS_DIR");
    int pass = 0, fail = 0;
    for (const Suite& s : kSuites) {
        if (only_suite && std::strcmp(only_suite, s.short_name) != 0) continue;
        const char* ver = s.tls13 ? "TLS1.3" : "TLS1.2";
        if (!only_dir || std::strcmp(only_dir, "A") == 0) {
            std::string why;
            bool r = interop_jpssl_server_rustls_client(s, why);
            std::string tag = std::string("A jpssl-server <-> rustls-client ") +
                              ver + " " + s.short_name;
            if (r) {
                ++pass;
                std::cout << "  \xE2\x9C\x93 " << tag << std::endl;
            } else {
                ++fail;
                std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl;
            }
        }
        if (!only_dir || std::strcmp(only_dir, "B") == 0) {
            std::string why;
            bool r = interop_rustls_server_jpssl_client(s, why);
            std::string tag = std::string("B rustls-server <-> jpssl-client ") +
                              ver + " " + s.short_name;
            if (r) {
                ++pass;
                std::cout << "  \xE2\x9C\x93 " << tag << std::endl;
            } else {
                ++fail;
                std::cout << "  \xE2\x9C\x97 " << tag << " - " << why << std::endl;
            }
        }
    }
    std::printf("  rustls interop: %d pass, %d fail"
                "（%zu 套件 × 2 方向 × %zu 长度）\n",
                pass, fail,
                sizeof(kSuites) / sizeof(kSuites[0]),
                sizeof(kLengths) / sizeof(kLengths[0]));
    TEST("jpssl <-> rustls TLS 1.2/1.3 全量互操作全部通过", fail == 0);
}

#ifndef JPSSL_INTEROP_NO_MAIN
int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    test_tls_rustls_interop_all(argc, argv);
    int rc = test_summary();
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
#endif
