/**
 * bench_tls13_rsa_handshake.cpp -- TLS 1.3 + RSA-2048 证书：新建连接速率基准
 *
 * 测量"新建连接速率"（完整 TLS 1.3 握手 conn/s）：
 *   - 服务端：tls_listener 单线程循环 accept（每次完成服务端握手）
 *   - 客户端：多线程并发 connect（TCP + TLS 1.3 完整握手）
 *   - RSA-2048 证书；TLS 1.3 下 CertificateVerify 自动使用 RSA-PSS
 *
 * 用法: bench_tls13_rsa_handshake [connections] [client_threads]
 */
#include "tls_socket.hpp"
#include "rsa.hpp"
#include "jpssl_memory.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

int main(int argc, char** argv) {
    const int total = argc > 1 ? std::atoi(argv[1]) : 200;
    const int nthreads = argc > 2 ? std::atoi(argv[2]) : 4;
    const int warmup_n = 5;
    if (total < 1 || nthreads < 1) {
        std::printf("usage: %s [connections] [client_threads]\n", argv[0]);
        return 1;
    }

    std::string err;
    if (!tls_socket_init(&err)) {
        std::printf("socket init failed: %s\n", err.c_str());
        return 1;
    }

    // RSA-2048 证书（服务端与客户端信任库各一份）。
    rsa_public_key rsa_pub;
    rsa_private_key rsa_priv;
    if (!rsa_keygen(rsa_pub, rsa_priv)) {
        std::printf("rsa_keygen failed\n");
        return 1;
    }

    tls_certificate_manager server_mgr, client_mgr;
    for (int i = 0; i < 2; ++i) {
        std::unique_ptr<tls_certificate> c = jpssl::make_unique<tls_certificate>();
        c->subject_name = "localhost";
        c->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
        c->pub.rsa = rsa_pub;
        c->priv.rsa = rsa_priv;
        (i == 0 ? server_mgr : client_mgr).add_certificate("localhost",
                                                            std::move(c));
    }

    tls_listener listener;
    if (!listener.listen(0, "127.0.0.1", &err)) {
        std::printf("listen failed: %s\n", err.c_str());
        return 1;
    }
    const uint16_t port = listener.local_port();

    std::atomic<int> accepted(0);
    std::atomic<bool> server_ok(true);
    std::thread server([&] {
        std::string e;
        // warmup 连接也由同一服务端线程 accept，总额为 total + warmup_n。
        while (accepted.load() < total + warmup_n) {
            tls_connection conn;
            if (!listener.accept(conn, server_mgr, &e)) {
                std::printf("accept failed: %s\n", e.c_str());
                server_ok.store(false);
                return;
            }
            conn.close();
            accepted.fetch_add(1);
        }
    });

    // 预热（首次路径等一次性开销不计入；服务端线程已就绪）。
    {
        std::string e;
        for (int i = 0; i < 5; ++i) {
            tls_connection conn;
            if (!conn.connect("127.0.0.1", port, &client_mgr, &e)) {
                std::printf("warmup connect failed: %s\n", e.c_str());
                return 1;
            }
            conn.close();
        }
    }

    std::atomic<int> connected(0);
    std::atomic<bool> client_ok(true);
    const std::chrono::steady_clock::time_point t0 =
        std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    for (int t = 0; t < nthreads; ++t) {
        const int per = total / nthreads + (t < total % nthreads ? 1 : 0);
        workers.push_back(std::thread([&, per] {
            std::string e;
            for (int i = 0; i < per; ++i) {
                tls_connection conn;
                if (!conn.connect("127.0.0.1", port, &client_mgr, &e)) {
                    std::printf("connect failed: %s\n", e.c_str());
                    client_ok.store(false);
                    return;
                }
                conn.close();
                connected.fetch_add(1);
            }
        }));
    }
    for (size_t i = 0; i < workers.size(); ++i) workers[i].join();
    const std::chrono::steady_clock::time_point t1 =
        std::chrono::steady_clock::now();
    server.join();

    const double sec = std::chrono::duration<double>(t1 - t0).count();
    const int ok = connected.load();
    std::printf("\n=== TLS 1.3 + RSA-2048 handshake rate (MSVC C++14 mode) ===\n");
    std::printf("connections : %d\n", total);
    std::printf("threads     : %d\n", nthreads);
    std::printf("elapsed     : %.3f s\n", sec);
    std::printf("rate        : %.1f conn/s\n", sec > 0 ? ok / sec : 0.0);
    std::printf("server_ok   : %s\n", server_ok.load() ? "yes" : "no");
    std::printf("client_ok   : %s\n", client_ok.load() ? "yes" : "no");
    std::printf("failed      : %d\n", total - ok);
    return (server_ok.load() && client_ok.load() && ok == total) ? 0 : 1;
}
