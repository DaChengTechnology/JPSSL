/**
 * nonblocking_echo.cpp -- TLS 非阻塞 socket 事件循环示例
 *
 * 演示 jpssl::tls 封装层的非阻塞模式：
 *   - tls_listener::set_nonblocking(true)：accept() 无连接时返回 would-block，
 *     配合 wait_readable() 在事件循环中轮询。
 *   - tls_connection::set_nonblocking(true)：send()/recv() 遇 EAGAIN 立即返回
 *     false 并经 would_block() 判定，连接保持打开；配合 wait_readable()/
 *     wait_writable() 重试。
 *   - accept 出的连接 socket 继承监听器的非阻塞状态。
 *
 * 运行：./nonblocking_echo
 *
 * 流程（本机回环自演示）：
 *   1. 服务端线程启动非阻塞监听事件循环；
 *   2. 客户端非阻塞 connect + TLS 1.3 握手，发送 "ping"；
 *   3. 服务端事件循环收到后回显 "pong"；
 *   4. 客户端 wait_readable() 后 recv 拿到回显并打印。
 */
#include "tls_socket.hpp"
#include "ecdsa.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

// 生成一个 ECDSA P-256 自签证书（服务端与客户端各持一份，
// 客户端用于校验 CertificateVerify）
static std::unique_ptr<tls_certificate> make_ecdsa_cert(const uint8_t pub[64],
                                                        const uint8_t priv[32]) {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(cert->pub.ecdsa_p256, pub, 64);
    std::memcpy(cert->priv.ecdsa_p256, priv, 32);
    return cert;
}

// 非阻塞读取一条应用消息：无数据则等待可读后重试
static bool nb_recv_message(tls_connection& conn, std::string& out,
                            std::string* err) {
    std::vector<uint8_t> buf;
    for (int i = 0; i < 100; ++i) {
        if (conn.recv(buf, err)) {
            out.assign((const char*)buf.data(), buf.size());
            return true;
        }
        if (!conn.would_block()) return false; // 真实错误
        if (!conn.wait_readable(200)) break;
    }
    if (err) *err = "recv timeout";
    return false;
}

int main() {
    if (!tls_socket_init()) {
        std::fprintf(stderr, "tls_socket_init failed\n");
        return 1;
    }

    // ---- 证书 ----
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    tls_certificate_manager server_mgr, client_mgr;
    server_mgr.add_certificate("localhost", make_ecdsa_cert(pub, priv));
    client_mgr.add_certificate("localhost", make_ecdsa_cert(pub, priv));

    // ---- 非阻塞监听 ----
    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) {
        std::fprintf(stderr, "listen failed: %s\n", err.c_str());
        return 1;
    }
    if (!listener.set_nonblocking(true, &err)) {
        std::fprintf(stderr, "set_nonblocking failed: %s\n", err.c_str());
        return 1;
    }
    uint16_t port = listener.local_port();
    std::printf("listener: 127.0.0.1:%u (non-blocking, inherits to accepted conns)\n",
                port);

    // ---- 服务端：非阻塞 accept + 收发事件循环 ----
    std::atomic<bool> server_ok{false};
    std::thread server_thread([&] {
        tls_connection conn;
        for (int i = 0; i < 200; ++i) {
            std::string e;
            if (listener.accept(conn, server_mgr, &e)) {
                std::printf("server: accepted (conn non-blocking: %d)\n",
                            conn.is_nonblocking());
                std::string msg;
                if (nb_recv_message(conn, msg, &e)) {
                    std::printf("server: recv \"%s\"\n", msg.c_str());
                    // 回显：非阻塞 send，写缓冲暂满时等待可写
                    bool sent = false;
                    for (int j = 0; j < 100; ++j) {
                        if (conn.send((const uint8_t*)"pong", 4, &e)) {
                            sent = true;
                            break;
                        }
                        if (!conn.would_block()) break;
                        if (!conn.wait_writable(200)) break;
                    }
                    server_ok = sent && msg == "ping";
                    return;
                }
                std::fprintf(stderr, "server: recv failed: %s\n", e.c_str());
                return;
            }
            // 无连接：确认是 would-block 后等待监听 socket 可读
            if (!listener.would_block()) {
                std::fprintf(stderr, "server: accept failed: %s\n", e.c_str());
                return;
            }
            if (!listener.wait_readable(200)) continue;
        }
        std::fprintf(stderr, "server: accept timeout\n");
    });

    // ---- 客户端：非阻塞 connect + 握手，非阻塞收发 ----
    tls_connection client;
    if (!client.set_nonblocking(true, &err)) { // connect 之前调用
        std::fprintf(stderr, "client set_nonblocking failed: %s\n", err.c_str());
        return 1;
    }
    if (!client.connect("127.0.0.1", port, &client_mgr, &err)) {
        std::fprintf(stderr, "client connect failed: %s\n", err.c_str());
        return 1;
    }
    std::printf("client: TLS 1.3 handshake done (non-blocking: %d)\n",
                client.is_nonblocking());

    const char ping[] = "ping";
    if (!client.send((const uint8_t*)ping, 4, &err)) {
        std::fprintf(stderr, "client send failed: %s\n", err.c_str());
        return 1;
    }
    std::printf("client: sent \"ping\"\n");

    std::string reply;
    if (!nb_recv_message(client, reply, &err)) {
        std::fprintf(stderr, "client recv failed: %s\n", err.c_str());
        return 1;
    }
    std::printf("client: recv \"%s\"\n", reply.c_str());

    client.close();
    server_thread.join();
    listener.close();

    const bool ok = server_ok.load() && reply == "pong";
    std::printf("\n%s\n", ok ? "nonblocking echo: OK"
                             : "nonblocking echo: FAILED");
    return ok ? 0 : 1;
}