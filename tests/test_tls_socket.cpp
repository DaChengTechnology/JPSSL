/**
 * test_tls_socket.cpp -- TLS socket 封装层回环测试（Windows / Linux）
 *
 * 覆盖：
 *   1. tls_listener 监听 + tls_connection 服务端握手（TLS 1.3）
 *   2. tls_connection 客户端握手（TLS 1.3）
 *   3. 握手后应用数据双向收发（加密 record 往返）
 */
#include "tls_socket.hpp"
#include "ecdsa.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; std::exit(1); } \
} while (0)

static std::unique_ptr<tls_certificate> make_server_cert(const uint8_t pub[64],
                                                         const uint8_t priv[32]) {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(cert->pub.ecdsa_p256, pub, 64);
    std::memcpy(cert->priv.ecdsa_p256, priv, 32);
    return cert;
}

static void test_socket_roundtrip() {
    std::printf("\n=== TLS socket loopback ===\n");

    // 服务端与客户端各持一份相同密钥的证书（客户端用于校验 CertificateVerify）
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    tls_certificate_manager server_mgr, client_mgr;
    server_mgr.add_certificate("localhost", make_server_cert(pub, priv));
    client_mgr.add_certificate("localhost", make_server_cert(pub, priv));

    // 监听临时端口
    tls_listener listener;
    std::string err;
    TEST("listener listen", listener.listen(0, "127.0.0.1", &err));
    uint16_t port = listener.local_port();
    TEST("listener port assigned", port != 0);

    // 服务端线程：accept + 握手 + 收 "hello from client" + 回 "hello from server"
    struct server_result {
        bool accepted = false;
        bool got_hello = false;
        bool sent_ok = false;
        std::string recv_text;
    } sr;
    std::thread server_thread([&] {
        tls_connection conn;
        std::string e;
        if (!listener.accept(conn, server_mgr, &e)) return;
        sr.accepted = true;
        std::vector<uint8_t> plain;
        if (conn.recv(plain, &e)) {
            sr.recv_text.assign((const char*)plain.data(), plain.size());
            sr.got_hello = (sr.recv_text == "hello from client");
        }
        const char resp[] = "hello from server";
        sr.sent_ok = conn.send((const uint8_t*)resp, sizeof(resp) - 1, &e);
    });

    // 客户端：connect + 握手 + 发 "hello from client" + 收响应
    tls_connection client;
    TEST("client connect+handshake", client.connect("127.0.0.1", port, &client_mgr, &err));
    const char msg[] = "hello from client";
    TEST("client send", client.send((const uint8_t*)msg, sizeof(msg) - 1, &err));
    std::vector<uint8_t> resp;
    TEST("client recv", client.recv(resp, &err));
    std::string resp_text((const char*)resp.data(), resp.size());
    TEST("client got server reply", resp_text == "hello from server");
    client.close();

    server_thread.join();
    TEST("server accepted", sr.accepted);
    TEST("server got client hello", sr.got_hello);
    TEST("server sent reply", sr.sent_ok);
    listener.close();
}

int main() {
    std::string err;
    TEST("socket init", tls_socket_init(&err));
    test_socket_roundtrip();

    std::printf("\n================================================\n");
    std::printf("  Result: %d passed, %d failed", pass, fail);
    std::printf(fail == 0 ? " OK\n" : " FAILED\n");
    std::printf("================================================\n");
    return fail > 0 ? 1 : 0;
}
