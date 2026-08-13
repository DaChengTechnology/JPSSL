/**
 * dtls_client.cpp -- DTLS 客户端示例（UDP，收发一条消息）
 *
 * 演示 jpssl::dtls::dtls_connection 客户端流程：
 *   connect(host, port, trust_store) -> send/recv 应用数据
 *
 * 用法：
 *   dtls_client --port <port> [--host <host>] [--dtls12|--dtls13]
 *              [--cipher aes128-gcm|aes256-gcm|chacha20]
 *              [--key-share x25519|p256] [--server-name <name>]
 *              [--ca <ca.pem>] [--msg <text>]
 *
 * 默认不验证服务器证书（演示模式）；传 --ca 后按 x509 链验证服务器证书。
 *
 * 示例（与 dtls_server 配合）：
 *   ./dtls_server --port 5684 --dtls13
 *   ./dtls_client --port 5684 --dtls13 --msg "hello"
 */
#include "dtls_common.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::dtls;
using namespace jpssl::dtls_examples;

int main(int argc, char** argv) {
    arg_parser args(argc, argv);
    if (args.has("--help") || args.has("-h")) {
        std::printf(
            "usage: dtls_client --port <port> [--host <host>] [--dtls12|--dtls13]\n"
            "                  [--cipher aes128-gcm|aes256-gcm|chacha20]\n"
            "                  [--key-share x25519|p256|p384|x448]\n"
            "                  [--server-name <name>] [--ca <ca.pem>] [--msg <text>]\n");
        return 0;
    }

    uint16_t port = (uint16_t)std::atoi(args.get("--port", "0").c_str());
    if (port == 0) {
        std::fprintf(stderr, "missing --port\n");
        return 2;
    }
    std::string host = args.get("--host", "127.0.0.1");
    DTLSVersion ver = args.has("--dtls12") ? DTLSVersion::V12 : DTLSVersion::V13;

    CipherSuite cs;
    std::string cipher = args.get("--cipher", cipher_default(ver));
    if (!parse_cipher(cipher, ver, cs)) {
        std::fprintf(stderr, "unknown cipher: %s\n", cipher.c_str());
        return 2;
    }
    NamedGroup group = NamedGroup::X25519;
    std::string gs = args.get("--key-share", "x25519");
    if (!parse_group(gs, group)) {
        std::fprintf(stderr, "unknown key share group: %s\n", gs.c_str());
        return 2;
    }

    std::string msg = args.get("--msg", "hello-dtls");
    std::string server_name = args.get("--server-name", "localhost");

    // ---- 信任库（可选） ----
    tls_trust_store trust;
    bool verify = false;
    std::string ca_path = args.get("--ca");
    if (!ca_path.empty()) {
        trust = tls_trust_store::from_pem_file(ca_path.c_str());
        if (trust.ca_roots.empty()) {
            std::fprintf(stderr, "no CA roots loaded from %s\n", ca_path.c_str());
            return 2;
        }
        verify = true;
    }

    // ---- DTLS 客户端 ----
    dtls_connection cli;
    cli.set_version(ver);
    cli.set_cipher_suite(cs);
    cli.set_key_share_group(group);
    cli.set_server_name(server_name);

    if (!cli.connect(host.c_str(), port, verify ? &trust : nullptr)) {
        std::fprintf(stderr, "connect %s:%u failed: %s\n",
                     host.c_str(), port, cli.last_error().c_str());
        return 1;
    }
    print_session_info("client", cli);

    if (!cli.send((const uint8_t*)msg.data(), msg.size())) {
        std::fprintf(stderr, "send failed: %s\n", cli.last_error().c_str());
        return 1;
    }
    std::printf("client: sent %zu bytes: \"%s\"\n", msg.size(), msg.c_str());

    std::vector<uint8_t> reply;
    if (!cli.recv(reply)) {
        std::fprintf(stderr, "recv failed: %s\n", cli.last_error().c_str());
        return 1;
    }
    std::printf("client: recv %zu bytes: \"%s\"\n",
                reply.size(), std::string((const char*)reply.data(), reply.size()).c_str());

    // 通知服务端结束会话
    static const char bye[] = "bye";
    cli.send((const uint8_t*)bye, sizeof(bye) - 1);
    cli.close();
    return 0;
}
