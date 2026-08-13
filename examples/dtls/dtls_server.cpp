/**
 * dtls_server.cpp -- DTLS 服务器示例（UDP，回显）
 *
 * 演示 jpssl::dtls::dtls_connection 服务端流程：
 *   bind(port) -> server_handshake(cert_mgr) -> recv/send 应用数据
 *
 * 用法：
 *   dtls_server [--port <port>] [--dtls12|--dtls13] [--cipher aes128-gcm|aes256-gcm|chacha20]
 *              [--key-share x25519|p256] [--cookie] [--cert <pem> --key <pem>]
 *
 * 默认在内存生成 ECDSA P-256 自签证书，无需任何证书文件即可演示；
 * 生产环境请用 --cert/--key 加载真实证书，并让客户端用 --ca 验证。
 *
 * 示例（与 dtls_client 配合）：
 *   ./dtls_server --port 5684 --dtls13
 *   ./dtls_client --port 5684 --dtls13 --msg "hello"
 */
#include "dtls_common.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::dtls;
using namespace jpssl::dtls_examples;

int main(int argc, char** argv) {
    arg_parser args(argc, argv);
    if (args.has("--help") || args.has("-h")) {
        std::printf(
            "usage: dtls_server [--port <port>] [--dtls12|--dtls13]\n"
            "                  [--cipher aes128-gcm|aes256-gcm|chacha20]\n"
            "                  [--key-share x25519|p256|p384|x448] [--cookie]\n"
            "                  [--cert <pem> --key <pem>] [--host <ip>]\n");
        return 0;
    }

    DTLSVersion ver = args.has("--dtls12") ? DTLSVersion::V12 : DTLSVersion::V13;
    uint16_t port = (uint16_t)std::atoi(args.get("--port", "0").c_str());
    std::string host = args.get("--host", "0.0.0.0");

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

    // ---- 证书：优先加载 PEM，否则内存生成自签证书 ----
    tls_certificate_manager cert_mgr;
    std::string err;
    std::string cert_path = args.get("--cert");
    std::string key_path = args.get("--key");
    if (!cert_path.empty() || !key_path.empty()) {
        if (cert_path.empty() || key_path.empty() ||
            !load_cert_files(cert_path.c_str(), key_path.c_str(), cert_mgr, err)) {
            std::fprintf(stderr, "load cert failed: %s\n",
                         err.empty() ? "need both --cert and --key" : err.c_str());
            return 2;
        }
        std::printf("server: loaded cert %s / key %s\n",
                    cert_path.c_str(), key_path.c_str());
    } else {
        auto cert = make_self_signed_ecdsa_cert();
        std::printf("server: generated in-memory ECDSA P-256 self-signed cert"
                    " (CN/SAN=localhost)\n");
        cert_mgr.add_certificate("localhost", std::move(cert));
    }

    // ---- DTLS 服务端 ----
    dtls_connection srv;
    srv.set_version(ver);
    srv.set_cipher_suite(cs);
    srv.set_key_share_group(group);
    if (args.has("--cookie")) {
        srv.set_require_cookie(true);
        std::printf("server: cookie exchange enabled (HelloVerifyRequest)\n");
    }
    if (!srv.bind(port, host.c_str())) {
        std::fprintf(stderr, "bind %s:%u failed: %s\n",
                     host.c_str(), port, srv.last_error().c_str());
        return 1;
    }
    uint16_t real_port = srv.local_port();
    std::printf("server: listening on %s:%u (%s, cipher=%s, key_share=%s)\n",
                host.c_str(), real_port,
                ver == DTLSVersion::V13 ? "DTLS 1.3" : "DTLS 1.2",
                cipher.c_str(), gs.c_str());

    if (!srv.server_handshake(cert_mgr)) {
        std::fprintf(stderr, "server_handshake failed: %s\n",
                     srv.last_error().c_str());
        return 1;
    }
    print_session_info("server", srv);

    // ---- 回显循环：收到 "bye" 或超时则退出 ----
    std::vector<uint8_t> buf;
    while (srv.recv(buf)) {
        std::string msg((const char*)buf.data(), buf.size());
        std::printf("server: recv %zu bytes: \"%s\"\n", buf.size(), msg.c_str());
        if (msg == "bye") break;
        if (!srv.send(buf.data(), buf.size())) {
            std::fprintf(stderr, "server: send failed: %s\n",
                         srv.last_error().c_str());
            return 1;
        }
        std::printf("server: echoed %zu bytes\n", buf.size());
        buf.clear();
    }

    srv.close();
    std::printf("server: done\n");
    return 0;
}
