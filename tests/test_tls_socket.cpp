/**
 * test_tls_socket.cpp -- TLS socket 封装层回环测试（Windows / Linux）
 *
 * 覆盖：
 *   1. tls_listener 监听 + tls_connection 服务端握手（TLS 1.3）
 *   2. tls_connection 客户端握手（TLS 1.3）
 *   3. 握手后应用数据双向收发（加密 record 往返）
 *   4. ALPN 协商（RFC 7301）：匹配 / 不匹配 / 服务端未配置 / 偏好序
 *   5. 非阻塞模式：listener 非阻塞 accept、连接非阻塞收发、would-block 与 wait
 *   6. 协程 I/O：co_send / co_recv 挂起-恢复双向回环（tls_co_executor 驱动）
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

// 客户端按偏好序提供的协议，服务端支持列表，握手后返回两端协商结果
static std::string run_alpn_roundtrip(const std::vector<std::string>& client_sel,
                                      const std::vector<std::string>& server_sel,
                                      std::string& server_result) {
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    tls_certificate_manager server_mgr, client_mgr;
    server_mgr.add_certificate("localhost", make_server_cert(pub, priv));
    client_mgr.add_certificate("localhost", make_server_cert(pub, priv));

    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) return "<listen-fail>";
    uint16_t port = listener.local_port();

    std::thread server_thread([&] {
        tls_connection conn;
        conn.session().alpn_protos = server_sel; // accept 前配置（会保留）
        std::string e;
        if (!listener.accept(conn, server_mgr, &e)) return;
        server_result = conn.session().alpn_selected;
        const char okp[] = "--"; // 发个字节让客户端 recv 正常返回
        conn.send((const uint8_t*)okp, sizeof(okp) - 1, &e);
    });

    tls_connection client;
    client.session().alpn_protos = client_sel; // connect 前配置（会保留）
    if (!client.connect("127.0.0.1", port, &client_mgr, &err)) {
        server_thread.join();
        listener.close();
        return "";
    }
    std::string client_result = client.session().alpn_selected;
    std::vector<uint8_t> resp;
    client.recv(resp, &err);
    client.close();
    server_thread.join();
    listener.close();
    return client_result;
}

static void test_alpn() {
    std::printf("\n=== ALPN negotiation ===\n");
    std::string server_sel;

    // 1. 匹配：客户端 h2 优先，服务端支持 http/1.1 → 协商 http/1.1
    std::string c1 =
        run_alpn_roundtrip({"h2", "http/1.1"}, {"http/1.1"}, server_sel);
    TEST("alpn matching (client)", c1 == "http/1.1");
    TEST("alpn matching (server)", server_sel == "http/1.1");

    // 2. 无交集 → 两端均未协商
    server_sel.clear();
    std::string c2 = run_alpn_roundtrip({"h2"}, {"http/1.1"}, server_sel);
    TEST("alpn no-overlap (client empty)", c2.empty());
    TEST("alpn no-overlap (server empty)", server_sel.empty());

    // 3. 服务端未配置 → 不协商
    server_sel.clear();
    std::string c3 = run_alpn_roundtrip({"h2", "http/1.1"}, {}, server_sel);
    TEST("alpn server-unconfigured (client empty)", c3.empty());
    TEST("alpn server-unconfigured (server empty)", server_sel.empty());

    // 4. 客户端偏好序：h2 被双方支持时选择 h2
    server_sel.clear();
    std::string c4 =
        run_alpn_roundtrip({"h2", "http/1.1"}, {"http/1.1", "h2"}, server_sel);
    TEST("alpn preference order", c4 == "h2");
}

static void test_nonblocking() {
    std::printf("\n=== TLS non-blocking ===\n");
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    tls_certificate_manager server_mgr, client_mgr;
    server_mgr.add_certificate("localhost", make_server_cert(pub, priv));
    client_mgr.add_certificate("localhost", make_server_cert(pub, priv));

    tls_listener listener;
    std::string err;
    TEST("nb listen", listener.listen(0, "127.0.0.1", &err));
    uint16_t port = listener.local_port();
    TEST("nb listener set_nonblocking", listener.set_nonblocking(true, &err));
    TEST("nb listener is_nonblocking", listener.is_nonblocking());

    // 无连接时 accept 应返回 would-block
    tls_connection dummy;
    {
        std::string e;
        bool r = listener.accept(dummy, server_mgr, &e);
        TEST("nb accept would-block", !r && listener.would_block());
    }

    struct srv {
        bool accepted_nonblocking = false;
        bool got_hello = false;
        bool sent = false;
    } sr;
    std::thread server_thread([&] {
        tls_connection conn;
        std::string e;
        if (!listener.wait_readable(3000)) return;
        if (!listener.accept(conn, server_mgr, &e)) return;
        sr.accepted_nonblocking = conn.is_nonblocking(); // 应继承非阻塞
        std::vector<uint8_t> plain;
        if (conn.recv(plain, &e) && plain.size() >= 1) sr.got_hello = true;
        const char okp[] = "reply";
        sr.sent = conn.send((const uint8_t*)okp, sizeof(okp) - 1, &e);
    });

    // 客户端：connect 前开启非阻塞（TCP 连接 + 握手走有界等待路径）
    tls_connection client;
    TEST("nb client set_nonblocking", client.set_nonblocking(true, &err));
    TEST("nb client connect+handshake", client.connect("127.0.0.1", port, &client_mgr, &err));
    TEST("nb client is_nonblocking", client.is_nonblocking());

    const char hello[] = "hello";
    TEST("nb client send", client.send((const uint8_t*)hello, sizeof(hello) - 1, &err));

    // 服务端尚未回包：直接 recv 应 would-block（非阻塞、不关闭）
    {
        std::vector<uint8_t> resp;
        std::string e2;
        bool r = client.recv(resp, &e2);
        TEST("nb recv would-block (no data yet)", !r && client.would_block());
    }

    // 事件循环：等待可读后重试，直到拿到回包
    std::vector<uint8_t> resp;
    bool got = false;
    for (int i = 0; i < 100 && !got; ++i) {
        std::string e2;
        if (client.recv(resp, &e2)) { got = true; break; }
        if (!client.would_block()) break; // 真实错误
        if (!client.wait_readable(200)) break;
    }
    TEST("nb recv after wait_readable", got &&
         std::string((const char*)resp.data(), resp.size()) == "reply");
    client.close();
    server_thread.join();
    TEST("nb server accepted(nonblocking inherited)", sr.accepted_nonblocking);
    TEST("nb server got hello", sr.got_hello);
    TEST("nb server replied", sr.sent);
    listener.close();
}

// ── 协程 I/O 回环测试 ──────────────────────────────────────────────
struct co_state {
    tls_co_executor ex;
    std::unique_ptr<tls_connection> server_conn;
    std::unique_ptr<tls_connection> client_conn;
    std::unique_ptr<tls_co_task<void>> server_task;
    std::unique_ptr<tls_co_task<void>> client_task;
    std::string server_got, client_got;
    bool server_ok = false, client_ok = false;
};

// 服务端协程：收 "co hello" → 回 "co reply"
static tls_co_task<void> co_server_session(co_state& st) {
    std::string e;
    std::vector<uint8_t> msg;
    if (!co_await st.server_conn->co_recv(msg, &e)) co_return;
    st.server_got.assign((const char*)msg.data(), msg.size());
    st.server_ok = (st.server_got == "co hello");
    const char reply[] = "co reply";
    st.server_ok = st.server_ok &&
                   co_await st.server_conn->co_send((const uint8_t*)reply,
                                                    sizeof(reply) - 1, &e);
}

// 客户端协程：发 "co hello" → 收 "co reply"
static tls_co_task<void> co_client_session(co_state& st) {
    std::string e;
    const char hello[] = "co hello";
    if (!co_await st.client_conn->co_send((const uint8_t*)hello,
                                          sizeof(hello) - 1, &e))
        co_return;
    std::vector<uint8_t> reply;
    if (!co_await st.client_conn->co_recv(reply, &e)) co_return;
    st.client_got.assign((const char*)reply.data(), reply.size());
    st.client_ok = (st.client_got == "co reply");
}

static void test_co_io() {
    std::printf("\n=== TLS coroutine I/O ===\n");
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    tls_certificate_manager server_mgr, client_mgr;
    server_mgr.add_certificate("localhost", make_server_cert(pub, priv));
    client_mgr.add_certificate("localhost", make_server_cert(pub, priv));

    co_state st;
    tls_listener listener;
    std::string err;
    TEST("co listen", listener.listen(0, "127.0.0.1", &err));
    uint16_t port = listener.local_port();

    // 服务端线程：同步 accept + 握手，然后创建协程任务挂到共享执行器
    std::thread server_thread([&] {
        auto conn = std::make_unique<tls_connection>();
        std::string e;
        if (!listener.accept(*conn, server_mgr, &e)) return;
        conn->set_nonblocking(true, &e);
        conn->attach_co_executor(&st.ex);
        st.server_conn = std::move(conn);
        st.server_task = std::make_unique<tls_co_task<void>>(co_server_session(st));
    });

    // 客户端：同步 connect + 握手，再协程收发
    st.client_conn = std::make_unique<tls_connection>();
    TEST("co client connect+handshake",
         st.client_conn->connect("127.0.0.1", port, &client_mgr, &err));
    TEST("co client set_nonblocking", st.client_conn->set_nonblocking(true, &err));
    st.client_conn->attach_co_executor(&st.ex);
    st.client_task = std::make_unique<tls_co_task<void>>(co_client_session(st));

    // 等待服务端协程任务创建完成（线程同步）
    for (int i = 0; i < 100 && !st.server_task; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    TEST("co server task created", st.server_task != nullptr);
    // 至少一个协程已挂起在等待 socket（客户端 co_recv 等待服务端回复；
    // 服务端可能因客户端数据已到达而提前完成，故不作 >=2 的时序假设）。
    // 挂起-恢复路径由最终双向交换结果断言严格验证。
    TEST("co coroutine suspended", st.ex.pending() >= 1);

    // 单线程执行器驱动两个协程完成双向交换
    st.ex.run(100);

    server_thread.join();
    TEST("co server got client msg", st.server_ok && st.server_got == "co hello");
    TEST("co client got server reply", st.client_ok && st.client_got == "co reply");
    listener.close();
}

// 客户端 connect 默认只信任系统信任库中的 CA：
// 自签证书（不在系统信任库）必须被拒绝；显式传入信任库则可成功。
static void test_connect_default_system_trust() {
    std::printf("\n=== connect 默认系统信任 ===\n");
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    tls_certificate_manager server_mgr;
    server_mgr.add_certificate("localhost", make_server_cert(pub, priv));

    tls_listener listener;
    std::string err;
    TEST("listener listen", listener.listen(0, "127.0.0.1", &err));
    uint16_t port = listener.local_port();
    TEST("listener port assigned", port != 0);

    // 服务端线程：accept 后立即握手（客户端会拒绝，握手失败返回）
    std::thread server_thread([&] {
        tls_connection conn;
        std::string e;
        listener.accept(conn, server_mgr, &e);  // 握手失败也正常返回
    });

    // 客户端：默认 connect（无显式 trust）→ 自签证书不被系统信任 → 握手失败
    // （host 用 localhost 匹配证书 SAN；证书是自签的，系统信任库必然拒绝）
    tls_connection client;
    TEST("默认 connect 拒绝自签证书", !client.connect("localhost", port, nullptr, &err));
    client.close();
    server_thread.join();
    listener.close();

    // 显式信任库：CA 签发的 leaf 可成功握手（验证默认行为差异）
    // 构造 CA + leaf（复用 x509 builder）
    uint8_t ca_pub[64], ca_priv[32];
    ecdsa_p256_keygen(ca_pub, ca_priv);
    x509::x509_builder ca_b;
    x509::DistinguishedName ca_dn;
    ca_dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), "Socket Test CA"});
    ca_b.set_subject(ca_dn).set_issuer(ca_dn);
    uint8_t ca_ser[8] = {0xA1};
    ca_b.set_serial(ca_ser, 8);
    uint64_t now = (uint64_t)time(nullptr);
    ca_b.set_validity(now - 86400, now + 365 * 86400);
    ca_b.set_key(x509::KeyType::ECDSA_P256, ca_pub, 64);
    ca_b.set_ca(true);
    auto ca_cert = ca_b.build_and_sign(x509::KeyType::ECDSA_P256, ca_priv, 32);

    uint8_t leaf_pub[64], leaf_priv[32];
    ecdsa_p256_keygen(leaf_pub, leaf_priv);
    x509::x509_builder leaf_b;
    x509::DistinguishedName leaf_dn;
    leaf_dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), "localhost"});
    leaf_b.set_subject(leaf_dn).set_issuer(ca_dn);
    uint8_t leaf_ser[8] = {0xA2};
    leaf_b.set_serial(leaf_ser, 8);
    leaf_b.set_validity(now - 86400, now + 365 * 86400);
    leaf_b.set_key(x509::KeyType::ECDSA_P256, leaf_pub, 64);
    leaf_b.set_ca(false);
    leaf_b.add_san_dns("localhost");
    auto leaf_cert = leaf_b.build_and_sign(x509::KeyType::ECDSA_P256, ca_priv, 32);

    // 服务端用 CA 签发的 leaf
    auto srv = std::make_unique<tls_certificate>();
    srv->subject_name = "localhost";
    srv->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(srv->pub.ecdsa_p256, leaf_pub, 64);
    std::memcpy(srv->priv.ecdsa_p256, leaf_priv, 32);
    srv->cert_data = leaf_cert.to_der();
    tls_certificate_manager server_mgr2;
    server_mgr2.add_certificate("localhost", std::move(srv));

    tls_listener listener2;
    TEST("listener2 listen", listener2.listen(0, "127.0.0.1", &err));
    uint16_t port2 = listener2.local_port();
    std::thread server_thread2([&] {
        tls_connection conn;
        std::string e;
        if (!listener2.accept(conn, server_mgr2, &e)) return;
        const char msg[] = "hi";
        conn.send((const uint8_t*)msg, sizeof(msg) - 1, &e);
    });

    tls_connection client2;
    tls_trust_store trust;
    trust.ca_roots.push_back(ca_cert);
    TEST("显式信任库可握手", client2.connect("localhost", port2, trust, &err));
    client2.close();
    server_thread2.join();
    listener2.close();
}

int main() {
    std::string err;
    TEST("socket init", tls_socket_init(&err));
    test_socket_roundtrip();
    test_alpn();
    test_nonblocking();
    test_co_io();
    test_connect_default_system_trust();

    std::printf("\n================================================\n");
    std::printf("  Result: %d passed, %d failed", pass, fail);
    std::printf(fail == 0 ? " OK\n" : " FAILED\n");
    std::printf("================================================\n");
    return fail > 0 ? 1 : 0;
}
