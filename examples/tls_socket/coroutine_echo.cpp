/**
 * coroutine_echo.cpp -- TLS 协程 I/O 示例
 *
 * 演示 jpssl::tls 封装层的 C++20 协程 I/O：
 *   - tls_co_executor：单线程 poll 驱动执行器，多个连接共享；
 *   - tls_connection::co_send() / co_recv()：would-block 时协程挂起，
 *     可读/可写后由执行器恢复，不阻塞任何线程；
 *   - tls_co_task<T>：泛型协程任务（热启动 + 对称转换，零外部依赖）。
 *
 * 运行：./coroutine_echo
 *
 * 流程（本机回环自演示）：
 *   1. 服务端线程 accept + 握手后创建服务端协程（co_recv 消息 → co_send 回显）；
 *   2. 客户端 connect + 握手后创建客户端协程（co_send "hello coroutine" → co_recv）；
 *   3. 单个 tls_co_executor 驱动两侧协程完成双向交换。
 */
#include "tls_socket.hpp"
#include "ecdsa.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include "jpssl_memory.hpp"
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

static std::unique_ptr<tls_certificate> make_ecdsa_cert(const uint8_t pub[64],
                                                        const uint8_t priv[32]) {
    auto cert = jpssl::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(cert->pub.ecdsa_p256, pub, 64);
    std::memcpy(cert->priv.ecdsa_p256, priv, 32);
    return cert;
}

// 共享状态：连接 / 协程任务 / 执行器 / 结果
struct co_state {
    tls_co_executor ex;
    std::unique_ptr<tls_connection> server_conn;
    std::unique_ptr<tls_connection> client_conn;
    std::unique_ptr<tls_co_task<void>> server_task;
    std::unique_ptr<tls_co_task<void>> client_task;
    std::string server_got, client_got;
    bool server_ok = false, client_ok = false;
};

// 服务端协程：收 "hello coroutine" → 回显 "echo coroutine"
static tls_co_task<void> co_server_session(co_state& st) {
    std::string e;
    std::vector<uint8_t> msg;
    if (!co_await st.server_conn->co_recv(msg, &e)) {
        std::fprintf(stderr, "server co_recv failed: %s\n", e.c_str());
        co_return;
    }
    st.server_got.assign((const char*)msg.data(), msg.size());
    st.server_ok = (st.server_got == "hello coroutine");
    const char reply[] = "echo coroutine";
    st.server_ok = st.server_ok &&
                   co_await st.server_conn->co_send((const uint8_t*)reply,
                                                    sizeof(reply) - 1, &e);
}

// 客户端协程：发 "hello coroutine" → 收 "echo coroutine"
static tls_co_task<void> co_client_session(co_state& st) {
    std::string e;
    const char hello[] = "hello coroutine";
    if (!co_await st.client_conn->co_send((const uint8_t*)hello,
                                          sizeof(hello) - 1, &e)) {
        std::fprintf(stderr, "client co_send failed: %s\n", e.c_str());
        co_return;
    }
    std::vector<uint8_t> reply;
    if (!co_await st.client_conn->co_recv(reply, &e)) {
        std::fprintf(stderr, "client co_recv failed: %s\n", e.c_str());
        co_return;
    }
    st.client_got.assign((const char*)reply.data(), reply.size());
    st.client_ok = (st.client_got == "echo coroutine");
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

    co_state st;
    tls_listener listener;
    std::string err;
    if (!listener.listen(0, "127.0.0.1", &err)) {
        std::fprintf(stderr, "listen failed: %s\n", err.c_str());
        return 1;
    }
    uint16_t port = listener.local_port();
    std::printf("listener: 127.0.0.1:%u\n", port);

    // ---- 服务端线程：accept + 握手 → 创建服务端协程 ----
    std::thread server_thread([&] {
        auto conn = jpssl::make_unique<tls_connection>();
        std::string e;
        if (!listener.accept(*conn, server_mgr, &e)) {
            std::fprintf(stderr, "server accept failed: %s\n", e.c_str());
            return;
        }
        conn->set_nonblocking(true, &e);
        conn->attach_co_executor(&st.ex);
        st.server_conn = std::move(conn);
        st.server_task = jpssl::make_unique<tls_co_task<void>>(co_server_session(st));
    });

    // ---- 客户端：connect + 握手 → 创建客户端协程 ----
    st.client_conn = jpssl::make_unique<tls_connection>();
    if (!st.client_conn->connect("127.0.0.1", port, &client_mgr, &err)) {
        std::fprintf(stderr, "client connect failed: %s\n", err.c_str());
        return 1;
    }
    st.client_conn->set_nonblocking(true, &err);
    st.client_conn->attach_co_executor(&st.ex);
    st.client_task = jpssl::make_unique<tls_co_task<void>>(co_client_session(st));

    // 等待服务端协程任务创建完成
    for (int i = 0; i < 100 && !st.server_task; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (!st.server_task) {
        std::fprintf(stderr, "server task not created\n");
        return 1;
    }
    std::printf("suspended coroutines: %zu\n", st.ex.pending());

    // 驱动执行器：poll 就绪并恢复挂起的协程（单线程）
    st.ex.run(100);

    server_thread.join();
    listener.close();

    // ---- 结果 ----
    std::printf("server got: [%s]\n", st.server_got.c_str());
    std::printf("client got: [%s]\n", st.client_got.c_str());

    const bool ok = st.server_ok && st.client_ok;
    std::printf("\n%s\n", ok ? "coroutine echo: OK"
                             : "coroutine echo: FAILED");
    return ok ? 0 : 1;
}