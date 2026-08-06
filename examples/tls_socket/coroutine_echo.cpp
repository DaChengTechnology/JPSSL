/**
 * coroutine_echo.cpp -- TLS 协程 I/O + 线程池示例
 *
 * 演示 jpssl::tls 封装层的 C++20 协程 I/O：
 *   - tls_co_executor：poll 驱动执行器，多个连接共享；
 *   - attach_threadpool()：socket 就绪协程的恢复被 enqueue 到 ThreadPool，
 *     协程体（co_send/co_recv 与应用逻辑）运行在线程池线程上，可并行；
 *   - tls_connection::co_send() / co_recv()：would-block 时协程挂起、
 *     可读/可写后由执行器+线程池恢复，不阻塞任何线程。
 *
 * 运行：./coroutine_echo
 *
 * 流程（本机回环自演示）：
 *   1. 服务端线程 accept + 握手后创建服务端协程（co_recv 消息 → co_send 回显）；
 *   2. 客户端 connect + 握手后创建客户端协程（co_send "hello coroutine" → co_recv）；
 *   3. 单个 tls_co_executor + ThreadPool(4) 驱动两侧协程完成双向交换；
 *   4. 验证协程恢复确实发生在线程池线程（非驱动线程）。
 */
#include "tls_socket.hpp"
#include "ecdsa.hpp"
#include <threadpool/ThreadPool.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

static std::unique_ptr<tls_certificate> make_ecdsa_cert(const uint8_t pub[64],
                                                        const uint8_t priv[32]) {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(cert->pub.ecdsa_p256, pub, 64);
    std::memcpy(cert->priv.ecdsa_p256, priv, 32);
    return cert;
}

// 共享状态：连接 / 协程任务 / 执行器 / 线程池 / 结果
struct co_state {
    tls_co_executor ex;
    ThreadPool pool{4}; // 协程线程池（最后析构：run 完成后才 shutdown）
    std::unique_ptr<tls_connection> server_conn;
    std::unique_ptr<tls_connection> client_conn;
    std::unique_ptr<tls_co_task<void>> server_task;
    std::unique_ptr<tls_co_task<void>> client_task;
    std::string server_got, client_got;
    bool server_ok = false, client_ok = false;
    std::thread::id server_tid, client_tid; // 协程在 co_recv 恢复后的执行线程
};

// 服务端协程：收 "hello coroutine" → 回显 "echo coroutine"
static tls_co_task<void> co_server_session(co_state& st) {
    std::string e;
    std::vector<uint8_t> msg;
    if (!co_await st.server_conn->co_recv(msg, &e)) {
        std::fprintf(stderr, "server co_recv failed: %s\n", e.c_str());
        co_return;
    }
    st.server_tid = std::this_thread::get_id(); // 挂起后由线程池恢复
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
    st.client_tid = std::this_thread::get_id(); // 挂起后由线程池恢复
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
        auto conn = std::make_unique<tls_connection>();
        std::string e;
        if (!listener.accept(*conn, server_mgr, &e)) {
            std::fprintf(stderr, "server accept failed: %s\n", e.c_str());
            return;
        }
        conn->set_nonblocking(true, &e);
        conn->attach_co_executor(&st.ex);
        st.server_conn = std::move(conn);
        st.server_task = std::make_unique<tls_co_task<void>>(co_server_session(st));
    });

    // ---- 客户端：connect + 握手 → 创建客户端协程 ----
    st.client_conn = std::make_unique<tls_connection>();
    if (!st.client_conn->connect("127.0.0.1", port, &client_mgr, &err)) {
        std::fprintf(stderr, "client connect failed: %s\n", err.c_str());
        return 1;
    }
    st.client_conn->set_nonblocking(true, &err);
    st.client_conn->attach_co_executor(&st.ex);
    st.client_task = std::make_unique<tls_co_task<void>>(co_client_session(st));

    // 等待服务端协程任务创建完成
    for (int i = 0; i < 100 && !st.server_task; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (!st.server_task) {
        std::fprintf(stderr, "server task not created\n");
        return 1;
    }
    std::printf("suspended coroutines: %zu\n", st.ex.pending());

    // 绑定线程池：就绪协程的恢复投递到池线程执行
    st.ex.attach_threadpool(&st.pool);
    const std::thread::id main_tid = std::this_thread::get_id();

    // 驱动：poll 监听 socket 就绪，恢复交给线程池（协程体并行）
    st.ex.run(100);

    server_thread.join();
    listener.close();

    // ---- 结果 ----
    std::printf("server got: [%s]\n", st.server_got.c_str());
    std::printf("client got: [%s]\n", st.client_got.c_str());
    std::printf("server resumed on pool thread: %d\n",
                st.server_ok && st.server_tid != main_tid);
    std::printf("client resumed on pool thread: %d\n",
                st.client_ok && st.client_tid != main_tid);

    const bool ok = st.server_ok && st.client_ok &&
                    st.server_tid != main_tid && st.client_tid != main_tid;
    std::printf("\n%s\n", ok ? "coroutine echo: OK"
                             : "coroutine echo: FAILED");
    return ok ? 0 : 1;
}
