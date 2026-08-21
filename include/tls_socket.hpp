#pragma once
/**
 * tls_socket.hpp -- TLS-over-TCP socket 封装层（Windows Winsock / Linux POSIX）
 *
 * 在 jpssl 消息级 TLS API（tls.hpp）之上提供 socket 封装：
 *   - 跨平台套接字句柄（SOCKET / int）与连接管理（TCP 流式 + UDP 数据报）
 *   - 外部 fd 托管：attach() 接管调用方已创建的 socket（TCP 已连接 /
 *     UDP 已 connect 或已 bind），可选择是否持有所有权（关闭时是否 close）
 *   - TLS 1.3 完整握手（客户端 connect / client_handshake + 服务端
 *     accept / server_handshake / accept_udp 内完成）
 *   - TLS record 收发（TCP：自动处理半包/粘包；UDP：每条 TLS record
 *     封装为一个数据报，握手与应用数据统一走该约定）
 *   - 应用数据加密收发（tls_encrypt / tls_decrypt）
 *
 * 用法（服务端）：
 *   tls::tls_listener listener;
 *   listener.listen(443, "0.0.0.0");
 *   tls::tls_connection conn;
 *   if (listener.accept(conn, cert_mgr)) { conn.send("HTTP/1.1 200 OK\r\n"); }
 *
 * 用法（客户端）：
 *   tls::tls_connection conn;
 *   if (conn.connect("example.com", 443, &trust_mgr)) {
 *       conn.send("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
 *       std::vector<uint8_t> resp;
 *       conn.recv(resp);
 *   }
 *
 * 注意：客户端握手校验依赖调用方提供的 tls_certificate_manager
 * （按 SNI 名称查找预期服务器证书并校验 CertificateVerify），
 * 完整证书链 / CT 校验由上层自行完成。
 */

#include "tls.hpp"
#include "ktls.hpp"

#include <coroutine>
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace jpssl::tls {

#ifdef _WIN32
using socket_handle_t = SOCKET;
inline constexpr socket_handle_t INVALID_SOCKET_HANDLE = INVALID_SOCKET;
inline void close_socket_handle(socket_handle_t s) { closesocket(s); }
#else
using socket_handle_t = int;
inline constexpr socket_handle_t INVALID_SOCKET_HANDLE = -1;
inline void close_socket_handle(socket_handle_t s) { ::close(s); }
#endif

/// 初始化 socket 子系统（Windows 下执行一次 WSAStartup；POSIX 为空操作）。
/// connect / listen 内部会自动调用，也可显式调用。
bool tls_socket_init(std::string* error = nullptr);

class tls_listener;

// ============================================================================
// 协程基础设施（C++20 coroutine，零外部依赖）
// ============================================================================

/// 泛型协程任务。co_await 后得到返回值 T。
/// 顶层任务（无人 co_await）用局部变量持有，完成（含挂起等待时）
/// 由析构清理协程帧；嵌套任务由外层 co_await 的 await_resume 清理。
template <typename T>
struct tls_co_task {
    struct promise_type {
        T value{};
        std::coroutine_handle<> consumer{}; // 被谁 co_await（对称转换目标）

        tls_co_task get_return_object() {
            return tls_co_task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_never initial_suspend() noexcept { return {}; } // 热启动

        struct final_awaiter {
            bool await_ready() const noexcept { return false; }
            std::coroutine_handle<> await_suspend(
                std::coroutine_handle<promise_type> h) noexcept {
                // 有 consumer 则对称转换过去，否则挂起等待外层析构清理
                return h.promise().consumer
                           ? h.promise().consumer
                           : std::noop_coroutine();
            }
            void await_resume() noexcept {}
        };
        final_awaiter final_suspend() noexcept { return {}; }

        void return_value(T v) { value = std::move(v); }
        void unhandled_exception() noexcept { std::terminate(); }
    };

    std::coroutine_handle<promise_type> h_ = nullptr;

    explicit tls_co_task(std::coroutine_handle<promise_type> h) : h_(h) {}
    tls_co_task(tls_co_task&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    tls_co_task& operator=(tls_co_task&& o) noexcept {
        if (this != &o) {
            if (h_) h_.destroy();
            h_ = o.h_;
            o.h_ = nullptr;
        }
        return *this;
    }
    tls_co_task(const tls_co_task&) = delete;
    tls_co_task& operator=(const tls_co_task&) = delete;
    ~tls_co_task() { if (h_ && h_.done()) h_.destroy(); }

    bool await_ready() const noexcept { return !h_ || h_.done(); }
    std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
        h_.promise().consumer = awaiting;
        // 任务为热启动（initial_suspend 不挂起）：若内层已挂起在内部等待
        // （由执行器驱动恢复），此处绝不能 resume 它（双重 resume 是 UB）；
        // 仅在内层已完成时 resume 触发 final 对称转换回到 awaiting，
        // 否则外层直接挂起，等内层完成时由 final_awaiter 转回。
        if (h_.done()) return h_;
        return std::noop_coroutine();
    }
    T await_resume() {
        T v = std::move(h_.promise().value);
        if (h_) {
            // 销毁后必须置空：临时任务对象（co_await 全表达式结束）的析构还会检查 h_，
            // 不置空会对已销毁的协程帧二次 destroy（double-free / 堆损坏）。
            h_.destroy();
            h_ = nullptr;
        }
        return v;
    }
};

/// void 特化：无返回值。
template <>
struct tls_co_task<void> {
    struct promise_type {
        std::coroutine_handle<> consumer{};
        tls_co_task get_return_object() {
            return tls_co_task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_never initial_suspend() noexcept { return {}; }
        struct final_awaiter {
            bool await_ready() const noexcept { return false; }
            std::coroutine_handle<> await_suspend(
                std::coroutine_handle<promise_type> h) noexcept {
                return h.promise().consumer
                           ? h.promise().consumer
                           : std::noop_coroutine();
            }
            void await_resume() noexcept {}
        };
        final_awaiter final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }
    };
    std::coroutine_handle<promise_type> h_ = nullptr;
    explicit tls_co_task(std::coroutine_handle<promise_type> h) : h_(h) {}
    tls_co_task(tls_co_task&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    tls_co_task& operator=(tls_co_task&& o) noexcept {
        if (this != &o) {
            if (h_) h_.destroy();
            h_ = o.h_;
            o.h_ = nullptr;
        }
        return *this;
    }
    tls_co_task(const tls_co_task&) = delete;
    tls_co_task& operator=(const tls_co_task&) = delete;
    ~tls_co_task() { if (h_ && h_.done()) h_.destroy(); }
    bool await_ready() const noexcept { return !h_ || h_.done(); }
    std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
        h_.promise().consumer = awaiting;
        // 见模板版本注释：热启动任务已挂起时不可 resume，仅完成时触发对称转换
        if (h_.done()) return h_;
        return std::noop_coroutine();
    }
    void await_resume() {
        if (h_) {
            h_.destroy();
            h_ = nullptr;  // 同模板版：防临时任务对象析构二次 destroy
        }
    }
};

/// 协程执行器：单线程 poll 驱动。多个 tls_connection 可共享一个执行器，
/// co_await 挂起的协程在 socket 就绪时由 run_once()/run() 恢复。
/// 非线程安全：注册与驱动须在同一线程。
class tls_co_executor {
public:
    tls_co_executor() = default;
    ~tls_co_executor() = default;
    tls_co_executor(const tls_co_executor&) = delete;
    tls_co_executor& operator=(const tls_co_executor&) = delete;

    /// 注册一次等待（tls_connection 协程 I/O 内部调用，勿手动调用）。
    void add_waiter(int fd, bool for_write, std::coroutine_handle<> h);

    /// 单次驱动：poll 所有注册 fd，就绪的协程恢复执行。
    /// timeout_ms < 0 表示无限等待；返回本次是否恢复了协程。
    bool run_once(int timeout_ms = -1);

    /// 循环驱动，直到没有等待中的协程。
    void run(int timeout_ms = 100);

    /// 当前等待中的协程数量。
    size_t pending() const { return waiters_.size(); }

private:
    struct waiter {
        int fd;
        bool for_write;
        std::coroutine_handle<> h;
    };
    std::vector<waiter> waiters_;
};

// ============================================================================
// TLS over TCP 连接（客户端或服务端，握手完成后即可收发应用数据）
// ============================================================================

class tls_connection {
public:
    tls_connection();
    ~tls_connection();
    tls_connection(const tls_connection&) = delete;
    tls_connection& operator=(const tls_connection&) = delete;

    /// 客户端：TCP 连接 + TLS 客户端握手（默认 TLS 1.3；
    /// 通过 set_tls_version(TLSVersion::V12) 切换到 TLS 1.2，支持
    /// RSA / ECDHE / DHE(ffdhe2048) / PSK / DHE-PSK 密钥交换）。
    /// 默认（trust_store == nullptr）：只信任系统信任库中的 CA 根证书
    /// （tls_trust_store::from_system()，见系统 CA bundle 探测），
    /// 对服务端证书链做 x509 验证；系统信任库不可用时握手失败。
    /// trust_store 可选：传 tls_certificate_manager* 时保持旧行为——
    /// 按 SNI 名称查找预期服务器证书校验 CertificateVerify。
    bool connect(const std::string& host, uint16_t port,
                 const tls_certificate_manager* trust_store = nullptr,
                 std::string* error = nullptr);

    /// 客户端：TCP 连接 + TLS 客户端握手（版本见 set_tls_version），
    /// 按 x509 信任库验证服务端证书链。
    /// trust 提供 CA 根证书时，握手会对服务端证书链执行 x509_verify_chain
    /// （含叶子证书主机名匹配），验证失败则握手失败。
    bool connect(const std::string& host, uint16_t port,
                 const tls_trust_store& trust,
                 std::string* error = nullptr);

    /// 托管外部 socket 句柄（调用方已创建并就绪的 socket）：
    ///   - TCP：已 connect 的客户端 socket，或 accept 出的服务端 socket；
    ///   - UDP：已 connect（固定对端）或已 bind 的 SOCK_DGRAM socket
    ///     （自动启用数据报模式，见 set_datagram_mode）。
    /// 托管后调用 client_handshake()（客户端）或 server_handshake()（服务端）
    /// 在已有 socket 上完成 TLS 握手，再通过 send/recv 收发应用数据。
    ///
    /// take_ownership=true（默认）：本连接 close() 时关闭该句柄；
    /// take_ownership=false：仅借用，close() 不关闭、不 shutdown，由调用方管理。
    bool attach(socket_handle_t fd, bool take_ownership = true,
                std::string* error = nullptr);

    /// 查询是否持有外部句柄的所有权（close() 时是否关闭底层 fd）。
    bool owns_socket() const { return owns_socket_; }

    /// 客户端：在已托管的 socket（attach 之后）上执行 TLS 客户端握手
    /// （版本见 set_tls_version）。
    /// 不建立任何传输连接，仅做握手；信任语义与 connect() 完全一致
    /// （trust_store == nullptr 时走系统信任库，传 tls_certificate_manager*
    /// 时按 SNI 名称查找预期服务器证书校验 CertificateVerify）。
    bool client_handshake(const std::string& host,
                          const tls_certificate_manager* trust_store = nullptr,
                          std::string* error = nullptr);

    /// 客户端握手（数据报/流式均可），按 x509 信任库验证服务端证书链。
    bool client_handshake(const std::string& host,
                          const tls_trust_store& trust,
                          std::string* error = nullptr);

    /// 设置客户端握手使用的 TLS 版本（默认 TLSVersion::V13）。
    /// 设为 TLSVersion::V12 后，connect() / client_handshake() 执行
    /// TLS 1.2 客户端握手（支持 RSA、ECDHE、DHE、PSK、DHE-PSK 套件；
    /// 证书套件校验方式与 connect()/client_handshake() 的信任参数一致，
    /// PSK 套件需先在 session() 上配置 tls12_psk_*）。
    void set_tls_version(TLSVersion v) { tls_version_ = v; }
    TLSVersion tls_version() const { return tls_version_; }

    /// 设置是否跳过对端证书认证（自签证书 / 内网测试环境）。
    /// 仅关闭证书链验证、主机名匹配与服务端 CertificateVerify 校验，
    /// TLS 握手与密钥交换照常进行，连接仍可加密收发数据。
    /// 默认 false（不跳过）；trust_store / cert_manager 为 nullptr 时的
    /// 默认行为不变。
    void set_skip_verify(bool skip = true) { skip_verify_ = skip; }
    bool skip_verify() const { return skip_verify_; }

    /// 数据报模式（UDP 链接）开关。attach() 对 SOCK_DGRAM 句柄自动启用；
    /// 对 TCP 句柄默认关闭。可手动覆盖：enable=true 要求底层为 UDP socket。
    ///
    /// 数据报模式下每条 TLS record（含握手消息）封装为一个 UDP 数据报发送，
    /// 接收端每个数据报解析为一条 record；单条 record 上限 16KiB+开销，
    /// 远小于 64KiB 数据报上限。send() 对大消息自动分片为多个数据报，
    /// recv() 自动合并还原。握手与 TCP 模式走同一套 record 收发逻辑。
    bool set_datagram_mode(bool enable, std::string* error = nullptr);
    bool is_datagram() const { return datagram_; }

    /// 服务端：对已建立的 TCP 连接执行 TLS 1.3 服务端握手。
    /// 通常由 tls_listener::accept 调用；也可对原生 socket 手动设置后调用。
    bool server_handshake(const tls_certificate_manager& cert_manager,
                          std::string* error = nullptr);

    /// 服务端握手（PSK 变体）：psk_store 提供 TLS 1.2 PSK 身份表（RFC 4279/5487），
    /// 客户端通告 PSK 套件时服务端可协商 PSK / DHE_PSK。
    bool server_handshake(const tls_certificate_manager& cert_manager,
                          const tls_psk_store& psk_store,
                          std::string* error = nullptr);

    /// 设置/取消非阻塞模式（可在 connect 之前或之后调用；
    /// connect 之前调用时，TCP 连接建立也采用非阻塞方式）。
    ///
    /// 非阻塞模式语义：
    ///   - send()/recv()：当内核缓冲区暂不可用（EAGAIN/EWOULDBLOCK）时
    ///     立即返回 false，error 为 "would block"，可通过 would_block()
    ///     判定；连接保持打开，配合 wait_readable()/wait_writable()
    ///     在事件循环中重试。
    ///   - 握手（connect/server_handshake/accept）：内部有界等待
    ///     （set_handshake_timeout 配置，默认 30 秒），不会永久阻塞，
    ///     但为保持握手状态机完整，暂不支持“一步一停”的分步握手。
    bool set_nonblocking(bool enable, std::string* error = nullptr);
    bool is_nonblocking() const { return nonblocking_; }

    /// 最近一次 I/O 是否因资源暂不可用而返回（仅非阻塞模式有效）。
    bool would_block() const { return would_block_; }

    /// 等待 socket 可读 / 可写（事件循环用）。timeout_ms < 0 表示无限等待；
    /// 返回 true 表示就绪，false 表示超时或 socket 无效。
    bool wait_readable(int timeout_ms) const;
    bool wait_writable(int timeout_ms) const;

    /// 配置握手阶段 I/O 的有界等待超时（毫秒，默认 30000）。
    /// 仅在非阻塞模式下生效；阻塞模式保持原有无限阻塞语义。
    void set_handshake_timeout(int timeout_ms) { handshake_timeout_ms_ = timeout_ms; }

    /// 发送应用数据（自动按 <=16KiB 分片为多条 TLS record 后写入 socket，
    /// 对端 recv 会自动合并为完整消息返回）
    bool send(const uint8_t* data, size_t len, std::string* error = nullptr);
    bool send(const std::string& data, std::string* error = nullptr);

    /// 读取应用数据：一次 send() 拆分出的多条 record 会自动合并返回。
    /// 对端关闭 / 致命错误 / 收到 alert 时返回 false。
    bool recv(std::vector<uint8_t>& out, std::string* error = nullptr);

    // ---- 协程 I/O（C++20 coroutine）----
    /// 绑定协程执行器。co_send()/co_recv() 前必须调用（多个连接可共享
    /// 一个执行器）。协程 I/O 要求连接处于非阻塞模式（set_nonblocking(true)）。
    void attach_co_executor(tls_co_executor* ex) { executor_ = ex; }
    tls_co_executor* co_executor() const { return executor_; }

    /// 协程发送：完整发送 len 字节；写缓冲暂满时协程挂起，socket 可写后
    /// 由执行器恢复继续发送。返回是否全部发送成功。
    tls_co_task<bool> co_send(const uint8_t* data, size_t len,
                              std::string* error = nullptr);
    tls_co_task<bool> co_send(const std::string& data,
                              std::string* error = nullptr);

    /// 协程接收：语义与 recv() 一致（自动合并一次 send() 拆分出的多条 record）；
    /// 无数据到达时协程挂起，可读后由执行器恢复。返回 false 表示对端关闭 /
    /// 致命错误 / 收到 alert。
    tls_co_task<bool> co_recv(std::vector<uint8_t>& out,
                              std::string* error = nullptr);

    void close();
    bool is_open() const { return open_; }

    tls_session& session() { return session_; }
    const tls_session& session() const { return session_; }

    socket_handle_t native() const { return sock_; }

    // ---- kTLS（内核 TLS 记录层卸载，Linux）----
    /// 握手完成后调用：把会话密钥导出并交给 Linux 内核（TCP_ULP "tls"），
    /// 成功后本连接进入“明文直通”模式——内核对记录做封装/加解密，
    /// 应用侧 send()/recv() 直接读写明文（不再经用户态 tls_encrypt/tls_decrypt）。
    /// 返回 false 时 error 说明原因（平台不支持 / 内核未开启 / 握手中）。
    bool enable_ktls(std::string* error = nullptr);
    /// 是否已成功启用 kTLS（明文直通模式激活）。
    bool ktls_active() const { return ktls_active_; }

private:
    friend class tls_listener;

    bool do_client_handshake(const tls_certificate_manager* trust_store,
                             const tls_trust_store* trust,
                             std::string* error);
    /// TLS 1.2 客户端握手（set_tls_version(V12) 时由 do_client_handshake 分发）。
    bool do_client_handshake_tls12(const tls_certificate_manager* trust_store,
                                   const tls_trust_store* trust,
                                   std::string* error);
    /// 建立 TCP 连接并初始化会话（connect 两个重载共用）。
    bool establish_tcp(const std::string& host, uint16_t port, std::string* error);
    bool do_server_handshake(const tls_certificate_manager& cert_manager,
                             const tls_psk_store* psk_store, std::string* error);

    bool write_all(const uint8_t* data, size_t len, std::string* error);
    /// 数据报模式：单次发送一个完整 UDP 数据报（一条 TLS record）。
    /// UDP 发送具有原子性：要么整包成功，要么返回错误，不会部分发送。
    bool send_one_datagram(const uint8_t* data, size_t len, std::string* error);
    /// 从 socket 读入数据追加到 rbuf_ 尾部，直到 rbuf_.size() >= min_total。
    /// 非阻塞应用数据阶段遇 EAGAIN 时返回 false 并置 would_block_（已读部分保留在 rbuf_）。
    bool fill_rbuf(size_t min_total, std::string* error);
    /// 读取一条完整 TLS record（从 rbuf_ 消费，续读无缝）；payload 不含 5 字节 record 头。
    bool read_record(uint8_t& type, std::vector<uint8_t>& payload, std::string* error);
    /// 检查 socket / 内部缓冲区是否还有已到达的数据（用于 recv 合并多条 record）
    bool more_data_pending() const;
    /// 协程版：从 socket 读入数据追加到 rbuf_，直到 rbuf_.size() >= min_total。
    /// would-block 时挂起等待可读（由执行器恢复）。
    tls_co_task<bool> co_fill_rbuf(size_t min_total, std::string* error);
    /// 协程版：读取一条完整 TLS record（从 rbuf_ 消费，续读无缝）。
    tls_co_task<bool> co_read_record(uint8_t& type, std::vector<uint8_t>& payload,
                                     std::string* error);

    void set_tcp_nodelay();

    socket_handle_t sock_ = INVALID_SOCKET_HANDLE;
    bool skip_verify_ = false;       // 跳过对端证书认证（见 set_skip_verify）
    bool open_ = false;
    bool owns_socket_ = true;        // 是否持有 sock_ 所有权（close() 时是否关闭）
    bool datagram_ = false;          // 数据报模式（UDP：每条 TLS record 一个数据报）
    bool nonblocking_ = false;       // 非阻塞模式标志
    bool would_block_ = false;       // 最近一次 I/O 是否 would-block
    bool handshake_pending_ = false; // 当前是否处于握手阶段（影响 EAGAIN 处理）
    int handshake_timeout_ms_ = 30000; // 握手阶段有界等待超时
    TLSVersion tls_version_ = TLSVersion::V13; // 客户端握手版本（默认 TLS 1.3）
    tls_session session_;
    std::vector<uint8_t> rbuf_;   // 接收缓冲（处理半包）
    tls_co_executor* executor_ = nullptr; // 协程执行器（co_send/co_recv 用）
    bool ktls_active_ = false;        // kTLS 明文直通模式已激活
};

// ============================================================================
// TLS 服务端监听器（TCP listen / accept + TLS 1.3 服务端握手）
// ============================================================================

class tls_listener {
public:
    tls_listener();
    ~tls_listener();
    tls_listener(const tls_listener&) = delete;
    tls_listener& operator=(const tls_listener&) = delete;

    /// 绑定并监听。port == 0 时由系统分配端口（可用 local_port() 查询）。
    bool listen(uint16_t port, const std::string& bind_addr = "0.0.0.0",
                std::string* error = nullptr);

    /// 托管外部 socket 句柄（调用方已创建并就绪的监听 socket：
    /// TCP 已 listen，或 UDP 已 bind）。take_ownership 语义同 tls_connection::attach。
    /// 对 SOCK_DGRAM 句柄自动标记为 UDP 监听（配合 accept_udp 使用）。
    bool attach(socket_handle_t fd, bool take_ownership = true,
                std::string* error = nullptr);

    /// 查询是否持有外部句柄的所有权（close() 时是否关闭底层 fd）。
    bool owns_socket() const { return owns_socket_; }

    /// 是否 UDP 监听器（listen_udp / attach(SOCK_DGRAM) 后为 true）。
    bool is_udp() const { return udp_; }

    /// 接受一个 TCP 连接并完成 TLS 1.3 服务端握手。
    bool accept(tls_connection& conn, const tls_certificate_manager& cert_manager,
                std::string* error = nullptr);

    /// 接受一个 TCP 连接并完成服务端握手（PSK 变体，见 server_handshake）。
    bool accept(tls_connection& conn, const tls_certificate_manager& cert_manager,
                const tls_psk_store& psk_store,
                std::string* error = nullptr);

    /// UDP 链接（数据报模式）：绑定 UDP 端口等待客户端握手。
    /// 配合 accept_udp 使用；port == 0 时由系统分配端口（local_port() 查询）。
    /// 注意：UDP 为无连接传输，握手丢包时由调用方负责重试整个握手。
    bool listen_udp(uint16_t port, const std::string& bind_addr = "0.0.0.0",
                    std::string* error = nullptr);

    /// 接收一个 UDP 客户端并完成 TLS 1.3 服务端握手：
    /// 先 recvfrom 取首个 ClientHello 数据报及其对端地址，用监听 socket
    /// 本身 connect 固定该对端（保持源端口不变，客户端才能收到回复），
    /// 把数据注入 conn 后执行服务端握手。监听 socket 由此转交给 conn，
    /// listener 变为未打开——一个 UDP listener 同一时刻服务一个客户端。
    /// 非阻塞模式下无待处理数据报时返回 false 并置 would_block()。
    bool accept_udp(tls_connection& conn, const tls_certificate_manager& cert_manager,
                    std::string* error = nullptr);

    /// 设置/取消监听 socket 的非阻塞模式。非阻塞时 accept() 在无待处理
    /// 连接时返回 false 并置 would_block()（可配合 wait_readable() 重试）。
    /// 注意：accept 出的连接 socket 会继承监听器的非阻塞状态。
    bool set_nonblocking(bool enable, std::string* error = nullptr);
    bool is_nonblocking() const { return nonblocking_; }

    /// 最近一次 accept 是否因暂无可接受连接而返回（仅非阻塞模式有效）。
    bool would_block() const { return would_block_; }

    /// 等待监听 socket 可读（即存在待 accept 的连接），事件循环用。
    bool wait_readable(int timeout_ms) const;

    /// 实际绑定的本地端口（port == 0 时有用）。
    uint16_t local_port() const;

    void close();
    bool is_open() const { return open_; }
    socket_handle_t native() const { return sock_; }

private:
    socket_handle_t sock_ = INVALID_SOCKET_HANDLE;
    bool open_ = false;
    bool owns_socket_ = true;   // 是否持有 sock_ 所有权（close() 时是否关闭）
    bool udp_ = false;          // 是否 UDP 监听（accept_udp 用）
    bool nonblocking_ = false;
    bool would_block_ = false;
};

} // namespace jpssl::tls
