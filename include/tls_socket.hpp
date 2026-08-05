#pragma once
/**
 * tls_socket.hpp -- TLS-over-TCP socket 封装层（Windows Winsock / Linux POSIX）
 *
 * 在 jpssl 消息级 TLS API（tls.hpp）之上提供面向连接的 socket 封装：
 *   - 跨平台套接字句柄（SOCKET / int）与 TCP 连接管理
 *   - TLS 1.3 完整握手（客户端 connect + 服务端 accept 内完成）
 *   - TLS record 收发（自动处理半包/粘包、握手消息封装与加密 record 透传）
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
// TLS over TCP 连接（客户端或服务端，握手完成后即可收发应用数据）
// ============================================================================

class tls_connection {
public:
    tls_connection();
    ~tls_connection();
    tls_connection(const tls_connection&) = delete;
    tls_connection& operator=(const tls_connection&) = delete;

    /// 客户端：TCP 连接 + TLS 1.3 客户端握手。
    /// trust_store 可选：包含按 SNI 名称查找的服务器证书（用于校验 CertificateVerify）。
    bool connect(const std::string& host, uint16_t port,
                 const tls_certificate_manager* trust_store = nullptr,
                 std::string* error = nullptr);

    /// 服务端：对已建立的 TCP 连接执行 TLS 1.3 服务端握手。
    /// 通常由 tls_listener::accept 调用；也可对原生 socket 手动设置后调用。
    bool server_handshake(const tls_certificate_manager& cert_manager,
                          std::string* error = nullptr);

    /// 发送应用数据（自动按 <=16KiB 分片为多条 TLS record 后写入 socket，
    /// 对端 recv 会自动合并为完整消息返回）
    bool send(const uint8_t* data, size_t len, std::string* error = nullptr);
    bool send(const std::string& data, std::string* error = nullptr);

    /// 读取应用数据：一次 send() 拆分出的多条 record 会自动合并返回。
    /// 对端关闭 / 致命错误 / 收到 alert 时返回 false。
    bool recv(std::vector<uint8_t>& out, std::string* error = nullptr);

    void close();
    bool is_open() const { return open_; }

    tls_session& session() { return session_; }
    const tls_session& session() const { return session_; }

    socket_handle_t native() const { return sock_; }

private:
    friend class tls_listener;

    bool do_client_handshake(const tls_certificate_manager* trust_store, std::string* error);
    bool do_server_handshake(const tls_certificate_manager& cert_manager, std::string* error);

    bool write_all(const uint8_t* data, size_t len, std::string* error);
    bool read_bytes(uint8_t* out, size_t n, std::string* error);
    /// 读取一条完整 TLS record；payload 不含 5 字节 record 头。
    bool read_record(uint8_t& type, std::vector<uint8_t>& payload, std::string* error);
    /// 检查 socket / 内部缓冲区是否还有已到达的数据（用于 recv 合并多条 record）
    bool more_data_pending() const;

    void set_tcp_nodelay();

    socket_handle_t sock_ = INVALID_SOCKET_HANDLE;
    bool open_ = false;
    tls_session session_;
    std::vector<uint8_t> rbuf_;   // 接收缓冲（处理半包）
    size_t rbuf_off_ = 0;         // 已消费偏移
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

    /// 接受一个 TCP 连接并完成 TLS 1.3 服务端握手。
    bool accept(tls_connection& conn, const tls_certificate_manager& cert_manager,
                std::string* error = nullptr);

    /// 实际绑定的本地端口（port == 0 时有用）。
    uint16_t local_port() const;

    void close();
    bool is_open() const { return open_; }
    socket_handle_t native() const { return sock_; }

private:
    socket_handle_t sock_ = INVALID_SOCKET_HANDLE;
    bool open_ = false;
};

} // namespace jpssl::tls
