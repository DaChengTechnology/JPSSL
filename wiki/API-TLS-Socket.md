# TLS socket 封装层

头文件：`include/tls_socket.hpp`，命名空间 `jpssl::tls`。

在消息级 TLS API（`tls.hpp`）之上提供跨平台（Windows Winsock / Linux POSIX）的 socket 封装（TLS 1.3，[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)）：TCP 流式连接 + UDP 数据报，并支持托管调用方已创建的外部 fd。

- `tls_connection`：客户端 `connect(host, port, trust_store)` 或服务端 `server_handshake(cert_manager)` 完成 TLS 1.3 握手；`send` / `recv` 收发加密应用数据。
- 客户端默认**只信任系统信任库**：不传 `trust_store`（或传 `nullptr`）时自动通过 `tls_trust_store::from_system()` 加载系统 CA bundle，对服务端证书链执行 x509 验证（含主机名匹配），验证失败或系统信任库不可用则握手失败。
- `tls_listener`：`listen(port)` + `accept(conn, cert_manager)`，接受连接并自动完成服务端握手。
- record 层自动处理半包 / 粘包、握手消息封装与加密 record 透传。

## 服务端示例

```cpp
#include "tls_socket.hpp"
using namespace jpssl::tls;

// 准备证书管理器
tls_certificate_manager cert_mgr;
// ... add_certificate("example.com", ...) ...

tls_listener listener;
if (!listener.listen(443, "0.0.0.0")) {
    // 绑定失败
}

tls_connection conn;
if (listener.accept(conn, cert_mgr)) {   // accept 内自动完成 TLS 1.3 服务端握手
    std::vector<uint8_t> req;
    if (conn.recv(req)) {
        conn.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    }
}
```

## 客户端示例

```cpp
tls_connection conn;
// 默认只信任系统信任库（无需显式 trust_store）：
// 自动加载系统 CA bundle 并验证服务端证书链
if (conn.connect("example.com", 443)) {
    conn.send("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    std::vector<uint8_t> resp;
    if (conn.recv(resp)) {
        // resp 为完整应用消息（多条 record 已自动合并）
    }
}

// 也可显式指定自定义 CA 根：
tls_trust_store trust = tls_trust_store::from_pem_file("ca.crt");
tls_connection conn2;
if (conn2.connect("example.com", 443, trust)) { /* ... */ }
```

### 跳过对端证书认证

自签证书 / 内网测试环境可用 `set_skip_verify(true)` 关闭对端证书认证：仅跳过证书链验证、主机名匹配与服务端 CertificateVerify 校验，TLS 握手与密钥交换照常进行，连接仍可加密收发数据（默认 `false`）：

```cpp
tls_connection conn;
conn.set_skip_verify(true);             // 跳过对端证书认证（默认 false）
if (conn.connect("example.com", 443)) { /* 不验证证书链，直接建立加密连接 */ }
```

## 成员一览

| 成员 | 说明 |
|------|------|
| `tls_socket_init(error)` | 初始化 socket 子系统（Windows 下执行一次 WSAStartup；POSIX 为空操作），`connect` / `listen` 内部会自动调用 |
| `tls_connection::connect(host, port, trust_store, error)` | 客户端：TCP 连接 + TLS 1.3 握手。默认（`trust_store == nullptr`）只信任系统信任库（`tls_trust_store::from_system()`）；传 `tls_certificate_manager*` 保持按 SNI 查找预期证书的旧行为 |
| `tls_connection::connect(host, port, trust, error)` | 客户端：TCP 连接 + TLS 1.3 握手，按 `tls_trust_store&`（自定义 CA 根）验证服务端证书链 |
| `tls_connection::server_handshake(cert_manager, error)` | 服务端：对已建立的 TCP 连接执行 TLS 1.3 握手（通常由 `accept` 调用） |
| `tls_connection::send(data, len, error)` | 发送应用数据，自动按 ≤16KiB 分片为多条 TLS record |
| `tls_connection::recv(out, error)` | 读取应用数据，同一突发到达的多条 record 自动合并后一次返回 |
| `tls_connection::close()` / `is_open()` | 关闭连接 / 连接状态 |
| `tls_connection::session()` | 访问底层 `tls_session`（套件、密钥、序列号等） |
| `tls_connection::set_skip_verify(skip)` / `skip_verify()` | 跳过对端证书认证（自签证书 / 内网测试环境）：仅关闭证书链验证、主机名匹配与服务端 CertificateVerify 校验，握手与密钥交换照常；默认 `false` |
| `tls_connection::enable_ktls(error)` | 握手完成后启用 kTLS（Linux 内核 TLS 记录层卸载），成功后进入明文直通模式；失败时 `error` 说明原因（平台不支持 / 内核未开启 / 握手中 / 套件不支持） |
| `tls_connection::ktls_active()` | 是否已成功启用 kTLS（明文直通模式激活） |
| `tls_connection::native()` | 原生 socket 句柄 |
| `tls_connection::attach(fd, take_ownership, error)` | 托管外部 socket 句柄（TCP 已连接 / accept 出的连接 / UDP 已 connect 或已 bind）；`take_ownership=false` 借用模式：`close()` 不关闭、不 shutdown 外部句柄 |
| `tls_connection::client_handshake(host, trust, error)` | 在已托管 socket（`attach` 之后）上执行客户端握手，不建立传输连接；信任语义与 `connect` 一致 |
| `tls_connection::owns_socket()` | 是否持有外部句柄所有权（`close()` 时是否关闭底层 fd） |
| `tls_connection::set_datagram_mode(enable, error)` | 数据报模式（UDP 链接）开关；`attach` 对 `SOCK_DGRAM` 自动启用，`enable=true` 要求底层为 UDP socket |
| `tls_connection::is_datagram()` | 是否数据报模式 |
| `tls_listener::attach(fd, take_ownership, error)` | 托管外部监听 socket（TCP 已 listen / UDP 已 bind，自动检测） |
| `tls_listener::owns_socket()` | 是否持有外部句柄所有权 |
| `tls_listener::is_udp()` | 是否 UDP 监听器 |
| `tls_listener::listen_udp(port, addr, error)` | UDP 链接：绑定 UDP 端口等待客户端握手（数据报模式） |
| `tls_listener::accept_udp(conn, cert_mgr, error)` | 接收一个 UDP 客户端并完成服务端握手（监听 socket 转交给 `conn`） |
| `tls_listener::listen(port, bind_addr, error)` | 监听端口（默认 `0.0.0.0`） |
| `tls_listener::accept(conn, cert_manager, error)` | 接受连接并自动完成服务端握手 |
| `tls_listener::close()` | 关闭监听 socket |
| `tls_connection::set_nonblocking(enable, error)` | 设置/取消非阻塞模式（可在 `connect` 之前调用）；非阻塞下 `send`/`recv` 遇 EAGAIN 立即返回 `false` + would-block |
| `tls_connection::would_block()` | 最近一次 I/O 是否因资源暂不可用而返回（仅非阻塞模式） |
| `tls_connection::wait_readable(ms)` / `wait_writable(ms)` | 等待 socket 可读 / 可写（事件循环用，`ms < 0` 无限等待） |
| `tls_connection::set_handshake_timeout(ms)` | 握手阶段有界等待超时（默认 30000 ms） |
| `tls_listener::set_nonblocking(enable, error)` | 监听 socket 非阻塞；`accept` 出的连接继承非阻塞状态 |
| `tls_connection::attach_co_executor(ex)` | 绑定协程执行器（`co_send`/`co_recv` 前置） |
| `tls_connection::co_send(data, len, error)` | 协程发送：写缓冲暂满时协程挂起，可写后由执行器恢复 |
| `tls_connection::co_recv(out, error)` | 协程接收：语义与 `recv()` 一致，无数据时挂起等待可读 |
| `tls_co_executor::run_once(ms)` / `run(ms)` | 驱动协程执行器：poll 就绪 + 恢复挂起协程 |

## 外部 fd 托管

`tls_connection` / `tls_listener` 均可托管调用方已创建的外部 socket 句柄（事件循环 / epoll / 自建连接等场景），并可选择是否持有句柄所有权：

```cpp
// 客户端：手动建立 TCP 连接后托管，再在已有 socket 上做 TLS 握手
int fd = socket(AF_INET, SOCK_STREAM, 0);
connect(fd, ...);                       // 调用方自己建连
tls_connection conn;
conn.attach(fd, /*take_ownership=*/true, &err);
conn.client_handshake("example.com", &trust, &err);  // 不重建 TCP
conn.send("GET / HTTP/1.1\r\n\r\n", &err);

// 借用模式：close() 不关闭外部 fd，生命周期由调用方管理
tls_connection borrowed;
borrowed.attach(fd, false, &err);       // owns_socket() == false
borrowed.server_handshake(cert_mgr, &err);
borrowed.close();                        // fd 仍有效，调用方自行释放
```

## UDP 链接（数据报模式）— ⚠️ 非标准，存在缺陷，仅限自研两端互通

`tls_connection` 支持在 UDP 上承载 TLS（数据报模式）：每条 TLS record（含握手消息）封装为一个 UDP 数据报发送——UDP 发送是原子的，整包成功或失败；`send()` 对大消息自动分片为多个数据报，`recv()` 自动合并还原。

```cpp
// 服务端：绑定 UDP 端口，接收首个 ClientHello 后固定对端并完成握手
tls_listener udp_listener;
udp_listener.listen_udp(8443, "0.0.0.0", &err);
tls_connection conn;
udp_listener.accept_udp(conn, cert_mgr, &err);   // 监听 socket 转交给 conn
conn.send("hello over udp", &err);

// 客户端：手动创建已 connect 的 UDP socket 后托管
int ufd = socket(AF_INET, SOCK_DGRAM, 0);
connect(ufd, ...);                      // 固定服务端地址
tls_connection client;
client.attach(ufd, true, &err);         // 自动检测 SOCK_DGRAM -> 数据报模式
client.client_handshake("example.com", &trust, &err);
std::vector<uint8_t> resp;
client.recv(resp, &err);
```

### ⚠️ 已知缺陷（与标准 DTLS / QUIC 不互通）

本数据报模式是**自研的简化封装，不是标准 DTLS，也不是 QUIC**：

- **非标准协议，无互操作性**：报文格式与 `DTLS`（[RFC 6347](https://www.rfc-editor.org/rfc/rfc6347) / [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)）和 `QUIC`（[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)）完全不同，无法与 OpenSSL、Wireshark、浏览器等标准实现互通，仅限本库客户端与服务端之间使用。
- **无抗 DoS 机制**：缺少 DTLS 的 `HelloVerifyRequest` 无状态 cookie，服务端对任意伪造源地址的 ClientHello 都会建立会话状态。
- **无握手分片 / 重传 / 乱序重组**：握手消息不按 `message_seq` 分片编号，无 flight 超时重传；UDP 丢包（尤其大证书链跨多个数据报时）直接导致握手失败，由调用方重试整个握手。
- **无防重放**：应用数据记录不带 epoch/sequence 滑动窗口，重放的旧数据报会被当作新数据接受。

**未来计划**：后续版本将实现标准 `DTLS 1.2/1.3`（[RFC 6347](https://www.rfc-editor.org/rfc/rfc6347) / [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)，含 cookie、握手分片/重传/乱序重组、防重放）以及 `QUIC + HTTP/3`（[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) / [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)），届时本数据报模式将被标准协议取代。在此之前，UDP 场景请评估上述缺陷，并优先考虑使用 TCP + TLS 或标准 DTLS 实现。

## 非阻塞模式（事件循环）

`tls_connection` / `tls_listener` 支持非阻塞模式，便于单线程事件循环复用同一线程服务大量连接：

```cpp
tls_listener listener;
listener.listen(443, "0.0.0.0");
listener.set_nonblocking(true);          // 无连接时 accept 返回 would-block

for (;;) {
    tls_connection conn;
    if (!listener.accept(conn, cert_mgr)) {
        if (listener.would_block()) { listener.wait_readable(100); continue; }
        break;                           // 真实错误
    }
    // accept 出的连接继承非阻塞状态
    std::vector<uint8_t> msg;
    if (!conn.recv(msg)) {
        if (conn.would_block()) { conn.wait_readable(100); continue; }
        break;
    }
    if (!conn.send("HTTP/1.1 200 OK\r\n\r\n")) {
        if (conn.would_block()) conn.wait_writable(100);
    }
}
```

- `set_nonblocking(true)` 可在 `connect` / `listen` 之前调用；非阻塞 `connect` 走 `EINPROGRESS` + poll 等待可写 + `SO_ERROR` 检查。
- `send()` / `recv()` 遇 `EAGAIN/EWOULDBLOCK` 立即返回 `false`（连接保持打开），配合 `would_block()` + `wait_readable()` / `wait_writable()` 重试。
- 握手阶段为有界等待（`set_handshake_timeout`，默认 30 秒），不会永久阻塞。

## 协程 I/O（C++20）

应用数据收发可写成协程：`co_send` / `co_recv` 在 socket 暂不可用时挂起，由执行器 `tls_co_executor` 在可读 / 可写时恢复，不阻塞任何线程：

```cpp
tls_co_executor ex;                   // 单线程 poll 驱动执行器，多连接共享

tls_connection conn;
conn.set_nonblocking(true);
conn.attach_co_executor(&ex);

tls_co_task<void> session() {         // 顶层协程任务（由持有者析构清理）
    bool ok = co_await conn.co_send("GET / HTTP/1.1\r\n\r\n");
    std::vector<uint8_t> resp;
    co_await conn.co_recv(resp);
}
auto task = session();
ex.run();                             // 驱动：poll 就绪并恢复挂起协程
```

- `tls_co_task<T>`：泛型协程任务（热启动 + 对称转换，零外部依赖）。
- `tls_co_executor`：单线程 poll 驱动执行器，多个连接共享；`run_once()` / `run()` 在 socket 就绪时恢复挂起协程。
- `co_send` / `co_recv` 语义与 `send` / `recv` 一致（自动分片/合并 record、跳过 NewSessionTicket）；使用前需 `set_nonblocking(true)` 并 `attach_co_executor(&ex)`。
- 可选增强：通过绑定的协程线程池（需 `threadpool` submodule）可使协程体并行运行在线程池工作线程上，相关内容在独立功能分支维护。

## 客户端验证

- **默认（推荐）**：只信任系统信任库中的 CA 根证书（`tls_trust_store::from_system()`，自动探测 `SSL_CERT_FILE` 环境变量与常见系统路径），对服务端证书链执行 x509 验证，含叶子证书主机名匹配。
- **显式自定义信任库**：`tls_trust_store::from_pem` / `from_pem_file` 加载自管 CA 根后传入 `connect`。
- **兼容旧行为**：传 `tls_certificate_manager*` 时按 SNI 名称查找预期服务器证书校验 CertificateVerify。

## 相关示例

- [HTTPS + 证书透明示例](Certificate-Transparency)
- [非阻塞 socket 示例](https://git.jphc.cn/lvshicheng/jpssl/-/tree/main/examples/tls_socket)：`nonblocking_echo` — 非阻塞监听 + 收发事件循环回环
- [协程 I/O 示例](https://git.jphc.cn/lvshicheng/jpssl/-/tree/main/examples/tls_socket)：`coroutine_echo` — 双端协程回环
：`examples/https/` 的服务器与客户端基于本封装层实现，演示完整 HTTP 消息往返与 CT 审计端点。

## kTLS（内核 TLS 记录层卸载，Linux）

`include/ktls.hpp` / `src/ktls.cpp` 提供 **Linux 内核 TLS（kTLS）** 支持：握手仍在用户态完成后，把会话密钥通过 `setsockopt(SOL_TCP, TCP_ULP, "tls")` + `setsockopt(SOL_TLS, TLS_TX/TLS_RX, &crypto_info)` 交给内核，此后应用数据以明文直接 `send/recv`，由内核负责 TLS record 封装与加解密，降低系统调用与加解密开销。

- **平台要求**：仅 Linux 内核 >= 4.13 且开启 `CONFIG_TLS`；其他平台（Windows / macOS / 不支持的内核）`ktls_is_supported()` 返回 `ktls_result::unsupported`，`enable_ktls()` 返回 `false` 并给出原因，优雅降级，不影响既有 TLS/DTLS 功能。
- **套件映射**：TLS 1.2 / 1.3 的 AES-GCM-128/256、ChaCha20-Poly1305、AES-CCM、SM4-GCM/CCM。
- **前提**：流式（TCP）socket、握手已完成、协商套件在内核 kTLS 支持列表内。

```cpp
tls_connection conn;
if (conn.connect("example.com", 443)) {      // 用户态完成 TLS 1.3 握手
    std::string err;
    if (conn.enable_ktls(&err)) {              // 把会话密钥交给 Linux 内核
        conn.send("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); // 明文直通
        std::vector<uint8_t> resp;
        conn.recv(resp);                       // 内核解密后返回明文
    } else {
        // 内核不支持 kTLS：仍走用户态加解密，功能不受影响
    }
}
```

`ktls_active()` 可查询是否已激活明文直通模式；激活后 `send()` / `recv()` 直接读写明文，不再经用户态 `tls_encrypt` / `tls_decrypt`。

### 底层 API（`ktls.hpp`，消息级）

| 函数 | 说明 |
|------|------|
| `ktls_result ktls_is_supported()` | 检测当前系统是否支持 kTLS（仅 Linux 且内核开启 `CONFIG_TLS`） |
| `ktls_result ktls_export_params(const tls_session& s, ktls_params& out)` | 从已握手完成的 `tls_session` 导出 TX/RX 密钥材料（key/iv/salt/rec_seq） |
| `ktls_result ktls_enable(const ktls_params& p, int fd, std::string* error)` | 在已连接、已握手完成的 TCP socket 上启用内核 TLS，成功后 fd 进入明文直通模式 |

`ktls_result` 枚举：`ok` / `unsupported` / `not_stream` / `invalid_params` / `handshake_pending` / `cipher_unsupported` / `syscall_failed`。

单元测试：`tests/test_ktls.cpp`（16 项，已接入 ctest）。
