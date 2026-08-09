/**
 * tls_socket.cpp -- TLS-over-TCP socket 封装层实现
 *
 * 记录层约定（与本库 tls.cpp 保持一致）：
 *   - 明文握手消息：封装为 type=22 (HANDSHAKE) 的 record。
 *   - 加密握手 / 应用数据：tls_encrypt / tls_encrypt_handshake 产出
 *     `17 03 03 <len>` 的 record，直接透传。
 *   - 服务端 flight 由 make_server_flight 产出“裸 ServerHello + 一条加密
 *     record”的混合缓冲，发送时拆分处理。
 */
#include "tls_socket.hpp"

#include <chrono>
#include <cstring>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
// Windows 无 poll.h：为 tls_co_executor 提供最小兼容定义
#ifndef POLLIN
#define POLLIN  0x0300
#define POLLOUT 0x0400
#define POLLERR 0x0008
#define POLLHUP 0x0010
struct pollfd {
    int fd;
    short events;
    short revents;
};
#endif
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#endif

namespace jpssl::tls {

// 版本选择（定义于 tls_router.cpp）：
//   客户端按配置选择 TLS 1.2 / TLS 1.3 握手路径；
//   服务端解析 ClientHello 的 supported_versions 扩展判断是否支持 TLS 1.3。
bool tls_router_client_use_tls12(TLSVersion configured);
bool tls_router_server_supports_tls13(const uint8_t* client_hello, size_t ch_len);

namespace {

// 判断最后一次系统调用是否因资源暂不可用而失败：
// EAGAIN/EWOULDBLOCK（send/recv）或 EINPROGRESS（非阻塞 connect 进行中）。
bool is_would_block() {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS;
#endif
}

// 设置/清除 socket 的非阻塞标志
bool set_socket_nonblocking(socket_handle_t fd, bool enable) {
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    if (enable) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags) == 0;
#endif
}

// 用 poll/select 等待 socket 可读(for_write=false)或可写(for_write=true)。
// timeout_ms < 0 表示无限等待；返回 true 表示已就绪，false 表示超时或错误。
bool wait_fd(int fd, bool for_write, int timeout_ms) {
#ifdef _WIN32
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = ::select(0, for_write ? nullptr : &fds, for_write ? &fds : nullptr,
                      nullptr, timeout_ms >= 0 ? &tv : nullptr);
    return rc > 0;
#else
    pollfd pfd;
    pfd.fd = fd;
    pfd.events = (short)(for_write ? POLLOUT : POLLIN);
    pfd.revents = 0;
    int rc = ::poll(&pfd, 1, timeout_ms);
    return rc > 0 && (pfd.revents & (for_write ? POLLOUT : POLLIN));
#endif
}

// RAII：标记握手阶段。非阻塞模式下，握手内部 I/O 遇 EAGAIN 时有界等待而非返回
struct handshake_guard {
    bool& flag;
    explicit handshake_guard(bool& f) : flag(f) { flag = true; }
    ~handshake_guard() { flag = false; }
};

// 重置会话状态，但保留调用方在 connect/accept 之前预先配置的
// ALPN 协议列表、签名方案列表、密钥交换组与目标加密套件
// （避免被 tls_session{} 清空；cipher_suite 用于互操作/组合测试
// 指定期望协商的 TLS 1.3 套件）。
void reset_session_preserving_config(tls_session& s) {
    auto alpn = s.alpn_protos;
    auto salgs = s.sig_algs;
    auto salgs_cert = s.sig_algs_cert;
    auto ks = s.ks_group;
    auto cs = s.cipher_suite;
    auto psk12_valid = s.tls12_psk_valid;
    auto psk12_id_len = s.tls12_psk_identity_len;
    auto psk12_val_len = s.tls12_psk_value_len;
    uint8_t psk12_id[128], psk12_val[64];
    memcpy(psk12_id, s.tls12_psk_identity, sizeof(psk12_id));
    memcpy(psk12_val, s.tls12_psk_value, sizeof(psk12_val));
    s = tls_session{};
    s.alpn_protos = std::move(alpn);
    s.sig_algs = std::move(salgs);
    s.sig_algs_cert = std::move(salgs_cert);
    s.ks_group = ks;
    s.cipher_suite = cs;
    s.tls12_psk_valid = psk12_valid;
    s.tls12_psk_identity_len = psk12_id_len;
    s.tls12_psk_value_len = psk12_val_len;
    memcpy(s.tls12_psk_identity, psk12_id, sizeof(s.tls12_psk_identity));
    memcpy(s.tls12_psk_value, psk12_val, sizeof(s.tls12_psk_value));
}

// poll 多个 fd（POSIX poll / Windows select）。就绪 fd 的 revents 被设置。
// 返回就绪数量；0 超时；<0 错误。
static int poll_multi(std::vector<pollfd>& pfds, int timeout_ms) {
#ifdef _WIN32
    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    int maxfd = 0;
    for (const auto& p : pfds) {
        if (p.events & POLLIN) FD_SET(p.fd, &rfds);
        if (p.events & POLLOUT) FD_SET(p.fd, &wfds);
        if (p.fd > maxfd) maxfd = p.fd;
    }
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = ::select(maxfd + 1, &rfds, &wfds, nullptr,
                      timeout_ms >= 0 ? &tv : nullptr);
    if (rc <= 0) {
        for (auto& p : pfds) p.revents = 0;
        return rc;
    }
    int n = 0;
    for (auto& p : pfds) {
        p.revents = 0;
        if (FD_ISSET(p.fd, &rfds)) p.revents |= POLLIN;
        if (FD_ISSET(p.fd, &wfds)) p.revents |= POLLOUT;
        if (p.revents) n++;
    }
    return n;
#else
    int rc = ::poll(pfds.data(), (nfds_t)pfds.size(), timeout_ms);
    if (rc <= 0)
        for (auto& p : pfds) p.revents = 0;
    return rc;
#endif
}

// 协程等待器：socket 暂不可用时挂起，执行器 poll 就绪后恢复
struct socket_wait_awaiter {
    int fd_;
    bool for_write_;
    tls_co_executor* ex_;
    std::coroutine_handle<> h_{};

    socket_wait_awaiter(tls_connection& c, bool for_write)
        : fd_((int)c.native()), for_write_(for_write), ex_(c.co_executor()) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        h_ = h;
        if (ex_) ex_->add_waiter(fd_, for_write_, h_);
    }
    void await_resume() noexcept {}
};

void set_err(std::string* error, const std::string& msg) {
    if (error) *error = msg;
}

std::string last_socket_error() {
#ifdef _WIN32
    int e = WSAGetLastError();
    char buf[256] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, (DWORD)e, 0, buf, (DWORD)sizeof(buf), nullptr);
    std::string msg(buf);
    while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n')) msg.pop_back();
    return msg.empty() ? ("error " + std::to_string(e)) : msg;
#else
    return std::string(std::strerror(errno));
#endif
}

// 构造一条明文 record：type + 0x03 0x03 + 16 位长度 + payload
std::vector<uint8_t> make_record(uint8_t type, const uint8_t* payload, size_t len) {
    std::vector<uint8_t> rec;
    rec.reserve(5 + len);
    rec.push_back(type);
    rec.push_back(0x03);
    rec.push_back(0x03);
    rec.push_back((uint8_t)(len >> 8));
    rec.push_back((uint8_t)(len & 0xFF));
    rec.insert(rec.end(), payload, payload + len);
    return rec;
}

} // namespace

// ============================================================================
// 初始化
// ============================================================================

bool tls_socket_init(std::string* error) {
#ifdef _WIN32
    static std::once_flag once;
    static bool ok = false;
    static std::string fail_msg;
    std::call_once(once, [] {
        WSADATA wsa;
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        if (!ok) fail_msg = "WSAStartup failed";
    });
    if (!ok) set_err(error, fail_msg);
    return ok;
#else
    (void)error;
    return true;
#endif
}

// ============================================================================
// tls_co_executor —— 单线程 poll 驱动
// ============================================================================

void tls_co_executor::add_waiter(int fd, bool for_write,
                                 std::coroutine_handle<> h) {
    waiters_.push_back({fd, for_write, h});
}

bool tls_co_executor::run_once(int timeout_ms) {
    if (waiters_.empty()) return false;

    std::vector<pollfd> pfds;
    pfds.reserve(waiters_.size());
    for (const auto& w : waiters_) {
        // 成员赋值而非列表初始化：winsock2.h 的 pollfd.fd 是 SOCKET，直接窄化会触发 C2397
        pollfd pfd{};
        pfd.fd = w.fd;
        pfd.events = (short)(w.for_write ? POLLOUT : POLLIN);
        pfd.revents = 0;
        pfds.push_back(pfd);
    }

    int rc = poll_multi(pfds, timeout_ms);
    if (rc <= 0) return false;

    // 先收集就绪协程再逐个恢复：resume 可能注册新的 waiter（如继续读下一条
    // record），不能边遍历边改 waiters_。
    std::vector<std::coroutine_handle<>> ready;
    for (size_t i = waiters_.size(); i-- > 0;) {
        short want = (short)(waiters_[i].for_write ? POLLOUT : POLLIN);
#ifdef _WIN32
        if (pfds[i].revents & want) {
#else
        // POLLERR/POLLHUP/POLLNVAL 也必须恢复协程：否则 poll 一直返回错误事件
        // 而 waiter 永不匹配，run() 会无限循环（Linux 上 test_tls_socket 卡死）。
        if ((pfds[i].revents & want) ||
            (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL))) {
#endif
            ready.push_back(waiters_[i].h);
            waiters_.erase(waiters_.begin() + i);
        }
    }
    for (auto h : ready) h.resume();
    return !ready.empty();
}

void tls_co_executor::run(int timeout_ms) {
    while (!waiters_.empty()) run_once(timeout_ms);
}

// ============================================================================
// tls_connection
// ============================================================================

tls_connection::tls_connection() = default;

tls_connection::~tls_connection() {
    close();
}

void tls_connection::close() {
    if (open_ && sock_ != INVALID_SOCKET_HANDLE && owns_socket_) {
        // 借用模式（attach take_ownership=false）不 shutdown、不关闭，
        // 句柄生命周期由调用方管理。
#ifdef _WIN32
        shutdown(sock_, SD_BOTH);
#else
        shutdown(sock_, SHUT_RDWR);
#endif
        close_socket_handle(sock_);
    }
    sock_ = INVALID_SOCKET_HANDLE;
    open_ = false;
    owns_socket_ = true; // 复位默认（下次 attach 重新决定）
    datagram_ = false;
    would_block_ = false;
    handshake_pending_ = false;
    rbuf_.clear();
}

// 托管外部 socket 句柄（TCP 已连接 / accept 出的连接 / UDP 已 connect 或已 bind）
bool tls_connection::attach(socket_handle_t fd, bool take_ownership,
                            std::string* error) {
    if (fd == INVALID_SOCKET_HANDLE) {
        set_err(error, "attach: invalid socket handle");
        return false;
    }
    close();
    sock_ = fd;
    open_ = true;
    owns_socket_ = take_ownership;
    would_block_ = false;
    handshake_pending_ = false;
    rbuf_.clear();
    reset_session_preserving_config(session_);
    // 自动检测 UDP：SOCK_DGRAM -> 数据报模式（每条 TLS record 一个数据报）
    int type = 0;
#ifdef _WIN32
    int tlen = sizeof(type);
#else
    socklen_t tlen = sizeof(type);
#endif
    datagram_ = (getsockopt(fd, SOL_SOCKET, SO_TYPE, (char*)&type, &tlen) == 0 &&
                 type == SOCK_DGRAM);
    if (!datagram_) set_tcp_nodelay(); // UDP 无 TCP_NODELAY，跳过
    return true;
}

// 数据报模式开关（attach 对 UDP 自动启用，这里可手动覆盖）
bool tls_connection::set_datagram_mode(bool enable, std::string* error) {
    if (enable) {
        int type = 0;
#ifdef _WIN32
        int tlen = sizeof(type);
#else
        socklen_t tlen = sizeof(type);
#endif
        if (sock_ == INVALID_SOCKET_HANDLE ||
            getsockopt(sock_, SOL_SOCKET, SO_TYPE, (char*)&type, &tlen) != 0 ||
            type != SOCK_DGRAM) {
            set_err(error, "datagram mode requires a SOCK_DGRAM socket");
            return false;
        }
    }
    datagram_ = enable;
    return true;
}

void tls_connection::set_tcp_nodelay() {
    int one = 1;
    setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
}

// 数据报模式：单次发送一个完整 UDP 数据报（一条 TLS record）。
// UDP 发送原子：要么整包成功，要么返回错误/would-block，不会部分发送。
bool tls_connection::send_one_datagram(const uint8_t* data, size_t len,
                                       std::string* error) {
    const auto start = std::chrono::steady_clock::now();
    for (;;) {
        // 握手阶段：即使阻塞模式也先做有界可写等待，避免对端停止接收时永久阻塞
        if (handshake_pending_) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - start)
                               .count();
            int remain = handshake_timeout_ms_ - (int)elapsed;
            if (remain <= 0 || !wait_fd(sock_, true, remain)) {
                set_err(error, "handshake write timeout");
                close();
                return false;
            }
        }
        int w = (int)::send(sock_, (const char*)data, (int)len, 0);
        if (w > 0) return true; // 整包发出
        if (w == 0) {
            set_err(error, "send failed: connection closed");
            close();
            return false;
        }
        // w < 0：错误或资源暂不可用
        if (!is_would_block()) {
            set_err(error, "send failed: " + last_socket_error());
            close();
            return false;
        }
        if (nonblocking_ && !handshake_pending_) {
            // 非阻塞模式 + 应用数据阶段：立即返回 would-block，不关闭连接
            would_block_ = true;
            set_err(error, "would block");
            return false;
        }
        // 握手阶段（或阻塞模式）：有界等待可写后重试
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
        int remain = handshake_timeout_ms_ - (int)elapsed;
        if (remain <= 0 || !wait_fd(sock_, true, remain)) {
            set_err(error, "handshake write timeout");
            close();
            return false;
        }
    }
}

bool tls_connection::write_all(const uint8_t* data, size_t len, std::string* error) {
    if (!open_ || sock_ == INVALID_SOCKET_HANDLE) {
        set_err(error, "connection not open");
        return false;
    }
    if (datagram_) {
        // 数据报模式：字节流由若干条 TLS record 拼接而成（record 头自描述
        // 5 字节长度），逐条切分，每条 record 封装为一个 UDP 数据报发送。
        size_t off = 0;
        while (off < len) {
            if (len - off < 5) {
                set_err(error, "datagram: truncated TLS record header");
                close();
                return false;
            }
            size_t rlen = ((size_t)data[off + 3] << 8) | data[off + 4];
            if (off + 5 + rlen > len) {
                set_err(error, "datagram: truncated TLS record");
                close();
                return false;
            }
            if (!send_one_datagram(data + off, 5 + rlen, error)) return false;
            off += 5 + rlen;
        }
        return true;
    }
    size_t off = 0;
    const auto start = std::chrono::steady_clock::now();
    while (off < len) {
        // 握手阶段：即使阻塞模式也先做有界可写等待，避免对端停止接收时永久阻塞
        if (handshake_pending_) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - start)
                               .count();
            int remain = handshake_timeout_ms_ - (int)elapsed;
            if (remain <= 0 || !wait_fd(sock_, true, remain)) {
                set_err(error, "handshake write timeout");
                close();
                return false;
            }
        }
        int w = (int)::send(sock_, (const char*)data + off, (int)(len - off), 0);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w == 0) {
            set_err(error, "send failed: connection closed");
            close();
            return false;
        }
        // w < 0：错误或资源暂不可用
        if (!is_would_block()) {
            set_err(error, "send failed: " + last_socket_error());
            close();
            return false;
        }
        if (nonblocking_ && !handshake_pending_) {
            // 非阻塞模式 + 应用数据阶段：立即返回 would-block，不关闭连接
            would_block_ = true;
            set_err(error, "would block");
            return false;
        }
        // 握手阶段（或阻塞模式）：有界等待可写后重试
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
        int remain = handshake_timeout_ms_ - (int)elapsed;
        if (remain <= 0 || !wait_fd(sock_, true, remain)) {
            set_err(error, "handshake write timeout");
            close();
            return false;
        }
    }
    return true;
}

// 从 socket 读入数据追加到 rbuf_ 尾部，直到 rbuf_.size() >= min_total。
// 非阻塞应用数据阶段遇 EAGAIN 时返回 false 并置 would_block_（已读部分保留在 rbuf_）。
bool tls_connection::fill_rbuf(size_t min_total, std::string* error) {
    if (!open_ || sock_ == INVALID_SOCKET_HANDLE) {
        set_err(error, "connection not open");
        return false;
    }
    const auto start = std::chrono::steady_clock::now();
    while (rbuf_.size() < min_total) {
        // 握手阶段：即使阻塞模式也先做有界可读等待，避免对端停止发送时永久阻塞
        if (handshake_pending_) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - start)
                               .count();
            int remain = handshake_timeout_ms_ - (int)elapsed;
            if (remain <= 0 || !wait_fd(sock_, false, remain)) {
                set_err(error, "handshake read timeout");
                close();
                return false;
            }
        }
        // 数据报模式：一次 recv 拿一个完整 UDP 数据报（最多 64KiB，
        // 单条 record 上限 16KiB+256 开销，一个数据报恰一条 record）；
        // TCP 模式：按需增量读取，处理半包/粘包。
        size_t want = datagram_ ? (size_t)65536
                                : std::min<size_t>(4096, min_total - rbuf_.size());
        size_t old = rbuf_.size();
        rbuf_.resize(old + want);
        int r = (int)::recv(sock_, (char*)rbuf_.data() + old, (int)want, 0);
        if (r > 0) {
            rbuf_.resize(old + (size_t)r);
            continue;
        }
        rbuf_.resize(old); // 恢复，丢弃本次空读
        if (r == 0) {
            set_err(error, "connection closed by peer");
            close();
            return false;
        }
        // r < 0：错误或资源暂不可用
        if (!is_would_block()) {
            set_err(error, "recv failed: " + last_socket_error());
            close();
            return false;
        }
        if (nonblocking_ && !handshake_pending_) {
            // 非阻塞模式 + 应用数据阶段：已读入 rbuf_ 的部分保留，返回 would-block
            would_block_ = true;
            set_err(error, "would block");
            return false;
        }
        // 握手阶段（或阻塞模式）：有界等待可读后重试
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
        int remain = handshake_timeout_ms_ - (int)elapsed;
        if (remain <= 0 || !wait_fd(sock_, false, remain)) {
            set_err(error, "handshake read timeout");
            close();
            return false;
        }
    }
    return true;
}

bool tls_connection::read_record(uint8_t& type, std::vector<uint8_t>& payload, std::string* error) {
    // 先确保 rbuf_ 中攒齐 5 字节 record 头
    if (!fill_rbuf(5, error)) return false;
    type = rbuf_[0];
    size_t len = ((size_t)rbuf_[3] << 8) | rbuf_[4];
    // TLS 明文上限 2^14，加上 AEAD tag 等开销
    if (len > 16384 + 256) {
        set_err(error, "TLS record too large");
        close();
        return false;
    }
    // 攒齐整条 record 后切出 payload 并消费
    if (!fill_rbuf(5 + len, error)) return false;
    payload.assign(rbuf_.begin() + 5, rbuf_.begin() + 5 + len);
    rbuf_.erase(rbuf_.begin(), rbuf_.begin() + 5 + len);
    return true;
}

bool tls_connection::more_data_pending() const {
    // 内部缓冲（半包）尚有未消费字节，或内核接收队列非空，都视为“仍有已到达数据”
    if (!rbuf_.empty()) return true;
#ifdef _WIN32
    u_long n = 0;
    return ioctlsocket(sock_, FIONREAD, &n) == 0 && n > 0;
#else
    int n = 0;
    return ioctl(sock_, FIONREAD, &n) == 0 && n > 0;
#endif
}

bool tls_connection::establish_tcp(const std::string& host, uint16_t port,
                                    std::string* error) {
    close();
    if (!tls_socket_init(error)) return false;

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        set_err(error, "getaddrinfo(" + host + "): " + gai_strerror(rc));
        return false;
    }

    socket_handle_t fd = INVALID_SOCKET_HANDLE;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == INVALID_SOCKET_HANDLE) continue;
        // 非阻塞模式下，TCP 连接建立本身也采用非阻塞方式：
        // 返回 EINPROGRESS/WSAEWOULDBLOCK 时用 poll 等待可写并检查 SO_ERROR
        // （受 set_handshake_timeout 约束），完成后 socket 保持非阻塞。
        if (nonblocking_) set_socket_nonblocking(fd, true);
        if (::connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        if (nonblocking_ && is_would_block()) {
            if (wait_fd(fd, true, handshake_timeout_ms_)) {
                int soerr = 0;
#ifdef _WIN32
                int slen = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&soerr, &slen) == 0 &&
                    soerr == 0)
                    break;
#else
                socklen_t slen = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0)
                    break;
#endif
            }
        }
        close_socket_handle(fd);
        fd = INVALID_SOCKET_HANDLE;
    }
    freeaddrinfo(res);
    if (fd == INVALID_SOCKET_HANDLE) {
        set_err(error, "TCP connect failed: " + last_socket_error());
        return false;
    }

    sock_ = fd;
    open_ = true;
    set_tcp_nodelay();
    reset_session_preserving_config(session_);
    session_.server_name = host;
    return true;
}

bool tls_connection::connect(const std::string& host, uint16_t port,
                             const tls_certificate_manager* trust_store,
                             std::string* error) {
    if (!establish_tcp(host, port, error)) return false;
    if (trust_store) return do_client_handshake(trust_store, nullptr, error);
    // 默认只信任系统信任库中的 CA 根证书：
    // 对服务端证书链执行 x509 验证，验证失败或系统信任库不可用则握手失败。
    auto sys = tls_trust_store::from_system();
    if (sys.empty()) {
        set_err(error, "no system trust store available (set SSL_CERT_FILE or install system CA bundle)");
        return false;
    }
    return do_client_handshake(nullptr, &sys, error);
}

bool tls_connection::connect(const std::string& host, uint16_t port,
                             const tls_trust_store& trust,
                             std::string* error) {
    if (!establish_tcp(host, port, error)) return false;
    return do_client_handshake(nullptr, &trust, error);
}

// 客户端：在已托管的 socket（attach 之后）上执行 TLS 1.3 客户端握手，
// 不建立传输连接。trust_store == nullptr 时走系统信任库。
bool tls_connection::client_handshake(const std::string& host,
                                      const tls_certificate_manager* trust_store,
                                      std::string* error) {
    if (!open_ || sock_ == INVALID_SOCKET_HANDLE) {
        set_err(error, "client_handshake: no socket attached (call attach first)");
        return false;
    }
    session_.server_name = host;
    if (trust_store) return do_client_handshake(trust_store, nullptr, error);
    auto sys = tls_trust_store::from_system();
    if (sys.empty()) {
        set_err(error, "no system trust store available (set SSL_CERT_FILE or install system CA bundle)");
        return false;
    }
    return do_client_handshake(nullptr, &sys, error);
}

bool tls_connection::client_handshake(const std::string& host,
                                      const tls_trust_store& trust,
                                      std::string* error) {
    if (!open_ || sock_ == INVALID_SOCKET_HANDLE) {
        set_err(error, "client_handshake: no socket attached (call attach first)");
        return false;
    }
    session_.server_name = host;
    return do_client_handshake(nullptr, &trust, error);
}

bool tls_connection::do_client_handshake(const tls_certificate_manager* trust_store,
                                         const tls_trust_store* trust,
                                         std::string* error) {
    if (tls_router_client_use_tls12(tls_version_))
        return do_client_handshake_tls12(trust_store, trust, error);

    handshake_guard hg(handshake_pending_);
    // 1. ClientHello（裸握手消息）→ 封装为明文 record 发送
    std::vector<uint8_t> ch;
    if (!tls13_make_client_hello(session_, ch)) {
        set_err(error, "tls13_make_client_hello failed");
        return false;
    }
    auto ch_record = make_record((uint8_t)ContentType::HANDSHAKE, ch.data(), ch.size());
    if (!write_all(ch_record.data(), ch_record.size(), error)) return false;

    // 2. 读取服务端 flight：
    //    明文握手 record（type 22）→ 提取裸消息；
    //    加密 record（type 23）→ 原样保留（含 record 头）。
    //    OpenSSL 等服务端可能把 EE/Cert/CV/SF 拆成多条加密 record 发送，
    //    仅读第一条会导致 transcript 缺失后续消息（握手假成功、应用数据
    //    解密失败）。因此：收集到"暂无可读数据"后，用会话副本尝试解析，
    //    只有解析到 Server Finished 才算完整；否则继续阻塞读取对端剩余
    //    record（socket 有超时兜底）。
    std::vector<uint8_t> flight;
    bool got_sh = false;
    bool done = false;
    std::vector<uint8_t> client_finished;
    while (!done) {
        if (got_sh && !more_data_pending()) {
            // 当前无更多可读数据：副本试错解析（失败不改动 session_）
            tls_session trial = session_;
            std::vector<uint8_t> cf;
            if (tls13_process_server_flight(trial, flight.data(), flight.size(), cf,
                                            trust_store, trust) &&
                trial.server_finished_received) {
                session_ = std::move(trial);
                client_finished = std::move(cf);
                done = true;
                break;
            }
            // 解析失败：可能是 flight 不完整（对端还会发剩余 record），也可能是
            // 致命错误（如证书验证失败）。短暂有界等待后仍无新数据即判失败，
            // 避免阻塞模式下永久等待（对端已停止发送时）。
            if (!wait_fd(sock_, false, 250)) {
                tls_session trial2 = session_;
                std::vector<uint8_t> cf2;
                if (tls13_process_server_flight(trial2, flight.data(), flight.size(), cf2,
                                                trust_store, trust) &&
                    trial2.server_finished_received) {
                    session_ = std::move(trial2);
                    client_finished = std::move(cf2);
                    done = true;
                    break;
                }
                set_err(error, "TLS 1.3 server flight incomplete or verification failed");
                return false;
            }
        }
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) {
            // 对端关闭或超时：以当前 flight 做最后一次解析尝试
            if (got_sh && !flight.empty()) {
                tls_session trial = session_;
                std::vector<uint8_t> cf;
                if (tls13_process_server_flight(trial, flight.data(), flight.size(), cf,
                                                trust_store, trust) &&
                    trial.server_finished_received) {
                    session_ = std::move(trial);
                    client_finished = std::move(cf);
                    done = true;
                }
            }
            break;
        }
        if (rtype == (uint8_t)ContentType::HANDSHAKE) {
            flight.insert(flight.end(), payload.begin(), payload.end());
            got_sh = true;
        } else if (rtype == (uint8_t)ContentType::APPLICATION_DATA) {
            auto rec = make_record(rtype, payload.data(), payload.size());
            flight.insert(flight.end(), rec.begin(), rec.end());
        } else if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert during handshake");
            return false;
        }
        // CCS（type 20）等兼容性记录直接忽略
    }

    // 3. 发送加密的 Client Finished record
    if (client_finished.empty()) {
        set_err(error, "TLS 1.3 服务端 flight 不完整或解析失败");
        return false;
    }
    if (!write_all(client_finished.data(), client_finished.size(), error)) return false;
    return true;
}

// TLS 1.2 客户端握手（RFC 5246）：ClientHello → 明文服务端 flight
// （ServerHello + [Certificate] + [ServerKeyExchange] + ServerHelloDone）
// → ClientKeyExchange → 客户端 CCS + 加密 Finished → 服务端 CCS + 加密 Finished。
bool tls_connection::do_client_handshake_tls12(const tls_certificate_manager* trust_store,
                                               const tls_trust_store* trust,
                                               std::string* error) {
    handshake_guard hg(handshake_pending_);

    // 1. ClientHello（裸握手消息）→ 明文 record
    std::vector<uint8_t> ch;
    if (!tls12_make_client_hello(session_, ch)) {
        set_err(error, "tls12_make_client_hello failed");
        return false;
    }
    auto ch_record = make_record((uint8_t)ContentType::HANDSHAKE, ch.data(), ch.size());
    if (!write_all(ch_record.data(), ch_record.size(), error)) return false;

    // 2. 读取明文服务端 flight：OpenSSL 等服务端把 ServerHello / Certificate /
    //    ServerKeyExchange / ServerHelloDone 拆成多条 record 发送，逐条累积裸
    //    握手消息，直到收到完整 ServerHelloDone 为止。
    std::vector<uint8_t> flight;
    bool shd = false;
    while (!shd) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) return false;
        if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert during handshake");
            return false;
        }
        if (rtype != (uint8_t)ContentType::HANDSHAKE) continue;
        flight.insert(flight.end(), payload.begin(), payload.end());
        size_t off = 0;
        while (off + 4 <= flight.size()) {
            size_t hlen = ((size_t)flight[off+1] << 16) |
                          ((size_t)flight[off+2] << 8) | flight[off+3];
            if (off + 4 + hlen > flight.size()) break; // 消息不完整，等待后续 record
            if (flight[off] == (uint8_t)HandshakeType::SERVER_HELLO_DONE) {
                shd = true;
                break;
            }
            off += 4 + hlen;
        }
    }

    // 3. 解析服务端 flight：生成 ClientKeyExchange + Client Finished。
    //    ECDHE/DHE/PSK 套件的 premaster 由库内部计算；RSA 套件需调用方
    //    生成 48 字节 premaster（version 0x0303 + 46 随机字节）传入。
    uint8_t rsa_pms[48];
    rsa_pms[0] = 0x03; rsa_pms[1] = 0x03;
    jpssl::secure_rand_bytes(rsa_pms + 2, sizeof(rsa_pms) - 2);
    tls_session trial = session_;
    std::vector<uint8_t> cf, cke;
    if (!tls12_process_server_flight(trial, flight.data(), flight.size(),
                                     rsa_pms, sizeof(rsa_pms), cf, &cke,
                                     trust_store, trust)) {
        set_err(error, "tls12_process_server_flight failed");
        return false;
    }
    session_ = std::move(trial);

    // 4. 发送 ClientKeyExchange（明文 handshake record）
    if (cke.empty()) {
        set_err(error, "tls12 client key exchange empty");
        return false;
    }
    auto cke_record = make_record((uint8_t)ContentType::HANDSHAKE, cke.data(), cke.size());
    if (!write_all(cke_record.data(), cke_record.size(), error)) return false;

    // 5. 发送 ChangeCipherSpec（明文）+ 加密的 Client Finished
    auto ccs = tls_make_change_cipher_spec();
    if (!write_all(ccs.data(), ccs.size(), error)) return false;
    std::vector<uint8_t> cf_enc = tls_encrypt(session_, ContentType::HANDSHAKE,
                                              cf.data(), cf.size());
    if (cf_enc.empty()) {
        set_err(error, "tls12 client finished encrypt failed");
        return false;
    }
    if (!write_all(cf_enc.data(), cf_enc.size(), error)) return false;

    // 6. 读取服务端 ChangeCipherSpec（明文）
    while (true) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) return false;
        if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert during handshake");
            return false;
        }
        if (rtype == (uint8_t)ContentType::CHANGE_CIPHER_SPEC) break;
    }

    // 7. 读取加密的 Server Finished 并校验（transcript 已含客户端 Finished）
    std::vector<uint8_t> sf_plain;
    while (true) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) return false;
        if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert during handshake");
            return false;
        }
        if (rtype != (uint8_t)ContentType::HANDSHAKE) continue;
        auto rec = make_record(rtype, payload.data(), payload.size());
        ContentType ct = ContentType::HANDSHAKE;
        if (!tls_decrypt(session_, rec.data(), rec.size(), ct, sf_plain)) {
            set_err(error, "tls_decrypt server finished failed");
            return false;
        }
        if (sf_plain.size() >= 4 &&
            sf_plain[0] == (uint8_t)HandshakeType::FINISHED) break;
    }
    if (!tls12_verify_finished(session_, sf_plain.data(), sf_plain.size(),
                               /*for_server=*/true)) {
        set_err(error, "tls12 server finished verify failed");
        return false;
    }

    session_.tls12_secure = true;
    return true;
}

bool tls_connection::server_handshake(const tls_certificate_manager& cert_manager,
                                      std::string* error) {
    reset_session_preserving_config(session_);
    return do_server_handshake(cert_manager, nullptr, error);
}

bool tls_connection::server_handshake(const tls_certificate_manager& cert_manager,
                                      const tls_psk_store& psk_store,
                                      std::string* error) {
    reset_session_preserving_config(session_);
    return do_server_handshake(cert_manager, &psk_store, error);
}

bool tls_connection::do_server_handshake(const tls_certificate_manager& cert_manager,
                                         const tls_psk_store* psk_store,
                                         std::string* error) {
    handshake_guard hg(handshake_pending_);
    // 1. 读取 ClientHello（裸握手消息，可能跨多条 record）
    std::vector<uint8_t> ch;
    while (true) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) return false;
        if (rtype == (uint8_t)ContentType::HANDSHAKE) {
            ch.insert(ch.end(), payload.begin(), payload.end());
        } else if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert during handshake");
            return false;
        }
        if (ch.size() >= 4 && ch[0] == (uint8_t)HandshakeType::CLIENT_HELLO) {
            size_t ch_len = ((size_t)ch[1] << 16) | ((size_t)ch[2] << 8) | ch[3];
            if (ch.size() >= 4 + ch_len) break;
        }
    }

    // 1.5 版本协商（tls_router.cpp）：TLS 1.3 客户端发送 legacy_version=0x0303
    //     + supported_versions 扩展(0x002b)；仅支持 TLS 1.2 的客户端
    //     legacy_version=0x0303 且无 supported_versions 或只有 0x0303。
    size_t ch_msg_len = ((size_t)ch[1] << 16) | ((size_t)ch[2] << 8) | ch[3];
    size_t ch_total = 4 + ch_msg_len;
    bool client_supports_13 = tls_router_server_supports_tls13(ch.data(), ch_total);
    if (!client_supports_13) {
        // ── TLS 1.2 服务端握手 ──
        std::vector<uint8_t> hello_flight;
        if (!tls12_make_server_hello_flight(session_, ch.data(), ch_total,
                                            hello_flight, cert_manager, psk_store)) {
            set_err(error, "tls12_make_server_hello_flight failed");
            return false;
        }
        auto hello_rec = make_record((uint8_t)ContentType::HANDSHAKE,
                                     hello_flight.data(), hello_flight.size());
        if (!write_all(hello_rec.data(), hello_rec.size(), error)) return false;

        // 读 ClientKeyExchange（明文 HANDSHAKE record）
        std::vector<uint8_t> cke;
        while (true) {
            uint8_t rtype = 0;
            std::vector<uint8_t> payload;
            if (!read_record(rtype, payload, error)) return false;
            if (rtype == (uint8_t)ContentType::ALERT) {
                set_err(error, "TLS alert during handshake");
                return false;
            }
            if (rtype != (uint8_t)ContentType::HANDSHAKE) continue;
            cke.insert(cke.end(), payload.begin(), payload.end());
            if (cke.size() >= 4 && cke[0] == (uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE) {
                size_t cke_len = ((size_t)cke[1] << 16) | ((size_t)cke[2] << 8) | cke[3];
                if (cke.size() >= 4 + cke_len) break;
            }
        }
        // ClientKeyExchange 消息体（跳过 4 字节头）
        size_t cke_body_len = ((size_t)cke[1] << 16) | ((size_t)cke[2] << 8) | cke[3];
        // transcript 使用完整握手消息（含 4 字节头）
        tls_transcript_update(session_, cke.data(), 4 + cke_body_len);
        std::vector<uint8_t> dummy;
        if (!tls12_process_client_key_exchange(session_, cke.data() + 4, cke_body_len,
                                               dummy, psk_store)) {
            set_err(error, "tls12_process_client_key_exchange failed");
            return false;
        }

        // 读 ChangeCipherSpec（明文，1 字节 0x01）
        while (true) {
            uint8_t rtype = 0;
            std::vector<uint8_t> payload;
            if (!read_record(rtype, payload, error)) return false;
            if (rtype == (uint8_t)ContentType::ALERT) {
                set_err(error, "TLS alert during handshake");
                return false;
            }
            if (rtype != (uint8_t)ContentType::CHANGE_CIPHER_SPEC) continue;
            break;
        }

        // 读加密的 Client Finished（TLS 1.2 加密记录 type=22）
        std::vector<uint8_t> client_finished_plain;
        while (true) {
            uint8_t rtype = 0;
            std::vector<uint8_t> payload;
            if (!read_record(rtype, payload, error)) {
                return false;
            }
            if (rtype == (uint8_t)ContentType::ALERT) {
                set_err(error, "TLS alert during handshake");
                return false;
            }
            if (rtype != (uint8_t)ContentType::HANDSHAKE) continue;
            auto rec = make_record(rtype, payload.data(), payload.size());
            ContentType ct = ContentType::HANDSHAKE;
            if (!tls_decrypt(session_, rec.data(), rec.size(), ct, client_finished_plain)) {
                set_err(error, "tls_decrypt client finished failed");
                return false;
            }
            if (client_finished_plain.size() >= 4 &&
                client_finished_plain[0] == (uint8_t)HandshakeType::FINISHED) break;
        }
        if (!tls12_verify_finished(session_, client_finished_plain.data(),
                                   client_finished_plain.size(), /*for_server=*/false)) {
            set_err(error, "tls12 client finished verify failed");
            return false;
        }

        // RFC 5246 7.4.9：服务端 Finished 的 hash 必须包含客户端 Finished
        tls_transcript_update(session_, client_finished_plain.data(), client_finished_plain.size());

        // 发送 ChangeCipherSpec（明文）+ 加密的 Server Finished
        auto ccs = tls_make_change_cipher_spec();
        if (!write_all(ccs.data(), ccs.size(), error)) return false;

        std::vector<uint8_t> sf = tls12_make_finished(session_, /*for_server=*/true);
        std::vector<uint8_t> sf_enc = tls_encrypt(session_, ContentType::HANDSHAKE,
                                                  sf.data(), sf.size());
        if (sf_enc.empty()) {
            set_err(error, "tls12 server finished encrypt failed");
            return false;
        }
        if (!write_all(sf_enc.data(), sf_enc.size(), error)) return false;

        session_.tls12_secure = true;
        return true;
    }

    // 2. TLS 1.3：生成服务端 flight（裸 ServerHello + 加密 record）
    std::vector<uint8_t> server_flight;
    if (!tls13_make_server_flight(session_, ch.data(), ch_total,
                                  server_flight, cert_manager)) {
        set_err(error, "tls13_make_server_flight failed");
        return false;
    }

    // 3. 拆分并发送：裸 ServerHello 封装为明文 record；加密 record 原样透传
    if (server_flight.size() < 4 ||
        server_flight[0] != (uint8_t)HandshakeType::SERVER_HELLO) {
        set_err(error, "malformed server flight");
        return false;
    }
    size_t sh_len = ((size_t)server_flight[1] << 16) |
                    ((size_t)server_flight[2] << 8) | server_flight[3];
    if (server_flight.size() < 4 + sh_len + 5) {
        set_err(error, "malformed server flight (missing encrypted record)");
        return false;
    }
    auto sh_record = make_record((uint8_t)ContentType::HANDSHAKE,
                                 server_flight.data(), 4 + sh_len);
    if (!write_all(sh_record.data(), sh_record.size(), error)) return false;
    if (!write_all(server_flight.data() + 4 + sh_len,
                   server_flight.size() - 4 - sh_len, error))
        return false;

    // 4. 读取加密的 Client Finished record 并校验
    while (true) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) return false;
        if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert during handshake");
            return false;
        }
        if (rtype != (uint8_t)ContentType::APPLICATION_DATA) continue;
        auto rec = make_record(rtype, payload.data(), payload.size());
        if (!tls13_process_client_finished(session_, rec.data(), rec.size())) {
            set_err(error, "tls13_process_client_finished failed");
            return false;
        }
        return true;
    }
}

bool tls_connection::send(const uint8_t* data, size_t len, std::string* error) {
    if (!open_) {
        set_err(error, "connection not open");
        return false;
    }
    would_block_ = false; // 新一次 I/O 清空上次 would-block 状态
    // tls_encrypt 内部按 <=16KiB 自动分片为多条 record，这里一次性写出
    auto rec = tls_encrypt(session_, ContentType::APPLICATION_DATA, data, len);
    if (rec.empty()) {
        set_err(error, "tls_encrypt failed");
        return false;
    }
    return write_all(rec.data(), rec.size(), error);
}

bool tls_connection::send(const std::string& data, std::string* error) {
    return send((const uint8_t*)data.data(), data.size(), error);
}

bool tls_connection::recv(std::vector<uint8_t>& out, std::string* error) {
    if (!open_) {
        set_err(error, "connection not open");
        return false;
    }
    would_block_ = false; // 新一次 I/O 清空上次 would-block 状态
    out.clear();
    bool got_app = false;
    while (true) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) return false;
        if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert received");
            close();
            return false;
        }
        if (rtype != (uint8_t)ContentType::APPLICATION_DATA) continue; // CCS / 明文握手
        auto rec = make_record(rtype, payload.data(), payload.size());
        ContentType ct = ContentType::APPLICATION_DATA;
        std::vector<uint8_t> plain;
        if (!tls_decrypt(session_, rec.data(), rec.size(), ct, plain)) {
            set_err(error, "tls_decrypt failed");
            return false;
        }
        if (ct == ContentType::HANDSHAKE) continue; // 握手后消息（如 NewSessionTicket）
        if (ct == ContentType::ALERT) {
            // close_notify 等告警：对端优雅关闭，返回已收到的数据
            close();
            break;
        }
        if (ct != ContentType::APPLICATION_DATA) {
            set_err(error, "unexpected content type in application record");
            return false;
        }
        out.insert(out.end(), plain.begin(), plain.end());
        got_app = true;
        // 大消息合并：若仍有已到达的 record 数据（同一次 send 拆分出的后续 record），
        // 继续读取并追加，使一次 send() 的大消息能在一次 recv() 中合并还原。
        if (!more_data_pending()) break;
    }
    return got_app;
}

// ============================================================================
// 协程 I/O（C++20 coroutine）
// ============================================================================

// 协程版：从 socket 读入数据追加到 rbuf_，直到 rbuf_.size() >= min_total。
// would-block 时挂起等待可读（由执行器恢复），不阻塞线程。
tls_co_task<bool> tls_connection::co_fill_rbuf(size_t min_total,
                                               std::string* error) {
    if (!open_ || sock_ == INVALID_SOCKET_HANDLE) {
        set_err(error, "connection not open");
        co_return false;
    }
    while (rbuf_.size() < min_total) {
        // 数据报模式：一次 recv 拿一个完整 UDP 数据报；TCP 模式：增量读取
        size_t want = datagram_ ? (size_t)65536
                                : std::min<size_t>(4096, min_total - rbuf_.size());
        size_t old = rbuf_.size();
        rbuf_.resize(old + want);
        int r = (int)::recv(sock_, (char*)rbuf_.data() + old, (int)want, 0);
        if (r > 0) {
            rbuf_.resize(old + (size_t)r);
            continue;
        }
        rbuf_.resize(old); // 恢复，丢弃本次空读
        if (r == 0) {
            set_err(error, "connection closed by peer");
            close();
            co_return false;
        }
        if (!is_would_block()) {
            set_err(error, "recv failed: " + last_socket_error());
            close();
            co_return false;
        }
        // 资源暂不可用：挂起，等 socket 可读后由执行器恢复
        co_await socket_wait_awaiter(*this, false);
    }
    co_return true;
}

// 协程版：读取一条完整 TLS record（从 rbuf_ 消费，续读无缝）
tls_co_task<bool> tls_connection::co_read_record(uint8_t& type,
                                                 std::vector<uint8_t>& payload,
                                                 std::string* error) {
    if (!co_await co_fill_rbuf(5, error)) co_return false;
    type = rbuf_[0];
    size_t len = ((size_t)rbuf_[3] << 8) | rbuf_[4];
    // TLS 明文上限 2^14，加上 AEAD tag 等开销
    if (len > 16384 + 256) {
        set_err(error, "TLS record too large");
        close();
        co_return false;
    }
    if (!co_await co_fill_rbuf(5 + len, error)) co_return false;
    payload.assign(rbuf_.begin() + 5, rbuf_.begin() + 5 + len);
    rbuf_.erase(rbuf_.begin(), rbuf_.begin() + 5 + len);
    co_return true;
}

tls_co_task<bool> tls_connection::co_send(const uint8_t* data, size_t len,
                                          std::string* error) {
    if (!open_) {
        set_err(error, "connection not open");
        co_return false;
    }
    if (!executor_) {
        set_err(error, "no co-executor attached (attach_co_executor)");
        co_return false;
    }
    if (!nonblocking_) {
        set_err(error, "coroutine I/O requires non-blocking mode");
        co_return false;
    }
    // 与同步 send() 一致：先 tls_encrypt（内部按 <=16KiB 自动分片为多条
    // record），再逐条写出到 socket。
    auto rec = tls_encrypt(session_, ContentType::APPLICATION_DATA, data, len);
    if (rec.empty()) {
        set_err(error, "tls_encrypt failed");
        co_return false;
    }
    if (datagram_) {
        // 数据报模式：每条 TLS record 一个 UDP 数据报，整包发送（UDP 原子）。
        size_t off = 0;
        while (off < rec.size()) {
            if (rec.size() - off < 5) {
                set_err(error, "datagram: truncated TLS record header");
                close();
                co_return false;
            }
            size_t rlen = ((size_t)rec[off + 3] << 8) | rec[off + 4];
            if (off + 5 + rlen > rec.size()) {
                set_err(error, "datagram: truncated TLS record");
                close();
                co_return false;
            }
            for (;;) {
                int w = (int)::send(sock_, (const char*)rec.data() + off,
                                    (int)(5 + rlen), 0);
                if (w > 0) break; // 整包发出
                if (w == 0) {
                    set_err(error, "send failed: connection closed");
                    close();
                    co_return false;
                }
                if (!is_would_block()) {
                    set_err(error, "send failed: " + last_socket_error());
                    close();
                    co_return false;
                }
                // 写缓冲暂满：挂起，等 socket 可写后由执行器恢复重发整包
                co_await socket_wait_awaiter(*this, true);
            }
            off += 5 + rlen;
        }
        co_return true;
    }
    size_t off = 0;
    while (off < rec.size()) {
        int w = (int)::send(sock_, (const char*)rec.data() + off,
                            (int)(rec.size() - off), 0);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w == 0) {
            set_err(error, "send failed: connection closed");
            close();
            co_return false;
        }
        if (!is_would_block()) {
            set_err(error, "send failed: " + last_socket_error());
            close();
            co_return false;
        }
        // 写缓冲暂满：挂起，等 socket 可写后由执行器恢复继续发送
        co_await socket_wait_awaiter(*this, true);
    }
    co_return true;
}

tls_co_task<bool> tls_connection::co_send(const std::string& data,
                                          std::string* error) {
    co_return co_await co_send((const uint8_t*)data.data(), data.size(), error);
}

tls_co_task<bool> tls_connection::co_recv(std::vector<uint8_t>& out,
                                          std::string* error) {
    if (!open_) {
        set_err(error, "connection not open");
        co_return false;
    }
    if (!executor_) {
        set_err(error, "no co-executor attached (attach_co_executor)");
        co_return false;
    }
    if (!nonblocking_) {
        set_err(error, "coroutine I/O requires non-blocking mode");
        co_return false;
    }
    out.clear();
    bool got_app = false;
    while (true) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!co_await co_read_record(rtype, payload, error)) co_return false;
        if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert received");
            close();
            co_return false;
        }
        if (rtype != (uint8_t)ContentType::APPLICATION_DATA) continue; // CCS / 明文握手
        auto rec = make_record(rtype, payload.data(), payload.size());
        ContentType ct = ContentType::APPLICATION_DATA;
        std::vector<uint8_t> plain;
        if (!tls_decrypt(session_, rec.data(), rec.size(), ct, plain)) {
            set_err(error, "tls_decrypt failed");
            co_return false;
        }
        if (ct == ContentType::HANDSHAKE) continue; // 握手后消息（如 NewSessionTicket）
        if (ct != ContentType::APPLICATION_DATA) {
            set_err(error, "unexpected content type in application record");
            co_return false;
        }
        out.insert(out.end(), plain.begin(), plain.end());
        got_app = true;
        // 大消息合并：若仍有已到达数据，继续读取并追加
        if (!more_data_pending()) break;
    }
    co_return got_app;
}

bool tls_connection::set_nonblocking(bool enable, std::string* error) {
    nonblocking_ = enable;
    // connect 之前调用时 socket 尚不存在，仅记录标志，connect 内部会应用
    if (sock_ != INVALID_SOCKET_HANDLE &&
        !set_socket_nonblocking(sock_, enable)) {
        set_err(error, "set_nonblocking failed: " + last_socket_error());
        return false;
    }
    return true;
}

bool tls_connection::wait_readable(int timeout_ms) const {
    return open_ && sock_ != INVALID_SOCKET_HANDLE ? wait_fd(sock_, false, timeout_ms)
                                                   : false;
}

bool tls_connection::wait_writable(int timeout_ms) const {
    return open_ && sock_ != INVALID_SOCKET_HANDLE ? wait_fd(sock_, true, timeout_ms)
                                                   : false;
}

// ============================================================================
// tls_listener
// ============================================================================

tls_listener::tls_listener() = default;

tls_listener::~tls_listener() {
    close();
}

bool tls_listener::listen(uint16_t port, const std::string& bind_addr, std::string* error) {
    close();
    if (!tls_socket_init(error)) return false;

    addrinfo hints = {};
    hints.ai_family = AF_INET; // 本封装层暂只监听 IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    const char* node = bind_addr.empty() ? nullptr : bind_addr.c_str();
    int rc = getaddrinfo(node, port_str.c_str(), &hints, &res);
    if (rc != 0) {
        set_err(error, std::string("getaddrinfo: ") + gai_strerror(rc));
        return false;
    }

    socket_handle_t fd = INVALID_SOCKET_HANDLE;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == INVALID_SOCKET_HANDLE) continue;
        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        if (::bind(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0 && ::listen(fd, 16) == 0)
            break;
        close_socket_handle(fd);
        fd = INVALID_SOCKET_HANDLE;
    }
    freeaddrinfo(res);
    if (fd == INVALID_SOCKET_HANDLE) {
        set_err(error, "bind/listen failed: " + last_socket_error());
        return false;
    }

    sock_ = fd;
    open_ = true;
    owns_socket_ = true;
    udp_ = false;
    // listen 之前若已设置非阻塞标志，则应用到监听 socket
    if (nonblocking_ && !set_socket_nonblocking(fd, true)) {
        set_err(error, "set_nonblocking failed: " + last_socket_error());
        close_socket_handle(fd);
        sock_ = INVALID_SOCKET_HANDLE;
        open_ = false;
        return false;
    }
    return true;
}

// 托管外部监听 socket 句柄（TCP 已 listen / UDP 已 bind）
bool tls_listener::attach(socket_handle_t fd, bool take_ownership,
                          std::string* error) {
    if (fd == INVALID_SOCKET_HANDLE) {
        set_err(error, "attach: invalid socket handle");
        return false;
    }
    close();
    sock_ = fd;
    open_ = true;
    owns_socket_ = take_ownership;
    // 自动检测 UDP 监听器（配合 accept_udp 使用）
    int type = 0;
#ifdef _WIN32
    int tlen = sizeof(type);
#else
    socklen_t tlen = sizeof(type);
#endif
    udp_ = (getsockopt(fd, SOL_SOCKET, SO_TYPE, (char*)&type, &tlen) == 0 &&
           type == SOCK_DGRAM);
    if (nonblocking_ && !set_socket_nonblocking(fd, true)) {
        set_err(error, "set_nonblocking failed: " + last_socket_error());
        return false;
    }
    return true;
}

// UDP 链接：绑定 UDP 端口等待客户端握手（数据报模式）
bool tls_listener::listen_udp(uint16_t port, const std::string& bind_addr,
                              std::string* error) {
    close();
    if (!tls_socket_init(error)) return false;

    addrinfo hints = {};
    hints.ai_family = AF_INET; // 本封装层暂只监听 IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    const char* node = bind_addr.empty() ? nullptr : bind_addr.c_str();
    int rc = getaddrinfo(node, port_str.c_str(), &hints, &res);
    if (rc != 0) {
        set_err(error, std::string("getaddrinfo: ") + gai_strerror(rc));
        return false;
    }

    socket_handle_t fd = INVALID_SOCKET_HANDLE;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == INVALID_SOCKET_HANDLE) continue;
        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        if (::bind(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        close_socket_handle(fd);
        fd = INVALID_SOCKET_HANDLE;
    }
    freeaddrinfo(res);
    if (fd == INVALID_SOCKET_HANDLE) {
        set_err(error, "udp bind failed: " + last_socket_error());
        return false;
    }

    sock_ = fd;
    open_ = true;
    owns_socket_ = true;
    udp_ = true;
    // bind 之前若已设置非阻塞标志，则应用到 UDP socket
    if (nonblocking_ && !set_socket_nonblocking(fd, true)) {
        set_err(error, "set_nonblocking failed: " + last_socket_error());
        close_socket_handle(fd);
        sock_ = INVALID_SOCKET_HANDLE;
        open_ = false;
        return false;
    }
    return true;
}

// UDP 链接：接收一个客户端数据报 -> 固定对端 -> 完成服务端握手。
// 注意：必须复用监听 socket 本身（connect 固定对端）才能保持源端口不变，
// 客户端（connected UDP）才能收到服务端回复；监听 socket 由此转交给 conn，
// listener 变为未打开，一个 UDP listener 同一时刻服务一个客户端。
bool tls_listener::accept_udp(tls_connection& conn,
                              const tls_certificate_manager& cert_manager,
                              std::string* error) {
    if (!open_ || !udp_) {
        set_err(error, "accept_udp: UDP listener not open (call listen_udp)");
        return false;
    }
    // 1. 接收首个 ClientHello 数据报并取对端地址
    std::vector<uint8_t> buf(65536);
    sockaddr_storage peer = {};
    socklen_t plen = sizeof(peer);
    int r = (int)::recvfrom(sock_, (char*)buf.data(), (int)buf.size(), 0,
                            (sockaddr*)&peer, &plen);
    if (r < 0) {
        would_block_ = is_would_block();
        if (would_block_) set_err(error, "would block");
        else set_err(error, "recvfrom failed: " + last_socket_error());
        return false;
    }
    would_block_ = false;

    // 2. 用监听 socket 本身 connect 固定该对端（保持源端口不变）
    if (::connect(sock_, (sockaddr*)&peer, plen) != 0) {
        set_err(error, "accept_udp: connect failed: " + last_socket_error());
        return false;
    }

    // 3. 装配连接：监听 socket 转交给 conn（listener 释放引用）
    conn.close();
    conn.sock_ = sock_;
    conn.open_ = true;
    conn.owns_socket_ = true;
    conn.datagram_ = true;
    conn.nonblocking_ = nonblocking_; // 继承监听器非阻塞状态
    if (nonblocking_ && !set_socket_nonblocking(conn.sock_, true)) {
        set_err(error, "set_nonblocking on accepted socket failed: " +
                           last_socket_error());
        return false;
    }
    conn.rbuf_.assign(buf.begin(), buf.begin() + r);
    reset_session_preserving_config(conn.session_);
    sock_ = INVALID_SOCKET_HANDLE;
    open_ = false;
    return conn.do_server_handshake(cert_manager, nullptr, error);
}

uint16_t tls_listener::local_port() const {
    if (!open_) return 0;
    sockaddr_in addr = {};
    socklen_t alen = sizeof(addr);
    if (getsockname(sock_, (sockaddr*)&addr, &alen) != 0) return 0;
    return ntohs(addr.sin_port);
}

bool tls_listener::accept(tls_connection& conn, const tls_certificate_manager& cert_manager,
                          std::string* error) {
    if (!open_) {
        set_err(error, "listener not open");
        return false;
    }
    sockaddr_storage addr = {};
    socklen_t alen = sizeof(addr);
    socket_handle_t fd = ::accept(sock_, (sockaddr*)&addr, &alen);
    if (fd == INVALID_SOCKET_HANDLE) {
        would_block_ = is_would_block();
        if (would_block_) set_err(error, "would block");
        else set_err(error, "accept failed: " + last_socket_error());
        return false;
    }
    would_block_ = false;

    conn.close();
    conn.sock_ = fd;
    conn.open_ = true;
    conn.owns_socket_ = true; // accept 出的连接 fd 由 conn 持有
    conn.datagram_ = false;   // TCP 流式模式
    conn.set_tcp_nodelay();
    reset_session_preserving_config(conn.session_);
    // accept 出的连接 socket 继承监听器的非阻塞状态
    conn.nonblocking_ = nonblocking_;
    if (nonblocking_ && !set_socket_nonblocking(fd, true)) {
        set_err(error, "set_nonblocking on accepted socket failed: " +
                           last_socket_error());
        return false;
    }
    return conn.do_server_handshake(cert_manager, nullptr, error);
}

bool tls_listener::accept(tls_connection& conn, const tls_certificate_manager& cert_manager,
                          const tls_psk_store& psk_store,
                          std::string* error) {
    if (!open_) {
        set_err(error, "listener not open");
        return false;
    }
    sockaddr_storage addr = {};
    socklen_t alen = sizeof(addr);
    socket_handle_t fd = ::accept(sock_, (sockaddr*)&addr, &alen);
    if (fd == INVALID_SOCKET_HANDLE) {
        would_block_ = is_would_block();
        if (would_block_) set_err(error, "would block");
        else set_err(error, "accept failed: " + last_socket_error());
        return false;
    }
    would_block_ = false;

    conn.close();
    conn.sock_ = fd;
    conn.open_ = true;
    conn.owns_socket_ = true;
    conn.datagram_ = false;
    conn.set_tcp_nodelay();
    reset_session_preserving_config(conn.session_);
    conn.nonblocking_ = nonblocking_;
    if (nonblocking_ && !set_socket_nonblocking(fd, true)) {
        set_err(error, "set_nonblocking on accepted socket failed: " +
                           last_socket_error());
        return false;
    }
    return conn.do_server_handshake(cert_manager, &psk_store, error);
}

bool tls_listener::set_nonblocking(bool enable, std::string* error) {
    nonblocking_ = enable;
    // listen 之前调用时 socket 尚不存在，仅记录标志，listen 内部会应用
    if (sock_ != INVALID_SOCKET_HANDLE && !set_socket_nonblocking(sock_, enable)) {
        set_err(error, "set_nonblocking failed: " + last_socket_error());
        return false;
    }
    return true;
}

bool tls_listener::wait_readable(int timeout_ms) const {
    return open_ && sock_ != INVALID_SOCKET_HANDLE ? wait_fd(sock_, false, timeout_ms)
                                                   : false;
}

void tls_listener::close() {
    if (open_ && sock_ != INVALID_SOCKET_HANDLE && owns_socket_)
        close_socket_handle(sock_);
    sock_ = INVALID_SOCKET_HANDLE;
    open_ = false;
    owns_socket_ = true; // 复位默认
    udp_ = false;
}

} // namespace jpssl::tls
