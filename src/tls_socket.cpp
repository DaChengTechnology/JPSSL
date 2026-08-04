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

#include <cstring>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#endif

namespace jpssl::tls {

namespace {

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
// tls_connection
// ============================================================================

tls_connection::tls_connection() = default;

tls_connection::~tls_connection() {
    close();
}

void tls_connection::close() {
    if (open_ && sock_ != INVALID_SOCKET_HANDLE) {
#ifdef _WIN32
        shutdown(sock_, SD_BOTH);
#else
        shutdown(sock_, SHUT_RDWR);
#endif
        close_socket_handle(sock_);
    }
    sock_ = INVALID_SOCKET_HANDLE;
    open_ = false;
    rbuf_.clear();
    rbuf_off_ = 0;
}

void tls_connection::set_tcp_nodelay() {
    int one = 1;
    setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
}

bool tls_connection::write_all(const uint8_t* data, size_t len, std::string* error) {
    if (!open_ || sock_ == INVALID_SOCKET_HANDLE) {
        set_err(error, "connection not open");
        return false;
    }
    size_t off = 0;
    while (off < len) {
        int w = (int)::send(sock_, (const char*)data + off, (int)(len - off), 0);
        if (w <= 0) {
            set_err(error, "send failed: " + last_socket_error());
            close();
            return false;
        }
        off += (size_t)w;
    }
    return true;
}

bool tls_connection::read_bytes(uint8_t* out, size_t n, std::string* error) {
    if (!open_ || sock_ == INVALID_SOCKET_HANDLE) {
        set_err(error, "connection not open");
        return false;
    }
    // 先消费内部缓冲
    size_t avail = rbuf_.size() - rbuf_off_;
    if (avail >= n) {
        std::memcpy(out, rbuf_.data() + rbuf_off_, n);
        rbuf_off_ += n;
        if (rbuf_off_ == rbuf_.size()) {
            rbuf_.clear();
            rbuf_off_ = 0;
        }
        return true;
    }
    if (avail > 0) {
        std::memcpy(out, rbuf_.data() + rbuf_off_, avail);
        rbuf_.clear();
        rbuf_off_ = 0;
    }
    // 从 socket 补齐
    size_t need = n - avail;
    uint8_t* p = out + avail;
    while (need > 0) {
        int r = (int)::recv(sock_, (char*)p, (int)need, 0);
        if (r <= 0) {
            if (r == 0) {
                set_err(error, "connection closed by peer");
                close();
            } else {
                set_err(error, "recv failed: " + last_socket_error());
                close();
            }
            return false;
        }
        p += r;
        need -= (size_t)r;
    }
    return true;
}

bool tls_connection::read_record(uint8_t& type, std::vector<uint8_t>& payload, std::string* error) {
    uint8_t hdr[5];
    if (!read_bytes(hdr, sizeof(hdr), error)) return false;
    type = hdr[0];
    size_t len = ((size_t)hdr[3] << 8) | hdr[4];
    // TLS 明文上限 2^14，加上 AEAD tag 等开销
    if (len > 16384 + 256) {
        set_err(error, "TLS record too large");
        return false;
    }
    payload.resize(len);
    if (len > 0 && !read_bytes(payload.data(), len, error)) return false;
    return true;
}

bool tls_connection::connect(const std::string& host, uint16_t port,
                             const tls_certificate_manager* trust_store,
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
        if (::connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
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
    session_ = tls_session{};
    session_.server_name = host;
    return do_client_handshake(trust_store, error);
}

bool tls_connection::do_client_handshake(const tls_certificate_manager* trust_store,
                                         std::string* error) {
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
    std::vector<uint8_t> flight;
    bool got_encrypted = false;
    while (!got_encrypted) {
        uint8_t rtype = 0;
        std::vector<uint8_t> payload;
        if (!read_record(rtype, payload, error)) return false;
        if (rtype == (uint8_t)ContentType::HANDSHAKE) {
            flight.insert(flight.end(), payload.begin(), payload.end());
        } else if (rtype == (uint8_t)ContentType::APPLICATION_DATA) {
            auto rec = make_record(rtype, payload.data(), payload.size());
            flight.insert(flight.end(), rec.begin(), rec.end());
            got_encrypted = true;
        } else if (rtype == (uint8_t)ContentType::ALERT) {
            set_err(error, "TLS alert during handshake");
            return false;
        }
        // CCS（type 20）等兼容性记录直接忽略
    }

    // 3. 处理服务端 flight，得到加密的 Client Finished record 并发送
    std::vector<uint8_t> client_finished;
    if (!tls13_process_server_flight(session_, flight.data(), flight.size(),
                                     client_finished, trust_store)) {
        set_err(error, "tls13_process_server_flight failed");
        return false;
    }
    if (!write_all(client_finished.data(), client_finished.size(), error)) return false;
    return true;
}

bool tls_connection::server_handshake(const tls_certificate_manager& cert_manager,
                                      std::string* error) {
    session_ = tls_session{};
    return do_server_handshake(cert_manager, error);
}

bool tls_connection::do_server_handshake(const tls_certificate_manager& cert_manager,
                                         std::string* error) {
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

    // 2. 生成服务端 flight：裸 ServerHello + 加密 record
    size_t ch_msg_len = ((size_t)ch[1] << 16) | ((size_t)ch[2] << 8) | ch[3];
    std::vector<uint8_t> server_flight;
    if (!tls13_make_server_flight(session_, ch.data(), 4 + ch_msg_len,
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
        if (ct != ContentType::APPLICATION_DATA) {
            set_err(error, "unexpected content type in application record");
            return false;
        }
        out = std::move(plain);
        return true;
    }
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
    return true;
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
        set_err(error, "accept failed: " + last_socket_error());
        return false;
    }

    conn.close();
    conn.sock_ = fd;
    conn.open_ = true;
    conn.set_tcp_nodelay();
    conn.session_ = tls_session{};
    return conn.do_server_handshake(cert_manager, error);
}

void tls_listener::close() {
    if (open_ && sock_ != INVALID_SOCKET_HANDLE) close_socket_handle(sock_);
    sock_ = INVALID_SOCKET_HANDLE;
    open_ = false;
}

} // namespace jpssl::tls
