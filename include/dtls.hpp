#pragma once
/** dtls.hpp — DTLS 1.2 (RFC 6347) / DTLS 1.3 (RFC 9147)
 *
 * 基于本库消息级 TLS API（tls.hpp）与底层密码原语实现标准 DTLS：
 *   - DTLS 记录层：DTLS 1.2（type||version||epoch||seq||len，13 字节头）与
 *     DTLS 1.3（unified header + 记录号加密，RFC 9147 §4）两种格式，
 *     epoch/序列号滑动窗口、AEAD（AES-GCM / ChaCha20-Poly1305）。
 *   - DTLS 1.2 握手：cookie（HelloVerifyRequest）、message_seq 与
 *     分片/重组、ChangeCipherSpec、ECDHE（X25519/P-256）密钥交换、
 *     TLS 1.2 PRF 密钥派生、Finished。
 *   - DTLS 1.3 握手：复用 TLS 1.3 消息与密钥派生（"dtls13" 标签前缀，
 *     RFC 9147 §5.9），DTLSHandshake 分帧（message_seq + fragment）、
 *     ACK 记录（content type 26）、记录号加密。
 *   - 数据报步进式握手状态机（dtls_handshake_step）：datagram in →
 *     datagram out，便于无 socket 的单元测试与上层传输封装。
 *   - dtls_connection：UDP socket 封装（握手重传 + 应用数据收发）。
 */
#include "tls.hpp"
#include "x509.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace jpssl::dtls {

/// DTLS 协议版本（线格式 16 位版本号）。
enum class DTLSVersion : uint16_t {
    V12 = 0xfefd,  ///< DTLS 1.2（RFC 6347）
    V13 = 0xfefc   ///< DTLS 1.3（RFC 9147）
};

/// DTLS 记录内容类型（RFC 9147 §A.1；DTLS 1.2 与 TLS 1.2 相同）。
enum class DTLSType : uint8_t {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    ACK = 26
};

/// DTLS 握手消息类型（RFC 6347 §4.2 / RFC 9147 §5.2）。
enum class DTLShandshakeType : uint8_t {
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    HELLO_VERIFY_REQUEST = 3,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    HELLO_RETRY_REQUEST = 6,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    KEY_UPDATE = 24
};

/// 客户端握手阶段（互斥状态，替代 ch_sent / hvr_received / client_flight_sent
/// 布尔组；uint8_t 枚举与 bool 同宽，但一个字段表达多状态）。
enum class DtlsClientPhase : uint8_t {
    Idle = 0,       ///< 尚未发出 ClientHello
    ChSent,         ///< 已发出首个 ClientHello
    HvrReceived,    ///< 已收到 HelloVerifyRequest（DTLS 1.2）
    FlightSent,     ///< 已发出客户端 flight（CKE/Finished）
    Done            ///< 客户端握手完成
};

/// 服务端握手阶段（替代 client_hello_ok 布尔）。
enum class DtlsServerPhase : uint8_t {
    Idle = 0,       ///< 等待首个 ClientHello
    HvrSent,        ///< 已发出 HelloVerifyRequest（DTLS 1.2 cookie）
    HelloOk,        ///< 已收到带有效 cookie 的 ClientHello
    Done            ///< 服务端握手完成（已收到客户端 Finished）
};

/// DTLS 会话状态。
struct dtls_session {
    DTLSVersion ver = DTLSVersion::V12;
    bool is_server = false;
    std::string server_name;   ///< SNI（客户端）
    tls::CipherSuite cipher_suite = tls::CipherSuite::TLS_AES_128_GCM_SHA256;
    tls::NamedGroup ks_group = tls::NamedGroup::X25519;
    std::vector<uint16_t> sig_algs;   ///< 空 = 默认（tls_default_signature_algorithms）

    // 随机数
    uint8_t client_random[32] = {};
    uint8_t server_random[32] = {};

    // ── 密钥材料 ────────────────────────────────────────────────
    uint8_t client_write_key[32] = {};  ///< DTLS 1.2 记录密钥
    uint8_t server_write_key[32] = {};
    uint8_t client_write_iv[16] = {};   ///< DTLS 1.2 固定 IV（GCM 4 / ChaCha20 12）
    uint8_t server_write_iv[16] = {};
    size_t key_len = 0;
    size_t iv_len = 0;
    uint8_t master_secret[48] = {};     ///< DTLS 1.2 master secret

    // DTLS 1.3 traffic secrets（"dtls13" 标签前缀派生）
    uint8_t handshake_secret[48] = {};
    uint8_t client_hs_traffic[48] = {};
    uint8_t server_hs_traffic[48] = {};
    uint8_t client_app_traffic[48] = {};
    uint8_t server_app_traffic[48] = {};
    uint8_t client_early_traffic[48] = {};

    // ECDHE 临时密钥对（X25519=32 / P-256=32 / X448=56）
    uint8_t ks_priv[56] = {};
    uint8_t ks_pub[96] = {};
    uint8_t ks_pub_len = 0;

    // ── 记录层状态 ──────────────────────────────────────────────
    uint16_t send_epoch = 0;
    uint16_t recv_epoch = 0;
    uint64_t send_seq = 0;   ///< 每个 epoch 内从 0 递增
    uint64_t recv_seq = 0;

    // ── 握手状态 ────────────────────────────────────────────────
    uint16_t send_msg_seq = 0;   ///< 本端 message_seq（每侧从 0 起）
    uint16_t recv_msg_seq = 0;   ///< 期望接收的对端 message_seq
    DtlsClientPhase client_phase = DtlsClientPhase::Idle;  ///< 客户端握手阶段
    DtlsServerPhase server_phase = DtlsServerPhase::Idle;  ///< 服务端握手阶段

    // cookie（DTLS 1.2 cookie 字段 / DTLS 1.3 cookie 扩展）
    std::vector<uint8_t> cookie;
    /// 服务端：cookie 签名密钥（首次生成 CH 响应时初始化）
    std::vector<uint8_t> cookie_secret;

    // 分片重组
    std::vector<uint8_t> reassembly_buf;
    std::vector<uint8_t> reassembly_received;   ///< 每字节是否已收到（防止数据中间含 0 字节时误判）
    size_t reassembly_remaining = 0;            ///< 尚未收到的字节数
    uint16_t reassembly_msg_seq = 0;
    uint32_t reassembly_total_len = 0;

    // 握手中继：记录号加密 / ACK
    uint8_t client_sn_key[32] = {};
    uint8_t server_sn_key[32] = {};
    std::vector<std::pair<uint64_t, uint64_t>> received_records;  ///< (epoch,seq) 已接收

    /// 最近一次发出的 flight（供重传）
    std::vector<uint8_t> last_sent;

    // transcript（DTLS 1.2：DTLS-framed 消息；DTLS 1.3：TLS-1.3 风格内层消息）。
    // cookie 交换时 DTLS 1.2 在第二个 ClientHello 处重置（排除首个 CH 与 HVR）。
    std::vector<uint8_t> transcript_buf;
    uint8_t transcript_hash[48] = {};
    // 服务端选择的本证书签名方案
    uint16_t selected_sig_alg = 0;

    // ── 独立状态标志（打包为位域：8 个标志仅占 1 字节）──────────────
    bool handshake_done : 1 = false;            ///< 本端握手完成
    bool server_finished_received : 1 = false;  ///< 客户端收到服务端 Finished
    bool require_cookie : 1 = false;            ///< 服务端是否要求 cookie 交换
    bool retransmit_requested : 1 = false;      ///< 识别到对端重传，重发 last_sent
    bool transcript_valid : 1 = false;
    bool have_server_cert : 1 = false;

    // Client-side: parsed server certificate chain, kept across step calls
    // (RFC 6347 allows each handshake message in its own datagram)。
    // 证书按需堆分配：tls_certificate 含全部密钥类型缓冲（约 2.7KB），
    // 未解析证书的会话零占用；shared_ptr 保持 dtls_session 可拷贝。
    std::vector<x509::x509_cert> server_chain;
    std::shared_ptr<tls::tls_certificate> server_cert_parsed;
};

/// 握手步进输入。
struct dtls_handshake_input {
    const uint8_t* datagram = nullptr;   ///< 收到的数据报；客户端首步为 nullptr
    size_t datagram_len = 0;
    /// 服务端：证书管理器（在首次收到 ClientHello 时提供）。
    const tls::tls_certificate_manager* cert_manager = nullptr;
    /// 客户端：信任库（提供时对服务端证书链执行 x509 验证）。
    const tls::tls_trust_store* trust_store = nullptr;
};

/// 握手结果。
struct dtls_step_result {
    bool ok = false;              ///< false = 协议错误
    bool done = false;            ///< 握手完成（可开始收发应用数据）
    std::vector<uint8_t> out;     ///< 要发送的数据报（可能为空）
    std::string error;
};

/// 步进式握手状态机：处理一个输入数据报，产出要发送的输出数据报。
/// 客户端首次调用传 datagram=nullptr（生成第一个 ClientHello）。
/// 服务端逐次把收到的数据报喂入；内部处理记录层解密、握手消息
/// 分片重组、cookie、密钥派生与 Finished 校验。
dtls_step_result dtls_handshake_step(dtls_session& s, const dtls_handshake_input& in);

// ── 记录层（应用数据）───────────────────────────────────────────────
/// 保护应用数据为一条（或多条）DTLS record。要求握手已完成。
std::vector<uint8_t> dtls_protect_application(dtls_session& s,
                                              const uint8_t* data, size_t len);

/// 从数据报中解密并提取应用数据（可含多条 record；握手记录会被忽略）。
/// 返回 false 表示数据报无法解析/认证失败。out 可能为空（仅握手/ACK 记录）。
bool dtls_unprotect_application(dtls_session& s, const uint8_t* datagram, size_t len,
                                std::vector<uint8_t>& out);

// ── UDP socket 封装 ──────────────────────────────────────────────────
class dtls_connection {
public:
    dtls_connection();
    ~dtls_connection();

    /// 客户端：连接到 host:port 并完成握手（阻塞，带重传）。
    /// expected_cert 非空时按 SNI 查找预期证书（兼容旧行为）；
    /// trust_store 提供时执行 x509 链验证。
    bool connect(const char* host, uint16_t port,
                 const tls::tls_trust_store* trust_store = nullptr);
    /// 服务端：绑定本地 UDP 端口并进入握手等待。
    bool bind(uint16_t port, const char* addr = "0.0.0.0");
    /// 服务端：从绑定的 socket 接收第一个客户端数据报并完成握手。
    /// 要求 bind() 已调用，且调用前配置好证书管理器。
    bool server_handshake(tls::tls_certificate_manager& cert_mgr);

    /// 发送应用数据（握手完成后）。
    bool send(const uint8_t* data, size_t len);
    /// 接收应用数据（阻塞）。
    bool recv(std::vector<uint8_t>& data);

    /// 配置 DTLS 版本（连接前设置）。
    void set_version(DTLSVersion v) { ver_ = v; }
    /// 服务端：是否要求 cookie 交换。
    void set_require_cookie(bool v) { require_cookie_ = v; }
    /// 设置握手总超时（毫秒，默认 30000）。
    /// connect()/server_handshake() 超时未完成握手时返回 false。
    void set_handshake_timeout_ms(int ms) { handshake_timeout_ms_ = ms; }
    /// 配置密钥交换组与密码套件（连接前设置）。
    void set_cipher_suite(tls::CipherSuite cs) { cipher_suite_ = cs; }
    void set_key_share_group(tls::NamedGroup g) { ks_group_ = g; }
    /// 客户端 SNI。
    void set_server_name(const std::string& n) { server_name_ = n; }

    bool handshake_done() const { return done_; }
    dtls_session& session() { return s_; }
    /// 最近一次握手/收发失败原因（调试用）。
    const std::string& last_error() const { return last_error_; }

    /// 已绑定/连接的本地端口（bind(0) 后用于告知客户端连接地址）。
    uint16_t local_port() const;

    void close();

private:
    dtls_session s_;
    DTLSVersion ver_ = DTLSVersion::V12;
    bool require_cookie_ = false;
    tls::CipherSuite cipher_suite_ = tls::CipherSuite::TLS_AES_128_GCM_SHA256;
    tls::NamedGroup ks_group_ = tls::NamedGroup::X25519;
    std::string server_name_;
    bool done_ = false;
    int handshake_timeout_ms_ = 30000;
    std::string last_error_;

#ifdef _WIN32
    void* sock_ = nullptr;   // SOCKET
#else
    int sock_ = -1;
#endif
    bool open_ = false;
    bool is_server_ = false;

    // 对端地址
    std::string peer_addr_;
    uint16_t peer_port_ = 0;
};

} // namespace jpssl::dtls
