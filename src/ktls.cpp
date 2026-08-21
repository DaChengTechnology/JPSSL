// ktls.cpp -- Kernel TLS (kTLS) 支持：Linux 内核记录层卸载
//
// 原理（Linux net/tls, Upper Layer Protocol）：
//   1) 用户态完成 TLS 握手（本库 tls12/tls13_client|server 路径）；
//   2) 用 setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 4) 挂载内核 TLS ULP；
//   3) 用 setsockopt(fd, SOL_TLS, TLS_TX) / TLS_RX 提交 TX/RX 密钥材料；
//   4) 之后本 fd 的 send/recv 以明文交互，内核负责 TLS 记录封装与加解密。
//
// 仅 Linux（__linux__）实现；其他平台返回 unsupported 且不参与编译逻辑。
#include "ktls.hpp"

#include <cstring>

#ifdef __linux__
#include <arpa/inet.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace jpssl::tls {

// ── 套件→内核 cipher_type / key 长度 映射 ──────────────────────────────
namespace {

// 计算某个套件的 AEAD key 长度（字节）
int suite_key_len(CipherSuite cs) {
    if (cs == CipherSuite::TLS_AES_256_GCM_SHA384 ||
        cs == CipherSuite::TLS_CHACHA20_POLY1305_SHA256 ||
        cs == CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
        cs == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ||
        cs == CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 ||
        cs == CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
        cs == CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384 ||
        cs == CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 ||
        cs == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
        cs == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ||
        cs == CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
        cs == CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 ||
        cs == CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
        return 32;
    return 16;
}

// 内核是否支持该套件（对应 tls_crypto_info.cipher_type）
bool suite_ktls_supported(CipherSuite cs) {
    switch (cs) {
        // TLS 1.3
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384:
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_SM4_GCM_SM3:
        case CipherSuite::TLS_SM4_CCM_SM3:
        // TLS 1.2 AEAD（内核 kTLS 支持 GCM / ChaCha20-Poly1305 / CCM）
        case CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return true;
        default:
            // CBC / CCM_8 等：CBC 内核仅支持 TLS1.2 有限套件，暂不接入；
            // CCM_8 内核未定义对应 cipher。保守返回不支持。
            return false;
    }
}

#ifdef __linux__
int suite_cipher_type(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
            return TLS_CIPHER_AES_GCM_128;
        case CipherSuite::TLS_AES_256_GCM_SHA384:
        case CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
            return TLS_CIPHER_AES_GCM_256;
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return TLS_CIPHER_CHACHA20_POLY1305;
        case CipherSuite::TLS_AES_128_CCM_SHA256: return TLS_CIPHER_AES_CCM_128;
        case CipherSuite::TLS_SM4_GCM_SM3: return TLS_CIPHER_SM4_GCM;
        case CipherSuite::TLS_SM4_CCM_SM3: return TLS_CIPHER_SM4_CCM;
        default: return 0;
    }
}

// 单方向启用：dir 为 TLS_TX 或 TLS_RX
ktls_result ktls_set_dir(int fd, int dir, TLSVersion ver, CipherSuite cs,
                         const uint8_t* key, int key_len,
                         const uint8_t* iv, const uint8_t* salt, int salt_len,
                         uint64_t seq, std::string* error) {
    // 构造与该套件匹配的 tls_crypto_info（TLS1.2 与 TLS1.3 结构相同，
    // 只是 info.version 不同）。使用 .info.version = TLS_1_2/1_3。
    // 统一按最大结构 tls12_crypto_info_chacha20_poly1305 的大小分配，
    // 其含 12 字节 iv，能覆盖 AES-GCM(8+4) 与 ChaCha(12+0) 布局。
    struct {
        struct tls_crypto_info info;
        unsigned char iv[12];
        unsigned char key[32];
        unsigned char salt[4];
        unsigned char rec_seq[8];
    } ci = {};
    ci.info.version = (uint16_t)(ver == TLSVersion::V12 ? TLS_1_2_VERSION
                                                        : TLS_1_3_VERSION);
    ci.info.cipher_type = (uint16_t)suite_cipher_type(cs);
    if (ci.info.cipher_type == 0) {
        if (error) *error = "ktls: unsupported cipher type";
        return ktls_result::cipher_unsupported;
    }
    int klen = key_len > 32 ? 32 : key_len;
    if (klen > 0) std::memcpy(ci.key, key, (size_t)klen);
    // iv：AES-GCM 取前 8 字节（内核与 salt 拼成 12 字节 nonce），
    //     ChaCha20 取全部 12 字节（salt 长度 0）。
    int iv_len = (cs == CipherSuite::TLS_CHACHA20_POLY1305_SHA256) ? 12 : 8;
    if (iv_len > 0) std::memcpy(ci.iv, iv, (size_t)iv_len);
    if (salt_len > 0) std::memcpy(ci.salt, salt, (size_t)salt_len);
    for (int i = 0; i < 8; ++i) ci.rec_seq[7 - i] = (uint8_t)(seq >> (i * 8));

    // 结构长度 = 头(4) + iv + key + salt + rec_seq
    // 为兼容不同 cipher 专用结构，统一上报一个较长缓冲（内核按 cipher_type
    // 自行取用前若干个字段）。这里按 4 + 12 + klen + salt_len + 8 计算。
    size_t info_size = sizeof(ci.info) + (size_t)iv_len + (size_t)klen +
                       (size_t)salt_len + 8;
    if (::setsockopt(fd, SOL_TLS, dir, &ci, (socklen_t)info_size) != 0) {
        if (error) *error = "ktls: setsockopt SOL_TLS failed: " + std::string(strerror(errno));
        return ktls_result::syscall_failed;
    }
    return ktls_result::ok;
}

#endif // __linux__

} // namespace

// ── 公开接口 ──────────────────────────────────────────────────────────
ktls_result ktls_is_supported() {
#ifdef __linux__
    // 探测：打开一个临时 UDP socket 尝试挂载 ULP 不现实；
    // 直接判断头文件与运行内核版本。这里保守地认为开启 CONFIG_TLS 的
    // 现代内核支持（实际能力在 ktls_enable 的 setsockopt 处验证）。
    return ktls_result::ok;
#else
    return ktls_result::unsupported;
#endif
}

ktls_result ktls_export_params(const tls_session& s, ktls_params& out) {
    out = ktls_params{};
    out.is_server = s.is_server;
    out.version = s.ver;
    out.cipher_suite = s.cipher_suite;
    if (s.is_server ? !s.tls12_secure : (s.server_finished_received == false && s.ver == TLSVersion::V13)) {
        if (s.ver == TLSVersion::V13 && !s.server_finished_received)
            return ktls_result::handshake_pending;
        if (s.ver == TLSVersion::V12 && !s.tls12_secure)
            return ktls_result::handshake_pending;
    }
    int klen = suite_key_len(s.cipher_suite);
    if (klen == 0 || !suite_ktls_supported(s.cipher_suite))
        return ktls_result::cipher_unsupported;

    // 角色：本端发送用 client/server_write_key 中“本端”那组。
    const uint8_t* txk = s.is_server ? s.server_write_key : s.client_write_key;
    const uint8_t* txi = s.is_server ? s.server_write_iv : s.client_write_iv;
    const uint8_t* rxk = s.is_server ? s.client_write_key : s.server_write_key;
    const uint8_t* rxi = s.is_server ? s.client_write_iv : s.server_write_iv;
    uint64_t txseq = s.is_server ? s.server_seq : s.client_seq;
    uint64_t rxseq = s.is_server ? s.client_seq : s.server_seq;

    std::memcpy(out.tx_key, txk, (size_t)klen);
    std::memcpy(out.tx_iv, txi, 12);
    if (s.ver == TLSVersion::V12) {
        // TLS1.2 AEAD：write_iv 前 4 字节是 salt，后 8 字节隐式 IV/填充
        std::memcpy(out.tx_salt, txi, 4);
    }
    out.tx_seq = txseq;

    std::memcpy(out.rx_key, rxk, (size_t)klen);
    std::memcpy(out.rx_iv, rxi, 12);
    if (s.ver == TLSVersion::V12) std::memcpy(out.rx_salt, rxi, 4);
    out.rx_seq = rxseq;
    return ktls_result::ok;
}

ktls_result ktls_enable(const ktls_params& p, int fd, std::string* error) {
#ifdef __linux__
    if (fd < 0) {
        if (error) *error = "ktls: invalid fd";
        return ktls_result::invalid_params;
    }
    int klen = suite_key_len(p.cipher_suite);
    if (klen == 0 || !suite_ktls_supported(p.cipher_suite))
        return ktls_result::cipher_unsupported;

    // 1) 挂载 TLS ULP
    if (::setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) != 0) {
        if (error) {
            *error = "ktls: TCP_ULP attach failed (" + std::string(strerror(errno)) +
                     "); kernel kTLS not available";
        }
        return ktls_result::syscall_failed;
    }

    // 2) 提交 RX 方向（先 RX 后 TX，内核要求接收方向在发送之前设置）
    ktls_result r = ktls_set_dir(fd, TLS_RX, p.version, p.cipher_suite,
                                 p.rx_key, klen, p.rx_iv, p.rx_salt,
                                 (p.version == TLSVersion::V12) ? 4 : 0,
                                 p.rx_seq, error);
    if (r != ktls_result::ok) return r;

    // 3) 提交 TX 方向
    r = ktls_set_dir(fd, TLS_TX, p.version, p.cipher_suite,
                     p.tx_key, klen, p.tx_iv, p.tx_salt,
                     (p.version == TLSVersion::V12) ? 4 : 0,
                     p.tx_seq, error);
    if (r != ktls_result::ok) return r;
    return ktls_result::ok;
#else
    (void)p; (void)fd; (void)error;
    return ktls_result::unsupported;
#endif
}

} // namespace jpssl::tls
