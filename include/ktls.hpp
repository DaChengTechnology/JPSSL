// ktls.hpp -- Kernel TLS (kTLS) 支持
//
// kTLS = Linux 内核 TLS 记录层卸载（net/tls, Upper Layer Protocol）：
//   握手仍在用户态完成后，把会话密钥通过 setsockopt 配置给内核，
//   此后应用数据以明文读写 socket，由内核负责 record 封装与加解密，
//   用户态不再经过 tls_encrypt / tls_decrypt。
//
// 该接口仅 Linux 内核 >= 4.13 且开启 CONFIG_TLS 时可用；其他平台
// （Windows / macOS / 不支持的内核）一律返回 ktls_result::unsupported。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "tls.hpp"

namespace jpssl::tls {

/// kTLS 配置/启用结果
enum class ktls_result {
    ok = 0,          ///< 成功启用内核 TLS
    unsupported,     ///< 平台/内核不支持 kTLS
    not_stream,      ///< 非流式 socket（数据报/UDP 不支持）
    invalid_params,  ///< 参数错误（密钥、套件不匹配等）
    handshake_pending, ///< 握手未完成，密钥尚未就绪
    cipher_unsupported,///< 当前协商套件内核 kTLS 不支持
    syscall_failed,  ///< setsockopt 等系统调用失败
};

/// 从已握手完成的 tls_session 导出给内核的密钥材料。
struct ktls_params {
    bool        is_server   = false;  // 本端角色（决定 TX/RX 密钥方向）
    TLSVersion  version     = TLSVersion::V13; // 握手协商版本
    CipherSuite cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256; // 协商套件

    // TX（本端发送）方向
    uint8_t tx_key[32]  = {};  // 密码算法密钥（16/32 字节）
    uint8_t tx_iv[16]   = {};  // 初始化向量（TLS1.2 GCM 用前 12 字节 [salt|iv]）
    uint8_t tx_salt[4]  = {};
    uint64_t tx_seq     = 0;   // 当前 record 序号

    // RX（本端接收，即对端发送）方向
    uint8_t rx_key[32]  = {};
    uint8_t rx_iv[16]   = {};
    uint8_t rx_salt[4]  = {};
    uint64_t rx_seq     = 0;
};

/// 检测当前系统是否支持 kTLS（仅 Linux 且内核开启 CONFIG_TLS）。
ktls_result ktls_is_supported();

/// 从 tls_session 导出 TX/RX 密钥材料（握手需已完成）。
ktls_result ktls_export_params(const tls_session& s, ktls_params& out);

/// 在已连接、已握手完成的 TCP socket 上启用内核 TLS。
/// 成功后本 fd 即处于“明文直通”模式；后续 send/recv 直接读写明文，
/// 内核负责 TLS 记录封装与加解密（会覆盖用户态对同一 fd 的加解密）。
ktls_result ktls_enable(const ktls_params& p, int fd, std::string* error = nullptr);

} // namespace jpssl::tls
