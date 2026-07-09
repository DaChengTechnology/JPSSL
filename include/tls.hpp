#pragma once
/** tls.hpp — TLS 1.2/1.3 记录层 + 简化握手 */
#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sha256.hpp"
#include "hkdf.hpp"
#include "x25519.hpp"
#include <cstdint>
#include <string>
#include <vector>
namespace jpssl::tls {

enum class TLSVersion { V12=0x0303, V13=0x0304 };
enum class ContentType { CHANGE_CIPHER_SPEC=20, ALERT=21, HANDSHAKE=22, APPLICATION_DATA=23 };
enum class HandshakeType { CLIENT_HELLO=1, SERVER_HELLO=2, ENCRYPTED_EXTENSIONS=8, CERTIFICATE=11, CERT_VERIFY=15, FINISHED=20 };

struct tls_record { ContentType type; TLSVersion ver; std::vector<uint8_t> payload; };
struct tls_session {
    TLSVersion ver;
    uint8_t client_random[32], server_random[32];
    uint8_t handshake_secret[32], master_secret[32];
    uint8_t client_write_key[32], server_write_key[32];
    uint8_t client_write_iv[12], server_write_iv[12];
    uint64_t client_seq, server_seq;
    aes_context aes_ctx;
};

// ── TLS 1.3 简化握手 ──
bool tls13_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello, const uint8_t* server_response, size_t resp_len);
bool tls13_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len, std::vector<uint8_t>& server_response);

// ── 记录层加密/解密 ──
std::vector<uint8_t> tls_encrypt(tls_session& s, ContentType ct, const uint8_t* data, size_t len);
bool tls_decrypt(tls_session& s, const uint8_t* record, size_t len, ContentType& ct, std::vector<uint8_t>& out);

}
