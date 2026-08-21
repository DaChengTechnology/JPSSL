# TLS API（TLS 1.2 / 1.3）

头文件：`include/tls.hpp`，命名空间 `jpssl::tls`。

TLS 模块提供完整的 TLS 1.2 和 TLS 1.3 握手流程、记录层加解密、SNI 多域名证书管理、0-RTT 早数据。支持 AES-128/256-GCM、ChaCha20-Poly1305、AES-128-CCM 等密码套件，以及 Ed25519、ECDSA P-256、RSA-2048/4096、SM2 等多种证书签名算法，并支持 **[RFC 8998 国密套件](https://www.rfc-editor.org/rfc/rfc8998)**（TLS_SM4_GCM_SM3 + SM2）。

```cpp
#include "tls.hpp"
using namespace jpssl::tls;
```

## 1. 创建证书

证书是 TLS 握手的关键组件，包含公钥、私钥和签名算法。jpssl 集成了 **X.509 v3**（[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)）证书编码：当 `cert_data` 为空时，握手过程会自动调用 `tls_make_x509_self_signed()` 生成标准的 X.509 v3 DER 自签名证书（含 SAN、KeyUsage、EKU 扩展），也可以手动预生成并填入 `cert_data`。

```cpp
// ── Ed25519 证书（握手时自动生成 X.509 DER） ──
auto cert = std::make_unique<tls_certificate>();
cert->subject_name = "example.com";
cert->sig_alg = SignatureAlgorithm::ED25519;
ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);

// 可选：预生成 X.509 v3 DER 证书并填入 cert_data
cert->cert_data = tls_make_x509_self_signed(*cert);

// ── ECDSA P-256 证书 ──
auto ecdsa_cert = std::make_unique<tls_certificate>();
ecdsa_cert->subject_name = "example.org";
ecdsa_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
ecdsa_p256_keygen(ecdsa_cert->pub.ecdsa_p256, ecdsa_cert->priv.ecdsa_p256);

// ── RSA-2048 证书 ──
auto rsa_cert = std::make_unique<tls_certificate>();
rsa_cert->subject_name = "example.net";
rsa_cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
rsa_keygen(rsa_cert->pub.rsa, rsa_cert->priv.rsa);

// ── SM2 证书（[RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) 国密 TLS） ──
auto sm2_cert = std::make_unique<tls_certificate>();
sm2_cert->subject_name = "example.cn";
sm2_cert->sig_alg = SignatureAlgorithm::SM2_SM3;
sm2_keygen(sm2_cert->pub.sm2, sm2_cert->priv.sm2);
```

## 2. 多域名证书管理（SNI）

证书管理器支持根据客户端 SNI 请求自动选择对应域名的证书，`get_certificate` 支持通配降级。

```cpp
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("example.com", std::move(cert));
cert_mgr.add_certificate("example.org", std::move(ecdsa_cert));
cert_mgr.add_certificate("example.net", std::move(rsa_cert));

// 查询证书
const tls_certificate* c = cert_mgr.get_certificate("example.com");
if (c) { /* 使用证书 */ }

// 默认证书（第一个添加的证书）
const tls_certificate* def = cert_mgr.get_default_certificate();
```

## 3. TLS 1.3 完整握手（推荐）

TLS 1.3 使用 X25519 进行密钥交换。国密套件用法：设置 `client.cipher_suite = CipherSuite::TLS_SM4_GCM_SM3`，服务端使用 SM2 证书自动协商。

```cpp
// ── 服务端：准备证书管理器 ──
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("example.com", std::move(server_cert));

// ── 客户端：发起握手 ──
tls_session client;
client.server_name = "example.com"; // SNI：指定目标域名

// Step 1: 客户端生成 ClientHello
std::vector<uint8_t> client_hello;
tls13_make_client_hello(client, client_hello);

// 将 client_hello 通过网络发送给服务端...

// ── 服务端：处理 ClientHello，生成完整回包 ──
tls_session server;
std::vector<uint8_t> server_flight;
tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                          server_flight, cert_mgr);

// 将 server_flight 通过网络发送给客户端...

// ── 客户端：处理服务端回包，生成 Client Finished ──
std::vector<uint8_t> client_finished;
tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                             client_finished, &cert_mgr);

// 将 client_finished 通过网络发送给服务端...

// ── 服务端：验证客户端 Finished ──
tls13_process_client_finished(server, client_finished.data(), client_finished.size());

// 握手完成！双向安全通信

// 客户端 → 服务端
auto client_record = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                  (const uint8_t*)"Hello, TLS 1.3!", 16);
ContentType ct; std::vector<uint8_t> plaintext;
tls_decrypt(server, client_record.data(), client_record.size(), ct, plaintext);

// 服务端 → 客户端（使用服务端专用 API）
auto server_record = tls_server_encrypt(server, ContentType::APPLICATION_DATA,
                                         (const uint8_t*)"Hi from server!", 15);
ContentType ct2; std::vector<uint8_t> resp;
tls_decrypt(client, server_record.data(), server_record.size(), ct2, resp);
```

## 4. TLS 1.3 简化版握手（一次性）

适合不需要分步处理握手消息的场景。注意简化版只交换 ServerHello，不包含加密握手消息。

```cpp
tls_session client, server;
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("localhost", std::move(cert));

// 服务端处理 ClientHello 并生成 ServerHello
std::vector<uint8_t> sh, ch;
tls13_make_client_hello(client, ch);
tls13_handshake_server(server, ch.data(), ch.size(), sh, cert_mgr);

// 客户端处理服务端回包
std::vector<uint8_t> dummy;
tls13_process_server_flight(client, sh.data(), sh.size(), dummy, &cert_mgr);

// 安全通信（应用数据加解密）
auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA,
                       (const uint8_t*)"data", 4);
ContentType t; std::vector<uint8_t> dec;
tls_decrypt(server, enc.data(), enc.size(), t, dec);
```

## 5. TLS 1.3 0-RTT（零往返）+ PSK 会话恢复

0-RTT 允许客户端在握手完成前发送应用数据，基于前一次握手的 PSK（Pre-Shared Key）恢复会话。

```cpp
// ═══════════════════════════════════════════════════════
// 阶段 1: 完整握手 + 获取 NewSessionTicket
// ═══════════════════════════════════════════════════════

tls_session client, server;
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("example.com", std::move(server_cert));

std::vector<uint8_t> ch, sf, cf;
tls13_make_client_hello(client, ch);
tls13_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr);
tls13_process_server_flight(client, sf.data(), sf.size(), cf, &cert_mgr);
tls13_process_client_finished(server, cf.data(), cf.size());

// ═══════════════════════════════════════════════════════
// 阶段 2: 服务端生成会话票据
// ═══════════════════════════════════════════════════════
std::vector<uint8_t> ticket_msg;
tls13_make_new_session_ticket(server, ticket_msg);

auto enc_ticket = tls_encrypt_handshake(server, ticket_msg.data(), ticket_msg.size());
// 客户端接收并存储 PSK
tls13_store_psk(client, ticket_msg.data(), ticket_msg.size());

// ═══════════════════════════════════════════════════════
// 阶段 3: 后续连接 — PSK 恢复 + 0-RTT 早数据
// ═══════════════════════════════════════════════════════
tls_session client2, server2;
// 客户端复制 PSK（实际应用中从持久化存储加载）
client2.psk_valid = true;
memcpy(client2.psk_identity, client.psk_identity, client.psk_identity_len);
client2.psk_identity_len = client.psk_identity_len;
memcpy(client2.psk_value, client.psk_value, tls_hash_len(client.cipher_suite));
client2.ticket_age_add = client.ticket_age_add;
client2.ticket_issue_time = client.ticket_issue_time;
client2.server_name = "example.com";

// 服务端也要有相同的 PSK（实际应用中从数据库/缓存加载）
server2.psk_valid = true;
memcpy(server2.psk_identity, server.psk_identity, server.psk_identity_len);
server2.psk_identity_len = server.psk_identity_len;
memcpy(server2.psk_value, server.psk_value, tls_hash_len(server.cipher_suite));
server2.is_server = true;

// 客户端生成含 PSK 扩展的 ClientHello
std::vector<uint8_t> psk_ch;
tls13_make_psk_client_hello(client2, psk_ch);

// 服务端处理 PSK ClientHello，接受 early_data
bool accept_early_data = false;
tls13_process_psk_client_hello(server2, psk_ch.data(), psk_ch.size(), accept_early_data);

// 客户端发送 0-RTT 早数据（在握手完成前！）
auto early_data = tls13_encrypt_early_data(client2,
    (const uint8_t*)"Early data before handshake!", 29);

// 服务端解密早数据
ContentType ct; std::vector<uint8_t> early_plain;
tls13_decrypt_early_data(server2, early_data.data(), early_data.size(), ct, early_plain);

// 服务端发送 EndOfEarlyData，然后继续正常握手流程
auto eoed = tls13_make_end_of_early_data();
auto enc_eoed = tls_encrypt_handshake(server2, eoed.data(), eoed.size());
tls13_process_end_of_early_data(client2, eoed.data(), eoed.size());
```

## 6. TLS 1.2 握手（[RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)）

支持 **RSA** 和 **ECDHE**（X25519）两种密钥交换方式，完整的密码套件协商、ServerKeyExchange、Certificate、ServerHelloDone 消息流程。

```cpp
// ── 服务端：准备 RSA 证书 ──
tls_certificate_manager cert_mgr;
auto rsa_cert = std::make_unique<tls_certificate>();
rsa_cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
rsa_keygen(rsa_cert->pub.rsa, rsa_cert->priv.rsa);
cert_mgr.add_certificate("example.com", std::move(rsa_cert));

// ── 客户端：发起握手 ──
tls_session client;
client.server_name = "example.com";

std::vector<uint8_t> ch12;
tls12_make_client_hello(client, ch12);

uint8_t pre_master[48];
for (int i = 0; i < 48; i++) pre_master[i] = (uint8_t)(rand() % 256);
pre_master[0] = 0x03; pre_master[1] = 0x03;  // TLS 1.2 协议版本

uint8_t encrypted_pms[256];
rsa_encrypt(cert_mgr.get_certificate("example.com")->pub.rsa,
            std::span<const uint8_t>(pre_master, 48), encrypted_pms);

// ── 服务端：处理 ClientHello，RSA 解密 pre-master ──
tls_session server;
uint8_t decrypted_pms[48];
std::vector<uint8_t> sh12;
tls12_make_server_flight(server, ch12.data(), ch12.size(), sh12,
                          encrypted_pms, 256, decrypted_pms, cert_mgr);

// ── 客户端：处理服务端回包，生成 Finished ──
std::vector<uint8_t> cf12;
tls12_process_server_flight(client, sh12.data(), sh12.size(),
                              pre_master, 48, cf12);

// ── 服务端：验证客户端 Finished ──
tls12_process_client_finished(server, cf12.data(), cf12.size());

// 握手完成！安全通信
auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA,
                       (const uint8_t*)"TLS 1.2 data", 12);
ContentType t; std::vector<uint8_t> dec;
tls_decrypt(server, enc.data(), enc.size(), t, dec);
```

## 7. 记录层加解密（握手完成后）

握手完成后，所有应用数据通过记录层加密传输。`tls_encrypt` / `tls_decrypt` 根据 `session.is_server` 自动选择正确的密钥方向。

```cpp
// ── 通用 API（双向） ──
std::vector<uint8_t> encrypted = tls_encrypt(
    session, ContentType::APPLICATION_DATA,
    plaintext_data, plaintext_len);
ContentType ct; std::vector<uint8_t> decrypted;
bool ok = tls_decrypt(session, encrypted.data(), encrypted.size(), ct, decrypted);

// ── 服务端专用 API（自文档化，显式方向） ──
auto server_record = tls_server_encrypt(server, ContentType::APPLICATION_DATA,
                                         (const uint8_t*)"response", 8);
ContentType sct; std::vector<uint8_t> from_client;
bool s_ok = tls_server_decrypt(server, client_record.data(),
                                client_record.size(), sct, from_client);
```

## 8. 大消息自动分片与合并

- **记录层**（`tls_encrypt` / `tls_decrypt`）：明文 > 16KiB（`TLS_MAX_RECORD_PLAINTEXT`）自动拆分为多条 ≤16KiB 的 record（TLS 1.2 / 1.3 均支持），解密时逐条解析并自动合并还原，单次调用即可收发任意大小的消息。
- **socket 层**（`tls_connection::send` / `recv`）：一次 `send(大缓冲)` 自动分片写出；`recv()` 会把同一突发到达的多条 record 合并后一次返回，大消息无需循环读取。消息边界由应用层协议负责（如 HTTP Content-Length）。
- 测试 `test_tls_large_msg`：覆盖 16KiB 边界、64KiB 长度字段边界、256KiB、TLS 1.2 以及 socket 端到端 128KiB 单次 send / 单次 recv。

## 9. 握手 API 总览

| 函数 | 说明 |
|------|------|
| `tls13_make_client_hello(s, out)` | 客户端生成 ClientHello（含 SNI + X25519 key_share） |
| `tls13_make_server_flight(s, ch, len, out, cert_mgr)` | 服务端处理 ClientHello，生成完整回包（SH+EE+Cert+CV+SF） |
| `tls13_process_server_flight(s, data, len, out, cert_mgr, trust)` | 客户端处理服务端回包，生成 Client Finished；`trust`（`tls_trust_store*`）提供时对服务端证书链执行 x509 验证（含主机名匹配），失败则握手失败 |
| `tls13_process_client_finished(s, data, len)` | 服务端验证客户端 Finished |
| `tls13_handshake_client(s, ch, resp, len)` | 简化版客户端握手（一次性） |
| `tls13_handshake_server(s, ch, len, out, cert_mgr)` | 简化版服务端握手（一次性） |
| `tls13_make_new_session_ticket(s, out, lifetime)` | 服务端生成 NewSessionTicket（握手后调用） |
| `tls13_store_psk(s, ticket, len)` | 客户端从票据中提取并存储 PSK |
| `tls13_make_psk_client_hello(s, out)` | 客户端生成含 PSK 扩展的 ClientHello（0-RTT） |
| `tls13_process_psk_client_hello(s, ch, len, accept)` | 服务端处理 PSK ClientHello，验证 binder 和票据 |
| `tls13_encrypt_early_data(s, data, len)` | 客户端加密 0-RTT 早数据 |
| `tls13_decrypt_early_data(s, rec, len, ct, out)` | 服务端解密 0-RTT 早数据 |
| `tls13_make_end_of_early_data()` | 服务端生成 EndOfEarlyData 消息 |
| `tls13_process_end_of_early_data(s, data, len)` | 客户端处理 EndOfEarlyData |
| `tls12_make_client_hello(s, out)` | 客户端生成 TLS 1.2 ClientHello（含密码套件协商 + signature_algorithms） |
| `tls12_make_server_flight(s, ch, len, out, epms, eplen, pms, cert_mgr)` | 服务端处理 ClientHello，密码套件协商，RSA 解密或 ECDHE 密钥交换，生成完整回包 |
| `tls12_process_server_flight(s, resp, len, pms, pms_len, out)` | 客户端处理服务端回包（SH+Cert+SKX+SHD），生成 Finished |
| `tls12_process_client_finished(s, data, len)` | 服务端验证客户端 Finished |
| `tls12_make_certificate(cert)` | 构造 TLS 1.2 Certificate 消息（自动生成 X.509 DER） |
| `tls_make_x509_self_signed(cert, days)` | 从 tls_certificate 生成 X.509 v3 DER 自签名证书 |
| `tls_sig_alg_to_key_type(sig_alg)` | 将 SignatureAlgorithm 映射为 X.509 KeyType |
| `tls12_make_server_hello_done()` | 构造 ServerHelloDone 消息 |
| `tls12_make_client_key_exchange(pub, pms)` | 构造 ClientKeyExchange（RSA 加密 pre-master） |
| `tls12_make_finished(s, for_server)` | 构造 TLS 1.2 Finished 消息 |
| `tls12_verify_finished(s, data, len, for_server)` | 验证 TLS 1.2 Finished |
| `tls_make_change_cipher_spec()` | 构造 ChangeCipherSpec 记录 |
| `tls_make_alert(level, desc)` | 构造 Alert 记录 |
| `tls_encrypt(s, ct, data, len)` | 记录层加密 |
| `tls_decrypt(s, record, len, ct, out)` | 记录层解密 |
| `tls_encrypt_handshake(s, hs_msg, len)` | 加密握手消息（TLS 1.3 内部） |
| `tls_server_encrypt(s, ct, data, len)` | 服务端加密发送（等价于 tls_encrypt，显式方向） |
| `tls_server_decrypt(s, rec, len, ct, out)` | 服务端解密客户端数据（等价于 tls_decrypt） |
| `tls_server_encrypt_handshake(s, hs, len)` | 服务端加密握手消息（内部使用） |

## 10. 证书管理 API

| 类 / 函数 | 说明 |
|-----------|------|
| `tls_certificate` | 证书结构体，含公钥、私钥、签名算法 |
| `tls_certificate::sign(data, len, sig, sig_len)` | 使用证书私钥签名 |
| `tls_certificate::verify(data, len, sig, sig_len)` | 使用证书公钥验证签名 |
| `tls_certificate::from_pem(cert_pem, key_pem, err)` | 从 PEM 证书 + PEM 私钥构造服务端证书（私钥支持 PKCS#8/PKCS#1/SEC1/[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)/加密 PEM） |
| `tls_certificate::from_pem_file(cert_path, key_path, err)` | 从证书 / 私钥 PEM 文件构造 |
| `tls_certificate::from_csr_pem(csr_pem, key_pem, err)` | 从 CSR + 私钥构造（握手时按 CSR 主体自动生成自签证书） |
| `tls_certificate::from_csr_pem_file(csr_path, key_path, err)` | 从 CSR / 私钥 PEM 文件构造 |
| `tls_certificate_manager::add_certificate(domain, cert)` | 添加域名对应的证书 |
| `tls_certificate_manager::get_certificate(domain)` | 根据域名获取证书（支持通配降级） |
| `tls_certificate_manager::get_default_certificate()` | 获取默认证书 |
| `tls_trust_store` | 客户端信任库：CA 根证书集合（`from_pem` / `from_pem_file` / `from_system` 系统信任库） |
| `tls_key_type_to_sig_alg(kt)` | KeyType → TLS 签名方案映射（from_pem 内部使用） |
| `tls_parse_server_name(extensions, len)` | 从扩展中解析 SNI 域名 |

## 11. 会话状态

| 字段 | 说明 |
|------|------|
| `tls_session::ver` | TLS 版本（V12 / V13） |
| `tls_session::server_name` | SNI 客户端请求的域名 |
| `tls_session::client_random` / `server_random` | 32 字节随机数 |
| `tls_session::cipher_suite` | 协商的密码套件（AES-128/256-GCM, ChaCha20, CCM, SM4-GCM/CCM） |
| `tls_session::handshake_secret` / `master_secret` | 握手机密 / 主密钥（32 或 48 字节，取决于套件） |
| `tls_session::client_write_key` / `server_write_key` | 记录层加密密钥（16 或 32 字节，取决于套件） |
| `tls_session::client_write_iv` / `server_write_iv` | 记录层加密 IV（12 字节） |
| `tls_session::client_seq` / `server_seq` | 记录层序列号（防重放） |
| `tls_session::is_server` | 是否为服务端会话 |
| `tls_session::transcript_hash` | 握手 transcript 哈希（32 或 48 字节） |
| `tls_session::psk_valid` / `psk_identity` / `psk_value` | PSK 恢复会话状态（0-RTT） |
| `tls_session::client_early_write_key` / `client_early_write_iv` | 0-RTT 早数据加密密钥和 IV |
| `tls_session::early_data_accepted` | 服务端是否接受了 0-RTT 早数据 |

## 12. kTLS（内核 TLS）

`include/ktls.hpp` 在消息级 TLS API 之上提供 **Linux 内核 TLS（kTLS）记录层卸载**：
握手（`tls_handshake` / `tls_connection`）仍在用户态完成后，把会话密钥导出并交给
内核（`TCP_ULP "tls"`），此后该 fd 上的应用数据以明文读写，由内核负责 record
封装与加解密。

```cpp
#include "ktls.hpp"
using namespace jpssl::tls;

// 1) 检测支持（仅 Linux 内核 >= 4.13 且开启 CONFIG_TLS）
if (ktls_is_supported() != ktls_result::ok) { /* 平台/内核不支持，走用户态即可 */ }

// 2) 握手完成后导出密钥材料
ktls_params params;
ktls_result r = ktls_export_params(session, params);   // session 为 tls_session
if (r != ktls_result::ok) { /* 握手中 / 套件不支持等 */ }

// 3) 在已连接、已握手的 TCP fd 上启用内核 TLS
std::string err;
r = ktls_enable(params, fd, &err);
if (r == ktls_result::ok) {
    send(fd, "GET / HTTP/1.1\r\n\r\n", ...);   // 明文直通：内核负责加解密
}
```

| API | 说明 |
|------|------|
| `ktls_result ktls_is_supported()` | 检测当前系统是否支持 kTLS |
| `ktls_result ktls_export_params(const tls_session& s, ktls_params& out)` | 从已握手完成的 `tls_session` 导出 TX/RX 密钥（`ktls_params`：key/iv/salt/rec_seq、版本与套件） |
| `ktls_result ktls_enable(const ktls_params& p, int fd, std::string* error)` | 在 TCP fd 上启用内核 TLS；成功后 fd 进入明文直通模式 |

`ktls_result`：`ok` / `unsupported` / `not_stream` / `invalid_params` /
`handshake_pending` / `cipher_unsupported` / `syscall_failed`。
覆盖 TLS 1.2/1.3 的 AES-GCM-128/256、ChaCha20-Poly1305、AES-CCM、SM4-GCM/CCM
套件映射；不支持时优雅降级。

> socket 封装层用户可直接用 `tls_connection::enable_ktls()` / `ktls_active()`，
> 见 [TLS socket 封装层](API-TLS-Socket)。
