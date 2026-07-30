# jpssl — C++20 高性能密码学库（CPU + MUSA GPU）

跨平台密码学库，支持 **AES**、**ChaCha20-Poly1305**、**RSA**、**TLS 1.2/1.3**、**Ed25519**、**ECDSA**，以及 **SM2/SM3/SM4 国密算法**（GM/T 0002/3/4-2012，RFC 8998 TLS 1.3 国密套件）。提供 CPU 优化（AES-NI/AVX2/Montgomery）和 MUSA GPU 加速。同时提供静态库和动态库两种构建方式。

## 架构

```
┌──────────────────────────────────────────────────┐
│              jpssl-test (测试)                    │
├──────────────────────────────────────────────────┤
│  libjpssl_musa (MUSA GPU 加速)                    │
│  ├─ aes_gpu.mu        AES ECB kernel             │
│  ├─ chacha20_gpu.mu   ChaCha20 keystream kernel   │
│  ├─ rsa_gpu.mu        RSA 批量模幂 kernel         │
│  ├─ sha512_gpu.mu     SHA-384/512 GPU kernel       │
│  ├─ aes_musa.cpp      主机端封装                  │
│  ├─ rsa_musa.cpp      RSA GPU 封装               │
│  └─ sha512_musa.cpp   SHA-512 MUSA 封装           │
├──────────────────────────────────────────────────┤
│  libjpssl_cpu (纯 CPU)                           │
│  ├─ aes_cpu.cpp            AES + AES-NI          │
│  ├─ aes_gcm_avx2.cpp       AVX2 GCM 4 路并行      │
│  ├─ aes_gcm_avx512.cpp     AVX512 GCM 8 路并行    │
│  ├─ aes_gcm_auto.cpp       GCM 自动分派           │
│  ├─ chacha20_poly1305.cpp  ChaCha20-Poly1305 AEAD │
│  ├─ rsa.cpp (+body.inc)    RSA 2048/4096 Montgomery│
│  ├─ sha256.cpp             SHA-256 哈希           │
│  ├─ sha3.cpp               SHA3-256/384/512 哈希   │
│  ├─ sha512_cpu.cpp         SHA-384/512 哈希 (CPU) │
│  ├─ sha512_opt.cpp         SHA-384/512 哈希 (SSE) │
│  ├─ hmac.cpp               HMAC-SHA256/SHA384      │
│  ├─ hkdf.cpp               HKDF-SHA256/SHA384      │
│  ├─ x25519.cpp             X25519 ECDH            │
│  ├─ ed25519.cpp            Ed25519 签名/验证      │
│  ├─ ecdsa.cpp              ECDSA P-256 签名/验证  │
│  ├─ sm2.cpp                SM2 签名/验证/密钥交换  │
│  ├─ sm3.cpp                SM3 密码杂凑算法        │
│  ├─ sm4.cpp                SM4 分组密码            │
│  ├─ sm4_gcm.cpp            SM4-GCM AEAD 模式       │
│  ├─ hmac.cpp               HMAC-SHA256/SHA384/SM3   │
│  ├─ hkdf.cpp               HKDF-SHA256/SHA384/SM3   │
│  └─ tls.cpp                TLS 1.2/1.3 记录层+握手│
└──────────────────────────────────────────────────┘
```

## 快速开始

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 运行测试
LD_LIBRARY_PATH=/usr/local/musa/lib ./jpssl-test

# 安装到系统（可选）
sudo make install
```

### 动态库 / 静态库

构建时默认同时生成静态库和动态库：

| 库文件 | 类型 | 说明 |
|--------|------|------|
| `libjpssl_cpu.a` | 静态库 | CPU 密码学库 |
| `libjpssl_cpu.so` | 动态库 | CPU 密码学库（共享） |
| `libjpssl_musa.a` | 静态库 | GPU 加速库 |
| `libjpssl_musa.so` | 动态库 | GPU 加速库（共享） |

链接动态库：
```bash
g++ -std=c++20 your_app.cpp -I./include -L./build -ljpssl_cpu -o your_app
LD_LIBRARY_PATH=./build ./your_app
```

## 算法总览

| 算法 | 模式 | CPU 加速 | GPU 加速 |
|------|------|----------|----------|
| **AES-128/256** | ECB, CBC+PKCS7, GCM | AES-NI (~5 GB/s), AVX2/AVX512 GCM | ECB kernel |
| **ChaCha20-Poly1305** | 流加密, AEAD | — | Keystream kernel |
| **RSA 2048/4096** | PKCS#1 v1.5 | Montgomery CIOS | 批量模幂 |
| **SHA-256** | 哈希 | — | — |
| **SHA-384/512** | 哈希 (FIPS 180-4) | SSE4.1 消息调度 | GPU kernel |
| **SHA3-256/384/512** | 哈希 (FIPS 202, Keccak) | — | — |
| **HMAC-SHA256/SHA384/SM3** | MAC | — | — |
| **HKDF-SHA256/SHA384/SM3** | TLS 1.3 密钥派生 | — | — |
| **X25519** | ECDH 密钥交换 | — | — |
| **Ed25519** | 数字签名 (EdDSA) | — | — |
| **ECDSA P-256** | 数字签名 (secp256r1) | — | — |
| **SM2** | 数字签名/密钥交换 (sm2p256v1, GM/T 0003) | — | — |
| **SM3** | 密码杂凑 (256-bit, GM/T 0004) | — | — |
| **SM4** | 分组密码 (128-bit, GM/T 0002) | — | — |
| **SM4-GCM** | SM4 AEAD 认证加密 (NIST SP 800-38D) | AVX2 自动分派 | — |
| **SM4-CCM** | SM4 AEAD 认证加密 (NIST SP 800-38C) | — | — |
| **TLS 1.2/1.3** | 完整握手, 密码套件协商, ECDHE/RSA, AES-GCM/ChaCha20/CCM/SM4-GCM, 0-RTT, RFC 8998 | AVX2/AVX512 GCM | — |

## API 示例

### AES

```cpp
#include "aes.hpp"
aes_context ctx; ctx.init(std::span<const uint8_t,16>(key));
aes_cbc_encrypt(ctx, iv, plaintext, ciphertext);
aes_gcm_encrypt(ctx, iv, 12, plaintext, aad, ct, tag);
```

### ChaCha20-Poly1305

```cpp
#include "chacha20_poly1305.hpp"
chacha20_poly1305_encrypt(key, nonce, plaintext, aad, ct, tag);
chacha20_stream_xor(key, nonce, input, output);
```

### RSA 2048 / 4096

```cpp
#include "rsa.hpp"
// 2048-bit
rsa_public_key pub; rsa_private_key prv;
rsa_keygen(pub, prv);
rsa_encrypt(pub, plaintext, ct);
rsa_decrypt(prv, ct, recovered);

// 4096-bit
rsa4096_bignum a = rsa4096_bignum::from_uint64(42);
rsa4096_public_key pub4; rsa4096_private_key prv4;
rsa4096_keygen(pub4, prv4);
```

### SHA256 / SHA384/512 / SHA3 / HMAC / HKDF

```cpp
#include "sha256.hpp"
sha256_ctx ctx; sha256_init(&ctx);
sha256_update(&ctx, data, len);
uint8_t digest[32]; sha256_final(&ctx, digest);

#include "sha512.hpp"
sha512_ctx ctx;
sha512_init(&ctx);  // or sha384_init for SHA-384
sha512_update(&ctx, data, len);
uint8_t hash[64]; sha512_final(&ctx, hash);  // output: 64 bytes (SHA-384: 48)
std::string hex = sha512_hex(hash);           // "e718483d0ce769..."

#include "sha3.hpp"
sha3_ctx ctx;
sha3_256_init(&ctx);  // or sha3_384_init / sha3_512_init
sha3_update(&ctx, data, len);
uint8_t hash[64]; sha3_final(&ctx, hash);

#include "hmac.hpp"
uint8_t mac[32]; hmac_sha256(key,32, msg,len, mac);
uint8_t mac384[48]; hmac_sha384(key,48, msg,len, mac384);
uint8_t mac_sm3[32]; hmac_sm3(key,32, msg,len, mac_sm3);

#include "hkdf.hpp"
// SHA-256
uint8_t prk[32]; hkdf_extract(salt,16, ikm,32, prk);
uint8_t okm[64]; hkdf_expand(prk, info,8, okm,64);
// SHA-384 (用于 TLS 1.3 AES-256-GCM 等套件)
uint8_t prk384[48]; hkdf_extract_sha384(salt,16, ikm,32, prk384);
uint8_t okm384[64]; hkdf_expand_sha384(prk384, info,8, okm384,64);
// SM3 (用于 TLS 1.3 RFC 8998 国密套件)
uint8_t prk_sm3[32]; hkdf_extract_sm3(salt,16, ikm,32, prk_sm3);
uint8_t okm_sm3[64]; hkdf_expand_sm3(prk_sm3, info,8, okm_sm3,64);
```

### SM2 签名/验证 (GM/T 0003)

```cpp
#include "sm2.hpp"

uint8_t pub[64], priv[32];
sm2_keygen(pub, priv);

uint8_t sig[64];
sm2_sign(priv, (const uint8_t*)"message", 7, sig);
bool ok = sm2_verify(pub, (const uint8_t*)"message", 7, sig);

// 从私钥派生公钥
sm2_pub_from_priv(priv, pub);

// 计算用户标识杂凑值 ZA
uint8_t za[32];
sm2_compute_za((const uint8_t*)"1234567812345678", 16, pub, pub+32, za);
```

### SM3 密码杂凑 (GM/T 0004)

```cpp
#include "sm3.hpp"

// 一次性哈希
uint8_t digest[32]; sm3_hash(digest, (const uint8_t*)data, len);

// 增量哈希
sm3_ctx ctx; sm3_init(&ctx);
sm3_update(&ctx, data, len);
sm3_final(&ctx, digest);
std::string hex = sm3_hex(digest);
```

### SM4 分组密码 (GM/T 0002)

```cpp
#include "sm4.hpp"

uint8_t key[16];
sm4_ctx ctx; sm4_init(&ctx, key);

// 单块
uint8_t cipher[16], recovered[16];
sm4_encrypt_block(&ctx, plain, cipher);
sm4_decrypt_block(&ctx, cipher, recovered);

// ECB
std::vector<uint8_t> ct(plain.size());
sm4_ecb_encrypt(&ctx, std::span<const uint8_t>(plain), std::span<uint8_t>(ct));

// CBC + PKCS#7
uint8_t iv[16] = {};
auto ct = sm4_cbc_encrypt(&ctx, iv, std::span<const uint8_t>(msg, len));
auto pt = sm4_cbc_decrypt(&ctx, iv, std::span<const uint8_t>(ct));
```

### SM4-GCM AEAD

```cpp
#include "sm4_gcm.hpp"

uint8_t key[16], iv[12], tag[16];
sm4_ctx ctx; sm4_init(&ctx, key);

std::vector<uint8_t> ct;
sm4_gcm_encrypt(&ctx, iv, 12,
    std::span<const uint8_t>(plaintext, pt_len),
    std::span<const uint8_t>(aad, aad_len),
    ct, tag, 16);

std::vector<uint8_t> recovered;
bool ok = sm4_gcm_decrypt(&ctx, iv, 12,
    std::span<const uint8_t>(ct),
    std::span<const uint8_t>(aad, aad_len),
    tag, 16, recovered);
```

### SM4-CCM AEAD

```cpp
#include "sm4_ccm.hpp"

uint8_t key[16], nonce[12], tag[16];
sm4_ctx ctx; sm4_init(&ctx, key);

std::vector<uint8_t> ct;
sm4_ccm_encrypt(&ctx, nonce, 12,
    std::span<const uint8_t>(plaintext, pt_len),
    std::span<const uint8_t>(aad, aad_len),
    ct, tag, 16);

std::vector<uint8_t> recovered;
bool ok = sm4_ccm_decrypt(&ctx, nonce, 12,
    std::span<const uint8_t>(ct),
    std::span<const uint8_t>(aad, aad_len),
    tag, 16, recovered);
```

### X25519 ECDH

```cpp
#include "x25519.hpp"
uint8_t alice_pub[32], alice_priv[32];
uint8_t bob_pub[32], bob_priv[32];
x25519_generate_keypair(alice_pub, alice_priv);
x25519_generate_keypair(bob_pub, bob_priv);
uint8_t shared[32];
x25519_scalar_mult(shared, alice_priv, bob_pub);
```

### TLS 1.2 / 1.3

TLS 模块提供完整的 TLS 1.2 和 TLS 1.3 握手流程、记录层加解密、SNI 多域名证书管理、0-RTT 早数据。
支持 AES-128/256-GCM、ChaCha20-Poly1305、AES-128-CCM 等密码套件，以及 Ed25519、ECDSA P-256、RSA-2048/4096 等多种证书签名算法。

```cpp
#include "tls.hpp"
using namespace jpssl::tls;
```

#### 1. 创建证书

证书是 TLS 握手的关键组件，包含公钥、私钥和签名算法。

```cpp
// ── Ed25519 证书 ──
auto cert = std::make_unique<tls_certificate>();
cert->subject_name = "example.com";
cert->sig_alg = SignatureAlgorithm::ED25519;
ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);
cert->cert_data = { /* DER 编码的证书数据 */ };

// ── ECDSA P-256 证书 ──
auto ecdsa_cert = std::make_unique<tls_certificate>();
ecdsa_cert->subject_name = "example.org";
ecdsa_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
ecdsa_p256_keygen(ecdsa_cert->pub.ecdsa_p256, ecdsa_cert->priv.ecdsa_p256);
ecdsa_cert->cert_data = { /* DER 编码的证书数据 */ };

// ── RSA-2048 证书 ──
auto rsa_cert = std::make_unique<tls_certificate>();
rsa_cert->subject_name = "example.net";
rsa_cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
rsa_keygen(rsa_cert->pub.rsa, rsa_cert->priv.rsa);
rsa_cert->cert_data = { /* DER 编码的证书数据 */ };

// ── SM2 证书（RFC 8998 国密 TLS） ──
auto sm2_cert = std::make_unique<tls_certificate>();
sm2_cert->subject_name = "example.cn";
sm2_cert->sig_alg = SignatureAlgorithm::SM2_SM3;
sm2_keygen(sm2_cert->pub.sm2, sm2_cert->priv.sm2);
sm2_cert->cert_data = { /* DER 编码的证书数据 */ };
```

#### 2. 多域名证书管理（SNI）

证书管理器支持根据客户端 SNI 请求自动选择对应域名的证书。

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

#### 3. TLS 1.3 完整握手（推荐）

TLS 1.3 是最新版本，握手更快、更安全。使用 X25519 进行密钥交换。

支持标准套件（AES-128/256-GCM, ChaCha20, CCM）和 **RFC 8998 国密套件**（TLS_SM4_GCM_SM3 + SM2 签名）。国密套件用法：设置 `client.cipher_suite = CipherSuite::TLS_SM4_GCM_SM3`，服务端使用 SM2 证书自动协商。

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

// ═══════════════════════════════════════════════════════
// 握手完成！双向安全通信
// ═══════════════════════════════════════════════════════

// 客户端 → 服务端
auto client_record = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                  (const uint8_t*)"Hello, TLS 1.3!", 16);
ContentType ct; std::vector<uint8_t> plaintext;
tls_decrypt(server, client_record.data(), client_record.size(), ct, plaintext);
// plaintext 包含 "Hello, TLS 1.3!"

// 服务端 → 客户端（使用服务端专用 API）
auto server_record = tls_server_encrypt(server, ContentType::APPLICATION_DATA,
                                         (const uint8_t*)"Hi from server!", 15);
ContentType ct2; std::vector<uint8_t> resp;
tls_decrypt(client, server_record.data(), server_record.size(), ct2, resp);
// resp 包含 "Hi from server!"
```

#### 4. TLS 1.3 简化版握手（一次性）

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

#### 5. TLS 1.3 0-RTT（零往返）

0-RTT 允许客户端在握手完成前发送应用数据，基于前一次握手的 PSK（Pre-Shared Key）恢复会话。

```cpp
// ═══════════════════════════════════════════════════════
// 阶段 1: 完整握手 + 获取 NewSessionTicket
// ═══════════════════════════════════════════════════════

tls_session client, server;
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("example.com", std::move(server_cert));

// 完整 TLS 1.3 握手...
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

// 加密并发送给客户端...
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

#### 6. TLS 1.2 握手 (RFC 5246)

支持 **RSA** 和 **ECDHE**（X25519）两种密钥交换方式，完整的密码套件协商、ServerKeyExchange、Certificate、ServerHelloDone 消息流程。

**支持的密码套件：**

| 套件 | 密钥交换 | 加密 | 哈希 |
|------|---------|------|------|
| `0xC02C` | ECDHE-ECDSA | AES-256-GCM | SHA-384 |
| `0xC030` | ECDHE-RSA | AES-256-GCM | SHA-384 |
| `0xC02B` | ECDHE-ECDSA | AES-128-GCM | SHA-256 |
| `0xC02F` | ECDHE-RSA | AES-128-GCM | SHA-256 |
| `0xCCA9` | ECDHE-ECDSA | ChaCha20-Poly1305 | SHA-256 |
| `0xCCA8` | ECDHE-RSA | ChaCha20-Poly1305 | SHA-256 |
| `0x009C` | RSA | AES-128-GCM | SHA-256 |
| `0x009D` | RSA | AES-256-GCM | SHA-384 |

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

// Step 1: 客户端生成 ClientHello 并加密 pre-master secret
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
// decrypted_pms 应与 pre_master 一致

// ── 客户端：处理服务端回包，生成 Finished ──
std::vector<uint8_t> cf12;
tls12_process_server_flight(client, sh12.data(), sh12.size(),
                              pre_master, 48, cf12);

// ── 服务端：验证客户端 Finished ──
tls12_process_client_finished(server, cf12.data(), cf12.size());

// ═══════════════════════════════════════════════════════
// TLS 1.2 握手完成！安全通信
// ═══════════════════════════════════════════════════════

auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA,
                       (const uint8_t*)"TLS 1.2 data", 12);
ContentType t; std::vector<uint8_t> dec;
tls_decrypt(server, enc.data(), enc.size(), t, dec);
```

#### 7. 记录层加密/解密（握手完成后）

握手完成后，所有应用数据通过记录层加密传输。`tls_encrypt`/`tls_decrypt` 根据 `session.is_server` 自动选择正确的密钥方向。

```cpp
// ── 通用 API（双向） ──
std::vector<uint8_t> encrypted = tls_encrypt(
    session, ContentType::APPLICATION_DATA,
    plaintext_data, plaintext_len);
ContentType ct; std::vector<uint8_t> decrypted;
bool ok = tls_decrypt(session, encrypted.data(), encrypted.size(), ct, decrypted);

// ── 服务端专用 API（自文档化，显式方向） ──
// 服务端发送数据给客户端
auto server_record = tls_server_encrypt(server, ContentType::APPLICATION_DATA,
                                         (const uint8_t*)"response", 8);
// 客户端解密后...
// 服务端解密客户端发来的数据
ContentType sct; std::vector<uint8_t> from_client;
bool s_ok = tls_server_decrypt(server, client_record.data(),
                                client_record.size(), sct, from_client);
```

#### 8. TLS 握手 API 总览

| 函数 | 说明 |
|------|------|
| `tls13_make_client_hello(s, out)` | 客户端生成 ClientHello（含 SNI + X25519 key_share） |
| `tls13_make_server_flight(s, ch, len, out, cert_mgr)` | 服务端处理 ClientHello，生成完整回包（SH+EE+Cert+CV+SF） |
| `tls13_process_server_flight(s, data, len, out, cert_mgr)` | 客户端处理服务端回包，生成 Client Finished |
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
| `tls12_make_certificate(cert)` | 构造 TLS 1.2 Certificate 消息 |
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

#### 9. 证书管理 API

| 类/函数 | 说明 |
|---------|------|
| `tls_certificate` | 证书结构体，含公钥、私钥、签名算法 |
| `tls_certificate::sign(data, len, sig, sig_len)` | 使用证书私钥签名 |
| `tls_certificate::verify(data, len, sig, sig_len)` | 使用证书公钥验证签名 |
| `tls_certificate_manager::add_certificate(domain, cert)` | 添加域名对应的证书 |
| `tls_certificate_manager::get_certificate(domain)` | 根据域名获取证书（支持通配降级） |
| `tls_certificate_manager::get_default_certificate()` | 获取默认证书 |
| `tls_parse_server_name(extensions, len)` | 从扩展中解析 SNI 域名 |

#### 10. 会话状态

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

### Ed25519

```cpp
#include "ed25519.hpp"

uint8_t pub[32], priv[64];
ed25519_keygen(pub, priv);

uint8_t sig[64];
ed25519_sign(priv, (const uint8_t*)"message", 7, sig);

bool ok = ed25519_verify(pub, (const uint8_t*)"message", 7, sig);
```

### ECDSA P-256

```cpp
#include "ecdsa.hpp"

uint8_t pub[64], priv[32];
ecdsa_p256_keygen(pub, priv);

uint8_t sig[64];
ecdsa_p256_sign(priv, (const uint8_t*)"message", 7, sig);

bool ok = ecdsa_p256_verify(pub, (const uint8_t*)"message", 7, sig);
```

## GPU 持久化池

```cpp
// AES
auto* pool = musa_aes_pool_create(ctx, 64*1024*1024);
musa_aes_pool_encrypt_ecb(pool, input, output, num_blocks);

// ChaCha20
auto* cc = musa_chacha20_pool_create(key, nonce);
musa_chacha20_pool_xor(cc, input, output, num_blocks, 0);

// RSA (批量解密)
auto* rsa = musa_rsa_pool_create(prv, 1024);
musa_rsa_batch_decrypt(rsa, ciphers, plains, count);
```

## 性能 (MTT S80 + i7-13700K)

| 算法 | CPU | GPU | 加速比 |
|------|-----|-----|--------|
| AES-128 ECB (16MB) | 5.5 GB/s (AES-NI) | 2.5 GB/s | — |
| ChaCha20 (16MB) | 0.5 GB/s | 1.1 GB/s | 2.2x |
| RSA 2048 模幂 | 19 ms/op | 36 ms/op (batch) | — |
| RSA 4096 模幂 | 0.5 ms (e=65537) | — | — |

## 文件结构

```
jpssl/
├── include/
│   ├── aes.hpp                  AES
│   ├── chacha20_poly1305.hpp    ChaCha20-Poly1305
│   ├── cpu_features.hpp         CPU 特性检测
│   ├── rsa.hpp                  RSA 2048/4096
│   ├── sha256.hpp               SHA-256
│   ├── sha512.hpp               SHA-384/512
│   ├── sha3.hpp                 SHA3-256/384/512
│   ├── hmac.hpp                 HMAC-SHA256/SHA384/SM3
│   ├── hkdf.hpp                 HKDF-SHA256/SHA384/SM3
│   ├── x25519.hpp               X25519 ECDH
│   ├── ed25519.hpp              Ed25519 签名
│   ├── ecdsa.hpp                ECDSA P-256 签名
│   ├── sm2.hpp                  SM2 签名/验证/密钥交换
│   ├── sm3.hpp                  SM3 密码杂凑
│   ├── sm4.hpp                  SM4 分组密码
│   ├── sm4_gcm.hpp              SM4-GCM AEAD (含 AVX2/AVX512 自动分派)
│   ├── sm4_ccm.hpp              SM4-CCM AEAD
│   └── tls.hpp                  TLS 1.2/1.3 (含 RFC 8998 + ECDHE)
├── src/
│   ├── aes_cpu.cpp / aes_musa.cpp / aes_gpu.mu
│   ├── aes_gcm_avx2.cpp / aes_gcm_avx512.cpp / aes_gcm_auto.cpp
│   ├── chacha20_poly1305.cpp / chacha20_gpu.mu
│   ├── rsa.cpp / rsa_body.inc / rsa_musa.cpp / rsa_gpu.mu
│   ├── sha256.cpp / sha3.cpp
│   ├── hmac.cpp / hkdf.cpp
│   ├── sha512_cpu.cpp / sha512_opt.cpp / sha512_musa.cpp / sha512_gpu.mu
│   ├── x25519.cpp / ed25519.cpp / ecdsa.cpp
│   ├── sm2.cpp / sm3.cpp / sm4.cpp / sm4_gcm.cpp / sm4_ccm.cpp / sm4_gcm_dispatch.cpp
│   ├── tls.cpp (TLS 1.2 RFC 5246 + TLS 1.3 RFC 8446 + RFC 8998)
│   └── main.cpp
├── CMakeLists.txt
└── README.md
```

## 条件编译

可通过 CMake 选项控制硬件加速模块的编译：

| 选项 | 默认 | 说明 |
|------|------|------|
| `JP_ENABLE_AVX2` | ON | AVX2 GCM (4 路并行) + SHA-512 SIMD 消息调度 |
| `JP_ENABLE_AVX512` | ON | AVX512 VAES GCM (8 路并行) |

```bash
# 禁用所有 SIMD 加速（纯标量回退）
cmake -B build -DJP_ENABLE_AVX2=OFF -DJP_ENABLE_AVX512=OFF
```

## 依赖

- **C++20** (GCC 13+ / Clang 16+)
- **CMake** 3.20+
- **MUSA SDK** 4.3.0+ (GPU, 可选)
- **x86_64** (AES-NI / AVX2 / AVX512, 可选)