# jpssl — C++20 高性能密码学库（CPU + MUSA GPU）

跨平台密码学库，支持 **AES**、**ChaCha20-Poly1305**、**RSA**、**TLS 1.2/1.3**、**Ed25519**、**ECDSA**，提供 CPU 优化（AES-NI/AVX2/Montgomery）和 MUSA GPU 加速。同时提供静态库和动态库两种构建方式。

## 架构

```
┌──────────────────────────────────────────────────┐
│              jpssl-test (测试)                    │
├──────────────────────────────────────────────────┤
│  libjpssl_musa (MUSA GPU 加速)                    │
│  ├─ aes_gpu.mu        AES ECB kernel             │
│  ├─ chacha20_gpu.mu   ChaCha20 keystream kernel   │
│  ├─ rsa_gpu.mu        RSA 批量模幂 kernel         │
│  ├─ aes_musa.cpp      主机端封装                  │
│  └─ rsa_musa.cpp      RSA GPU 封装               │
├──────────────────────────────────────────────────┤
│  libjpssl_cpu (纯 CPU)                           │
│  ├─ aes_cpu.cpp            AES + AES-NI          │
│  ├─ chacha20_poly1305.cpp  ChaCha20-Poly1305 AEAD │
│  ├─ rsa.cpp (+body.inc)    RSA 2048/4096 Montgomery│
│  ├─ sha256.cpp             SHA-256 哈希           │
│  ├─ sha3.cpp               SHA3-256/384/512 哈希   │
│  ├─ hmac.cpp               HMAC-SHA256            │
│  ├─ hkdf.cpp               HKDF-SHA256            │
│  ├─ x25519.cpp             X25519 ECDH            │
│  ├─ ed25519.cpp            Ed25519 签名/验证      │
│  ├─ ecdsa.cpp              ECDSA P-256 签名/验证  │
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
| **AES-128/256** | ECB, CBC+PKCS7, GCM | AES-NI (~5 GB/s) | ECB kernel |
| **ChaCha20-Poly1305** | 流加密, AEAD | — | Keystream kernel |
| **RSA 2048/4096** | PKCS#1 v1.5 | Montgomery CIOS | 批量模幂 |
| **SHA-256** | 哈希 | — | — |
| **SHA3-256/384/512** | 哈希 (FIPS 202, Keccak) | — | — |
| **HMAC-SHA256** | MAC | — | — |
| **HKDF-SHA256** | TLS 1.3 密钥派生 | — | — |
| **X25519** | ECDH 密钥交换 | — | — |
| **Ed25519** | 数字签名 (EdDSA) | — | — |
| **ECDSA P-256** | 数字签名 (secp256r1) | — | — |
| **TLS 1.2/1.3** | AES-128-GCM 记录层 | — | — |

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

### SHA256 / SHA3 / HMAC / HKDF

```cpp
#include "sha256.hpp"
sha256_ctx ctx; sha256_init(&ctx);
sha256_update(&ctx, data, len);
uint8_t digest[32]; sha256_final(&ctx, digest);

#include "sha3.hpp"
sha3_ctx ctx;
sha3_256_init(&ctx);  // or sha3_384_init / sha3_512_init
sha3_update(&ctx, data, len);
uint8_t hash[64]; sha3_final(&ctx, hash);

#include "hmac.hpp"
uint8_t mac[32]; hmac_sha256(key,32, msg,len, mac);

#include "hkdf.hpp"
uint8_t prk[32]; hkdf_extract(salt,16, ikm,32, prk);
uint8_t okm[64]; hkdf_expand(prk, info,8, okm,64);
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

TLS 模块提供完整的 TLS 1.2 和 TLS 1.3 握手流程、记录层加解密、SNI 多域名证书管理。
支持 Ed25519、ECDSA P-256、RSA-2048/4096 等多种证书签名算法。

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
// 握手完成！现在可以安全通信
// ═══════════════════════════════════════════════════════

// 客户端发送加密数据
auto record = tls_encrypt(client, ContentType::APPLICATION_DATA,
                          (const uint8_t*)"Hello, TLS 1.3!", 16);

// 服务端解密
ContentType ct; std::vector<uint8_t> plaintext;
tls_decrypt(server, record.data(), record.size(), ct, plaintext);
// plaintext 包含 "Hello, TLS 1.3!"
```

#### 4. TLS 1.3 简化版握手（一次性）

适合不需要分步处理握手消息的场景。

```cpp
tls_session client, server;
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("localhost", std::move(cert));

// 客户端生成 ClientHello 并处理服务端回包
std::vector<uint8_t> ch;
tls13_handshake_client(client, ch, server_flight.data(), server_flight.size());

// 服务端处理 ClientHello 并生成回包
std::vector<uint8_t> sh;
tls13_handshake_server(server, ch.data(), ch.size(), sh, cert_mgr);

// 安全通信
auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA,
                       (const uint8_t*)"data", 4);
ContentType t; std::vector<uint8_t> dec;
tls_decrypt(server, enc.data(), enc.size(), t, dec);
```

#### 5. TLS 1.2 握手

TLS 1.2 使用 pre-master secret 进行密钥派生，支持多种密码套件。

```cpp
// ── 服务端：准备证书 ──
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("example.com", std::move(server_cert));

// ── 客户端：发起握手 ──
tls_session client;
client.server_name = "example.com";

// Step 1: 客户端生成 ClientHello
std::vector<uint8_t> ch12;
tls12_make_client_hello(client, ch12);

// ── 服务端：处理 ClientHello，生成回包 ──
tls_session server;
uint8_t pre_master[48];
std::vector<uint8_t> sh12;
tls12_make_server_flight(server, ch12.data(), ch12.size(), sh12, pre_master, cert_mgr);

// ── 客户端：处理服务端回包，生成 Finished ──
std::vector<uint8_t> cf12;
tls12_process_server_flight(client, sh12.data(), sh12.size(), pre_master, 48, cf12);

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

#### 6. 记录层加密/解密（握手完成后）

握手完成后，所有应用数据通过记录层加密传输。

```cpp
// 加密：ContentType 可以是 APPLICATION_DATA、ALERT 等
std::vector<uint8_t> encrypted = tls_encrypt(
    session, ContentType::APPLICATION_DATA,
    plaintext_data, plaintext_len);

// 解密：同时返回内容类型
ContentType content_type;
std::vector<uint8_t> decrypted;
bool ok = tls_decrypt(session, encrypted.data(), encrypted.size(),
                      content_type, decrypted);

if (ok && content_type == ContentType::APPLICATION_DATA) {
    // 处理解密后的应用数据
}
```

#### 7. TLS 握手 API 总览

| 函数 | 说明 |
|------|------|
| `tls13_make_client_hello(s, out)` | 客户端生成 ClientHello（含 SNI + X25519 key_share） |
| `tls13_make_server_flight(s, ch, len, out, cert_mgr)` | 服务端处理 ClientHello，生成完整回包（SH+EE+Cert+CV+SF） |
| `tls13_process_server_flight(s, data, len, out, cert_mgr)` | 客户端处理服务端回包，生成 Client Finished |
| `tls13_process_client_finished(s, data, len)` | 服务端验证客户端 Finished |
| `tls13_handshake_client(s, ch, resp, len)` | 简化版客户端握手（一次性） |
| `tls13_handshake_server(s, ch, len, out, cert_mgr)` | 简化版服务端握手（一次性） |
| `tls12_make_client_hello(s, out)` | 客户端生成 TLS 1.2 ClientHello |
| `tls12_make_server_flight(s, ch, len, out, pms, cert_mgr)` | 服务端处理 ClientHello，生成回包 + pre-master |
| `tls12_process_server_flight(s, resp, len, pms, pms_len, out)` | 客户端处理回包，生成 Finished |
| `tls12_process_client_finished(s, data, len)` | 服务端验证客户端 Finished |
| `tls_encrypt(s, ct, data, len)` | 记录层加密 |
| `tls_decrypt(s, record, len, ct, out)` | 记录层解密 |
| `tls_encrypt_handshake(s, hs_msg, len)` | 加密握手消息（TLS 1.3 内部） |

#### 8. 证书管理 API

| 类/函数 | 说明 |
|---------|------|
| `tls_certificate` | 证书结构体，含公钥、私钥、签名算法 |
| `tls_certificate::sign(data, len, sig, sig_len)` | 使用证书私钥签名 |
| `tls_certificate::verify(data, len, sig, sig_len)` | 使用证书公钥验证签名 |
| `tls_certificate_manager::add_certificate(domain, cert)` | 添加域名对应的证书 |
| `tls_certificate_manager::get_certificate(domain)` | 根据域名获取证书（支持通配降级） |
| `tls_certificate_manager::get_default_certificate()` | 获取默认证书 |
| `tls_parse_server_name(extensions, len)` | 从扩展中解析 SNI 域名 |

#### 9. 会话状态

| 字段 | 说明 |
|------|------|
| `tls_session::ver` | TLS 版本（V12 / V13） |
| `tls_session::server_name` | SNI 客户端请求的域名 |
| `tls_session::client_random` / `server_random` | 32 字节随机数 |
| `tls_session::handshake_secret` / `master_secret` | 握手机密 / 主密钥（32 字节） |
| `tls_session::client_write_key` / `server_write_key` | 记录层加密密钥（32 字节） |
| `tls_session::client_write_iv` / `server_write_iv` | 记录层加密 IV（12 字节） |
| `tls_session::client_seq` / `server_seq` | 记录层序列号（防重放） |
| `tls_session::is_server` | 是否为服务端会话 |
| `tls_session::transcript_hash` | 握手 transcript 哈希（32 字节） |

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
│   ├── sha3.hpp                 SHA3-256/384/512
│   ├── hmac.hpp                 HMAC-SHA256
│   ├── hkdf.hpp                 HKDF-SHA256
│   ├── x25519.hpp               X25519 ECDH
│   ├── ed25519.hpp              Ed25519 签名
│   ├── ecdsa.hpp                ECDSA P-256 签名
│   └── tls.hpp                  TLS 1.2/1.3
├── src/
│   ├── aes_cpu.cpp / aes_musa.cpp / aes_gpu.mu
│   ├── chacha20_poly1305.cpp / chacha20_gpu.mu
│   ├── rsa.cpp / rsa_body.inc / rsa_musa.cpp / rsa_gpu.mu
│   ├── sha256.cpp / sha3.cpp / hmac.cpp / hkdf.cpp
│   ├── x25519.cpp / ed25519.cpp / ecdsa.cpp
│   ├── tls.cpp / main.cpp
│   └── main.cpp
├── CMakeLists.txt
└── README.md
```

## 依赖

- **C++20** (GCC 13+ / Clang 16+)
- **CMake** 3.20+
- **MUSA SDK** 4.3.0+ (GPU, 可选)
- **x86_64** (AES-NI / AVX2, 可选)