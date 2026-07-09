# jpssl — C++20 高性能密码学库（CPU + MUSA GPU）

跨平台密码学库，支持 **AES**、**ChaCha20-Poly1305**、**RSA**、**TLS 1.3**，提供 CPU 优化（AES-NI/AVX2/Montgomery）和 MUSA GPU 加速。

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
│  ├─ hmac.cpp               HMAC-SHA256            │
│  ├─ hkdf.cpp               HKDF-SHA256            │
│  ├─ x25519.cpp             X25519 ECDH            │
│  └─ tls.cpp                TLS 1.3 记录层+握手    │
└──────────────────────────────────────────────────┘
```

## 快速开始

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
LD_LIBRARY_PATH=/usr/local/musa/lib ./jpssl-test
```

## 算法总览

| 算法 | 模式 | CPU 加速 | GPU 加速 |
|------|------|----------|----------|
| **AES-128/256** | ECB, CBC+PKCS7, GCM | AES-NI (~5 GB/s) | ECB kernel |
| **ChaCha20-Poly1305** | 流加密, AEAD | — | Keystream kernel |
| **RSA 2048/4096** | PKCS#1 v1.5 | Montgomery CIOS | 批量模幂 |
| **SHA-256** | 哈希 | — | — |
| **HMAC-SHA256** | MAC | — | — |
| **HKDF-SHA256** | TLS 1.3 密钥派生 | — | — |
| **X25519** | ECDH 密钥交换 | — | — |
| **TLS 1.3** | AES-128-GCM 记录层 | — | — |

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

### SHA256 / HMAC / HKDF

```cpp
#include "sha256.hpp"
sha256_ctx ctx; sha256_init(&ctx);
sha256_update(&ctx, data, len);
uint8_t digest[32]; sha256_final(&ctx, digest);

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

### TLS 1.3

```cpp
#include "tls.hpp"
using namespace jpssl::tls;

tls_session client, server;
std::vector<uint8_t> ch, sh;
tls13_handshake_client(client, ch, sh.data(), sh.size());
tls13_handshake_server(server, ch.data(), ch.size(), sh);

auto record = tls_encrypt(client, ContentType::APPLICATION_DATA,
                          (const uint8_t*)"hello", 5);
ContentType ct; std::vector<uint8_t> data;
tls_decrypt(server, record.data(), record.size(), ct, data);
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
│   ├── cpu_features.hpp        CPU 特性检测
│   ├── rsa.hpp                 RSA 2048/4096
│   ├── sha256.hpp              SHA-256
│   ├── hmac.hpp                HMAC-SHA256
│   ├── hkdf.hpp                HKDF-SHA256
│   ├── x25519.hpp              X25519 ECDH
│   └── tls.hpp                 TLS 1.3
├── src/
│   ├── aes_cpu.cpp / aes_musa.cpp / aes_gpu.mu
│   ├── chacha20_poly1305.cpp / chacha20_gpu.mu
│   ├── rsa.cpp / rsa_body.inc / rsa_musa.cpp / rsa_gpu.mu
│   ├── sha256.cpp / hmac.cpp / hkdf.cpp
│   ├── x25519.cpp / tls.cpp
│   └── main.cpp
├── CMakeLists.txt
└── README.md
```

## 依赖

- **C++20** (GCC 13+ / Clang 16+)
- **CMake** 3.20+
- **MUSA SDK** 4.3.0+ (GPU, 可选)
- **x86_64** (AES-NI / AVX2, 可选)
