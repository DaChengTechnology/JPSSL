# jpssl — C++20 高性能密码学库（CPU + MUSA GPU）

跨平台密码学库，支持 **AES**、**ChaCha20-Poly1305**、**RSA**、**TLS 1.2/1.3**、**Ed25519**、**ECDSA**、**X.509 v3 证书**（RFC 5280），以及 **SM2/SM3/SM4 国密算法**（GM/T 0002/3/4-2012，RFC 8998 TLS 1.3 国密套件）。提供 CPU 优化（AES-NI/AVX2/Montgomery）和可选的 MUSA GPU 加速（实验性，默认关闭）。同时提供静态库和动态库两种构建方式。

## 架构

```
┌──────────────────────────────────────────────────┐
│    jpssl-cert (证书工具)    jpssl-crypt (加解密)  │
├──────────────────────────────────────────────────┤
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
│  ├─ sm3_win.asm           SM3 标量汇编 (MSVC x64)       │
│  ├─ sm4.cpp                SM4 分组密码            │
│  ├─ sm4_gcm.cpp            SM4-GCM AEAD 模式       │
│  ├─ hmac.cpp               HMAC-SHA256/SHA384/SM3   │
│  ├─ hkdf.cpp               HKDF-SHA256/SHA384/SM3   │
│  ├─ x509.cpp               X.509 v3 证书 DER 编解码  │
│  └─ tls.cpp                TLS 1.2/1.3 记录层+握手│
└──────────────────────────────────────────────────┘
```

## 性能基准 (benchmarks/)

可选编译开关 `JP_ENABLE_BENCH`（默认 OFF）：

```bash
cmake -DJP_ENABLE_BENCH=ON .. && make bench_rsa_cpu_gpu
```

`benchmarks/` 目录：

| 目标 | 内容 |
|---|---|
| `bench_rsa_cpu_gpu` | RSA CPU vs GPU vs OpenSSL 综合基准（2048/4096 私钥、2048 公钥） |
| `bench_rsa_gpu` | RSA-2048/4096 CPU 批量 vs MUSA GPU 批量（仅 `JP_ENABLE_MUSA=ON` 时构建） |
| `bench_sha512` | SHA-512 CPU vs SSE4.1 SIMD；GPU 单块/批量（仅 MUSA 构建） |
| `bench_hardware_accel` | AES / ChaCha20-Poly1305 / SHA-512 硬件加速路径对比（GPU 段仅 MUSA 构建） |
| `bench_cipher_suites` | TLS 密码套件性能 |
| `bench_sm4` | SM4 (ECB/GCM) vs OpenSSL |
| `bench_sm_ossl` | SM3 吞吐 + SM2 keygen/sign/verify vs OpenSSL |
| `bench_ed25519_ossl` | Ed25519 签名/验证 vs OpenSSL（仅找到 OpenSSL 时构建） |
| `bench_ed448_x448_ossl` | Ed448 / X448 vs OpenSSL（仅找到 OpenSSL 时构建） |
| `bench_x25519_ossl` | X25519 ECDH vs OpenSSL（仅找到 OpenSSL 时构建） |

> 所有 GPU 基准段（`bench_sha512` / `bench_hardware_accel` 中的 `musa_*` 调用、`bench_rsa_gpu` 目标）都由 `JP_MUSA` 宏守卫：`JP_ENABLE_MUSA=OFF`（默认）时自动跳过 GPU 段，基准程序仍可正常编译运行。

## 快速开始

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 或启用 MUSA GPU 加速 (实验性，需要 MUSA SDK 4.3.0+)
# cmake .. -DCMAKE_BUILD_TYPE=Release -DJP_ENABLE_MUSA=ON

# 运行主测试程序
LD_LIBRARY_PATH=/usr/local/musa/lib ./jpssl-test

# 运行全部单元测试（CTest, 目标定义在 tests/CMakeLists.txt）
LD_LIBRARY_PATH=/usr/local/musa/lib ctest --output-on-failure

# 安装到系统（可选，安装命令行工具 jpssl-cert / jpssl-crypt 到 bin/）
sudo make install
```

## Windows 构建（MSVC）

支持 Windows x64 + MSVC（VS 2019 16.10+ / VS 2022+ / Build Tools），通过 CMake + Ninja 或 VS 解决方案构建：

```powershell
# 在 "x64 Native Tools Command Prompt" 或 Developer PowerShell 中：
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
# 或直接生成 VS 工程
# cmake -S . -B build-win -G "Visual Studio 17 2022" -A x64

# 运行测试
ctest --test-dir build-win --output-on-failure
```

平台适配说明：

- **128 位整数**：MSVC 不提供 GCC 的 `__uint128_t`，Windows 构建通过 `/FI` 强制包含 `include/jpssl_platform.hpp` 提供等价的 `jp_uint128` 兼容层（基于 `_umul128`/`_addcarry_u64`/`_udiv128`，全部内联）。**不要求**业务代码改动；GCC/Clang 仍使用原生类型。
- **随机数**：统一走 `include/rand_os.hpp`（`jpssl::os_rand_bytes`）——Windows 用 `BCryptGenRandom`，Linux 用 `/dev/urandom`。MSVC 的 `std::random_device` 是确定性的，不用于密钥/签名 nonce。
- **CPU 特性检测**：`include/cpu_features.hpp` 在 MSVC 下改用 `__cpuidex`/`_xgetbv` 运行时检测 AES-NI/AVX2/AVX512/SHA-NI，硬件加速分派在 Windows 上同样生效。
- **RSA Montgomery 汇编加速**：RSA-2048/4096 的 CIOS Montgomery 乘法在 Windows 走手写 MASM 汇编（`src/rsa_mont_asm_win.asm`，MULX 加速，K=32/64），Linux 走 GCC 内联汇编（`src/rsa_mont_asm.cpp`）。运行时不支持 BMI2/ADX 的 CPU 自动回退到标量 `_umul128` 实现；CPUID 检测结果进程内缓存。
- **CRT 半尺寸汇编加速**：CRT 私钥解密的 p/q 模幂使用半尺寸 Montgomery 乘法 `mont_mul_half_`（只处理前 K/2 个 limb），同样接入汇编快速路径（`mont_mul_half_asm`，HK=16/32，MASM 宏生成双实例 + GCC 动态 HK 单实例），核心吞吐提升约 1.3–1.45×。
- **CRT 解密默认双线程 OpenMP**：`rsa_decrypt`/`rsa_crt_decrypt`（dec_fn + RSADP/RSADP4096）的两路独立模幂 m1/m2 用 `#pragma omp parallel sections num_threads(2)` 并行（`-DJP_ENABLE_OPENMP=OFF` 或非 OpenMP 编译器自动回退串行），2048/4096 解密实测提速 1.5–1.7×；RSADP 与 dec_fn 统一走半尺寸路径。
- **RSA keygen 素数预算兜底**：素数搜索预算 100ms（`rsa_keygen`/`rsa_keygen_crt` 及其 4096 版本统一），超时即从预制素数表（`src/rsa_prebuilt_primes_data.inc`，1024 位×50 对 + 2048 位×50 对，MR 已验证）随机取一组完成 keygen，保证 keygen 永不因素数搜索卡死。预制素数公开、仅作测试/兜底，不用于生产密钥。注：构建规则为 unscanned，`.inc` 通过 `OBJECT_DEPENDS` 显式跟踪，改动后自动触发 `rsa.cpp` 重编。
- **MUSA GPU 加速**：仅支持 Linux，Windows 上 `-DJP_ENABLE_MUSA=ON` 会被自动禁用并提示。
- **OpenSSL**：仅测试/基准的对比需要；未安装时相关对比测试自动跳过，库本身不依赖。
- **产物命名**：Windows 下静态库为 `jpssl_cpu_static.lib`（共享库导入库占用 `jpssl_cpu.lib`），动态库为 `jpssl_cpu.dll`。
- 动态库通过 `WINDOWS_EXPORT_ALL_SYMBOLS` 导出全部公共符号，无需手写 `__declspec(dllexport)`。

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

## 命令行工具

构建后生成两个命令行工具，`make install` 后安装到 `bin/` 目录：

| 工具 | 说明 | 源文件 |
|------|------|--------|
| `jpssl-cert` | X.509 v3 证书生成 / 查看 / 验证 | `src/cmd/jpssl_cert.cpp` |
| `jpssl-crypt` | 加密 / 解密 / 哈希 / HMAC | `src/cmd/jpssl_crypt.cpp` |

### jpssl-cert — 证书工具

```bash
# 生成自签名 X.509 v3 证书 + 私钥
jpssl-cert gen --cn example.com --key-type ed25519 --out cert.der --key-out key.bin
# 支持的密钥类型: ed25519 | ecdsa | sm2 | rsa2048 | ed448

# 查看证书信息
jpssl-cert info --cert cert.der

# 验证证书链 (leaf → root)
jpssl-cert verify --cert leaf.der --ca root.der
# 多级链: --ca 可多次指定中间 CA
jpssl-cert verify --cert leaf.der --ca intermediate.der --ca root.der

# 通过 TLS API 生成证书 (等价于 tls_make_x509_self_signed)
jpssl-cert tlsgen --cn example.com --key-type ecdsa --out cert.der --key-out key.bin
```

### jpssl-crypt — 加密/哈希工具

```bash
# AES-256-GCM 加密 (输出格式: IV || 密文 || Tag)
jpssl-crypt encrypt --algo aes256gcm --key <hex-key> --in plain.txt --out cipher.bin

# ChaCha20-Poly1305 加密
jpssl-crypt encrypt --algo chacha20 --key <hex-key> --in plain.txt --out cipher.bin

# 解密 (自动从文件提取 IV 和 Tag)
jpssl-crypt decrypt --algo aes256gcm --key <hex-key> --in cipher.bin --out plain.txt

# 哈希
jpssl-crypt hash --algo sha256 --in file.txt
jpssl-crypt hash --algo sm3   --in file.txt     # 国密 SM3

# HMAC
jpssl-crypt hmac --algo sha256 --key <hex-key> --in file.txt

# 生成随机字节 (十六进制输出)
jpssl-crypt rand 32
```

支持的算法：
- **加密**: `aes256gcm`（AES-256-GCM AEAD）、`chacha20`（ChaCha20-Poly1305 AEAD）
- **哈希**: `sha256`、`sha512`、`sha3-256`、`sha3-512`、`sm3`
- **HMAC**: `sha256`、`sha384`、`sm3`

密钥、IV、Tag 均以十六进制字符串传入，AAD 认证数据可用 `--aad <hex>` 指定。

## 算法总览

| 算法 | 模式 | CPU 加速 | GPU 加速 |
|------|------|----------|----------|
| **AES-128/256** | ECB, CBC+PKCS7, GCM | AES-NI (~5 GB/s), AVX2/AVX512 GCM | ECB kernel (实验性) |
| **ChaCha20-Poly1305** | 流加密, AEAD | — | Keystream kernel (实验性) |
| **RSA 2048/4096** | PKCS#1 v1.5 | Montgomery CIOS | 批量模幂 (实验性) |
| **SHA-256** | 哈希 | — | — |
| **SHA-384/512** | 哈希 (FIPS 180-4) | SSE4.1 消息调度 | GPU kernel (实验性) |
| **SHA3-256/384/512** | 哈希 (FIPS 202, Keccak) | — | — |
| **HMAC-SHA256/SHA384/SM3** | MAC | — | — |
| **HKDF-SHA256/SHA384/SM3** | TLS 1.3 密钥派生 | — | — |
| **X25519** | ECDH 密钥交换 | — | — |
| **Ed25519** | 数字签名 (EdDSA) | — | — |
| **ECDSA P-256** | 数字签名 (secp256r1) | — | — |
| **X.509 v3** | 证书 DER 编解码 (RFC 5280), 自签名/证书链, SAN/KeyUsage/BasicConstraints | — | — |
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

证书是 TLS 握手的关键组件，包含公钥、私钥和签名算法。jpssl 集成了 **X.509 v3**（RFC 5280）证书编码：当 `cert_data` 为空时，握手过程会自动调用 `tls_make_x509_self_signed()` 生成标准的 X.509 v3 DER 自签名证书（含 SAN、KeyUsage、EKU 扩展）。也可以手动调用 `tls_make_x509_self_signed()` 预生成并填入 `cert_data`。

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

// ── SM2 证书（RFC 8998 国密 TLS） ──
auto sm2_cert = std::make_unique<tls_certificate>();
sm2_cert->subject_name = "example.cn";
sm2_cert->sig_alg = SignatureAlgorithm::SM2_SM3;
sm2_keygen(sm2_cert->pub.sm2, sm2_cert->priv.sm2);
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

### X.509 v3 证书 (RFC 5280)

`x509.hpp` 提供完整的 X.509 v3 证书 DER 编解码、自签名证书生成和证书链验证。支持 RSA-2048/4096、Ed25519、Ed448、ECDSA P-256、SM2 五种密钥类型。

```cpp
#include "x509.hpp"
using namespace jpssl::x509;
```

#### 1. 生成自签名证书

```cpp
// 生成 Ed25519 密钥
uint8_t pub[32], priv[64];
ed25519_keygen(pub, priv);

// 构建并签名自签名证书
x509_builder builder;
DistinguishedName dn;
dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + 3), "example.com"});
builder.set_subject(dn).set_issuer(dn);                    // 自签名: subject == issuer

uint8_t serial[8] = {0x01, 0x02, 0x03, 0x04};
builder.set_serial(serial, 8);

uint64_t now = (uint64_t)time(nullptr);
builder.set_validity(now, now + 365ULL * 86400);           // 有效期 365 天

builder.set_key(KeyType::Ed25519, pub, 32);                // 公钥
builder.set_ca(false);                                     // 叶子证书 (CA=false)
builder.set_key_usage(KU_DIGITAL_SIGNATURE);               // KeyUsage 扩展
builder.set_server_auth();                                 // EKU: serverAuth
builder.add_san_dns("example.com");                        // SAN: DNS 名称
builder.add_san_dns("www.example.com");

auto cert = builder.build_and_sign(KeyType::Ed25519, priv, 64); // 私钥签名

// 编码为 DER 字节
std::vector<uint8_t> der = cert.to_der();
```

#### 2. 解析 DER 证书

```cpp
// 从 DER 字节解析
auto parsed = x509_cert::from_der(der);
if (parsed) {
    std::string cn = parsed->common_name();        // 获取 subject CN
    std::string issuer = parsed->issuer_name();    // 获取 issuer CN
    bool is_ca = parsed->is_ca();                  // 是否 CA 证书
    bool valid = parsed->is_valid_now();           // 是否在有效期内
    auto dns = parsed->dns_names();                // SAN DNS 名称列表
    KeyType kt = parsed->key_type;                 // 密钥类型
}
```

#### 3. 证书链验证

```cpp
// 构建根 CA（自签名, CA=true, KeyCertSign）
x509_builder root_builder;
root_builder.set_ca(true, 0);                                // pathLen=0
root_builder.set_key_usage(KU_KEY_CERT_SIGN);
auto root = root_builder.build_and_sign(KeyType::Ed25519, root_priv, 64);

// 叶子证书由根 CA 签发（issuer=root, 用根私钥签名）
x509_builder leaf_builder;
leaf_builder.set_issuer(root_dn);
auto leaf = leaf_builder.build_and_sign(KeyType::Ed25519, root_priv, 64);

// 验证证书链: leaf → root
std::vector<x509_cert> chain = {leaf, root};
auto result = x509_verify_chain(chain, now);
if (result.success) {
    // 链有效: 签名正确、有效期未过期、根证书是 CA
} else {
    std::string err = result.error;   // 失败原因
}
```

#### 4. TLS 集成

```cpp
#include "tls.hpp"
using namespace jpssl::tls;

// 从 tls_certificate 生成 X.509 DER 自签名证书
std::vector<uint8_t> der = tls_make_x509_self_signed(*tls_cert);

// 密钥类型映射
x509::KeyType kt = tls_sig_alg_to_key_type(cert->sig_alg);
```

TLS 握手时若 `tls_certificate::cert_data` 为空，会自动生成 X.509 v3 DER 证书并发送给对端（`tls13_make_certificate` / `tls12_make_certificate` 均支持）。

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
│   ├── x509.hpp                 X.509 v3 证书 (RFC 5280)
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
│   ├── x509.cpp                 X.509 v3 DER 编解码/自签名/证书链验证
│   ├── tls.cpp (TLS 1.2 RFC 5246 + TLS 1.3 RFC 8446 + RFC 8998)
│   ├── cmd/
│   │   ├── jpssl_cert.cpp       X.509 证书命令行工具
│   │   └── jpssl_crypt.cpp      加解密/哈希命令行工具
│   └── main.cpp
├── tests/
│   ├── CMakeLists.txt           独立测试构建 (add_subdirectory(tests))
│   ├── test_x509.cpp            X.509 v3 证书单元测试
│   └── ...                      其余单元测试与 benchmark
├── CMakeLists.txt
└── README.md
```

## 条件编译

可通过 CMake 选项控制硬件加速模块的编译：

| 选项 | 默认 | 说明 |
|------|------|------|
| `JP_ENABLE_MUSA` | **OFF** | MUSA GPU 加速 (实验性) |
| `JP_ENABLE_BENCH` | **OFF** | 构建 benchmarks/ 基准程序 |
| `JP_ENABLE_OPENMP` | ON | OpenMP 并行（CPU 批量 RSA） |
| `JP_ENABLE_AVX2` | ON | AVX2 GCM (4 路并行) + SHA-512 SIMD 消息调度 |
| `JP_ENABLE_AVX512` | ON | AVX512 VAES GCM (8 路并行) |

```bash
# 启用 MUSA GPU 加速 (需要 MUSA SDK 4.3.0+)
cmake -B build -DJP_ENABLE_MUSA=ON

# 禁用所有 SIMD 加速（纯标量回退）
cmake -B build -DJP_ENABLE_AVX2=OFF -DJP_ENABLE_AVX512=OFF
```

## 依赖

- **C++20** (GCC 13+ / Clang 16+)
- **CMake** 3.20+
- **OpenSSL** (仅部分测试目标需要，用于与 OpenSSL 结果对比)
- **MUSA SDK** 4.3.0+ (可选，实验性 GPU 加速，默认关闭，通过 `-DJP_ENABLE_MUSA=ON` 启用)
- **x86_64** (AES-NI / AVX2 / AVX512, 可选)
