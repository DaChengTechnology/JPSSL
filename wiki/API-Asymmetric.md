# 非对称加密 API

## RSA 2048 / 4096（[PKCS#1 v2.2 / RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)）

头文件：`include/rsa.hpp`

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

支持的填充方案（`include/rsa.hpp` 相关函数）：

- PKCS#1 v1.5（RSA 加密 / 签名，`rsa_schemes.cpp`）
- OAEP（[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)，`rsa_oaep.cpp`）
- PSS（[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)，`rsa_pss.cpp`）

性能特性：

- **Montgomery CIOS** 乘法，Windows 走 MASM MULX 汇编（`rsa_mont_asm_win.asm`），Linux 走 GCC 内联汇编（`rsa_mont_asm.cpp`）；CPU 不支持 BMI2/ADX 时自动回退标量。
- **CRT 半尺寸汇编**：私钥解密 p/q 模幂使用半尺寸 Montgomery 乘法（`mont_mul_half_asm`），核心吞吐提升约 1.3–1.45×。
- **CRT 私钥签名**：PKCS#1 完整私钥解析自动携带 CRT 参数（p/q/dP/dQ/qInv），`rsa_pkcs1_sign` 优先 RSASP1 两路半宽模幂（RSA-2048 私钥签名 2186ms → 3ms、PSS 2436ms → 1ms）；仅含 n/d/e 的私钥自动回退全模幂。
- **OpenMP 双线程**：`rsa_decrypt` / `rsa_crt_decrypt` 的两路独立模幂 m1/m2 用 `#pragma omp parallel sections num_threads(2)` 并行（2048/4096 解密实测提速 1.5–1.7×）；`-DJP_ENABLE_OPENMP=OFF` 时自动回退串行。
- **批量模幂**：AVX2 / AVX-512 批量 Montgomery（`rsa_batch_dispatch.cpp`），用于服务器批量解密场景。
- **keygen 素数预算兜底**：素数搜索预算 100ms，超时后从预制素数表（1024 位 ×50 对 + 2048 位 ×50 对，MR 已验证）随机取一组完成 keygen，保证永不卡死。预制素数公开、仅作测试/兜底，不用于生产密钥。

## ECDSA P-256（[FIPS 186-4](https://csrc.nist.gov/pubs/fips/186-4/final)）

头文件：`include/ecdsa.hpp`

```cpp
#include "ecdsa.hpp"

uint8_t pub[64], priv[32];
ecdsa_p256_keygen(pub, priv);

uint8_t sig[64];
ecdsa_p256_sign(priv, (const uint8_t*)"message", 7, sig);

bool ok = ecdsa_p256_verify(pub, (const uint8_t*)"message", 7, sig);
```

曲线：[secp256r1](https://www.secg.org/sec2-v2.pdf)（P-256，NIST 曲线）。

## Ed25519（[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)）

头文件：`include/ed25519.hpp`（批量验签：`include/ed25519_batch.hpp`）

```cpp
#include "ed25519.hpp"

uint8_t pub[32], priv[64];
ed25519_keygen(pub, priv);

uint8_t sig[64];
ed25519_sign(priv, (const uint8_t*)"message", 7, sig);

bool ok = ed25519_verify(pub, (const uint8_t*)"message", 7, sig);
```

加速：AVX-512（`ed25519_avx512.cpp`）、Radix-51 表示（`ed25519_r51.cpp`）、批量验签（`ed25519_batch_dispatch.cpp`）。

## Ed448（[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)）

头文件：`include/ed448.hpp`（批量验签：`include/ed448_batch.hpp`）

```cpp
#include "ed448.hpp"

uint8_t pub[57], priv[114];
ed448_generate_keypair(pub, priv);   // priv = seed(57) || pub(57)

uint8_t sig[114];
ed448_sign(priv, (const uint8_t*)"message", 7, sig);

bool ok = ed448_verify(pub, (const uint8_t*)"message", 7, sig);
```

加速：AVX2 / AVX-512（`ed448_avx2.cpp` / `ed448_avx512.cpp`）、批量验签（`ed448_batch_dispatch.cpp`）。

## X25519（[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)）

头文件：`include/x25519.hpp`

```cpp
#include "x25519.hpp"

uint8_t alice_pub[32], alice_priv[32];
uint8_t bob_pub[32], bob_priv[32];
x25519_generate_keypair(alice_pub, alice_priv);
x25519_generate_keypair(bob_pub, bob_priv);

uint8_t shared[32];
x25519_scalar_mult(shared, alice_priv, bob_pub);
```

加速：AVX-512（`x25519_avx512.cpp`）。

## X448（[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)）

头文件：`include/x448.hpp`

```cpp
#include "x448.hpp"

uint8_t pub[56], priv[56];
x448_generate_keypair(pub, priv);

uint8_t shared[56];
x448_scalar_mult(shared, priv, peer_pub);
```

加速：AVX2 / AVX-512（`x448_avx2.cpp` / `x448_avx512.cpp`），批量（`test_x448_batch`）。

## SM2（[GM/T 0003-2012](https://www.oscca.gov.cn/)，[RFC 8998 国密 TLS](https://www.rfc-editor.org/rfc/rfc8998)）

头文件：`include/sm2.hpp`

```cpp
#include "sm2.hpp"

uint8_t pub[64], priv[32];
sm2_keygen(pub, priv);

uint8_t sig[64];
sm2_sign(priv, (const uint8_t*)"message", 7, sig);
bool ok = sm2_verify(pub, (const uint8_t*)"message", 7, sig);

// 从私钥派生公钥
sm2_pub_from_priv(priv, pub);

// 计算用户标识杂凑值 ZA（默认 ID "1234567812345678"）
uint8_t za[32];
sm2_compute_za((const uint8_t*)"1234567812345678", 16, pub, pub+32, za);
```

曲线：sm2p256v1。性能特性：

- 域运算 Montgomery（CIOS）+ wNAF-5 标量乘 + Shamir 双标量乘 + 批量仿射化
- keygen / sign / verify 相对旧实现提速 84× / 83× / 135×，对 OpenSSL 4.0 反超 1.31× / 1.35× / 1.26×
- 支持 OpenSSL 双向签名互操作验证（`bench_sm_ossl` / `test_sm`）

## 密钥与签名互操作

库提供与 OpenSSL 的交叉验证测试（安装 OpenSSL 后自动启用）：RSA、ECDSA、Ed25519、Ed448、X25519、X448、SM2、SM3、SM4、SHA-3、GCM 等均有对应对比测试（见 [测试与 CI](Testing)）。
