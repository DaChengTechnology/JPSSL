# Changelog

## [0.9.2] — 2026-08-01

### Added

#### ChaCha20 AVX2/AVX512 硬件加速
- 新增 `src/chacha20_avx2.cpp`（181 行）与 `src/chacha20_avx512.cpp`（134 行）：ChaCha20 keystream 的 AVX2/AVX512 并行路径
- `src/chacha20_poly1305.cpp` 与 `include/chacha20_poly1305.hpp` 增加硬件加速分派入口，`CMakeLists.txt` 增加对应编译目标

#### RSA 填充方案与原语
- 新增 `src/rsa_oaep.cpp`（156 行）：RSA-OAEP 加密填充
- 新增 `src/rsa_pss.cpp`（160 行）：RSA-PSS 签名填充
- 新增 `src/rsa_schemes.cpp`（131 行）与 `src/rsa_prim.cpp`（327 行）：RSA 方案层与底层模幂/素数原语
- `include/rsa.hpp`、`src/rsa_body.inc` 相应扩展公开 API

#### RSA 基准测试
- 新增 `benchmarks/bench_rsa_cpu_gpu.cpp`（320 行）：RSA 2048/4096 CPU vs GPU vs OpenSSL 综合基准
- 新增 `benchmarks/bench_rsa_gpu.cpp`（280 行）：RSA GPU 批量基准
- benchmark 目标从 `tests/` 迁移至独立 `benchmarks/` 目录，新增 `benchmarks/CMakeLists.txt`（60 行）

### Changed

#### Ed25519 / X25519 重构与优化
- Ed25519 域运算重构为 radix-51 表示：新增 `src/fe_25519_r51.hpp`（368 行）、`src/ed25519_r51.cpp`（67 行），`src/ed25519.cpp` 精简约 580 行（删除旧 `ed25519_cpu.cpp`/`ed25519_avx2.cpp`）
- 新增 `src/x25519_body.inc`（83 行），`src/x25519.cpp` 重写并新增 `src/x25519_avx512.cpp`：X25519 支持 AVX512 加速
- 批量签名/验证分派与 `include/cpu_features.hpp` 同步更新

#### Ed448 优化
- `src/ed448.cpp`、`src/ed448_body.inc`、`src/fe_448.hpp` 域运算与实现优化（合计约 400 行变更）

#### RSA GPU 优化
- `src/rsa_gpu.mu` kernel 与 `src/rsa_musa.cpp` 主机封装重构优化（两轮共约 1300 行变更），并同步优化 `rsa_batch_avx2.cpp`/`rsa_batch_avx512.cpp`/`rsa_batch_dispatch.cpp` 批量分派

#### 构建
- `CMakeLists.txt`、`tests/CMakeLists.txt` 调整：benchmark 目标移出 tests，README 同步更新

### Fixed
- 修复 RSA 相关 bug（含密钥生成/批量模幂路径，经 `src/rsa.cpp`、`src/rsa_batch_dispatch.cpp` 等两轮修复）

---

## [0.9.1] — 2026-07-31

### Added

#### X.509 v3 证书 (RFC 5280)
- 新增 `include/x509.hpp`、`src/x509.cpp`（783 行）：完全自包含的 DER 编码器/解码器，支持 ASN.1 基本类型（INTEGER、OID、BIT STRING、OCTET STRING、UTF8String、UTCTime、SEQUENCE、SET），X.509 v3 证书生成、解析与证名链验证。
- 支持五种密钥类型：**RSA-2048/4096**、**Ed25519**、**Ed448**、**ECDSA P-256**、**SM2**
- 支持证书扩展：**BasicConstraints**（CA）、**KeyUsage**、**ExtendedKeyUsage**（serverAuth/clientAuth）、**SubjectAlternativeName**（DNS SAN）
- 单元测试 `tests/test_x509.cpp`（459 行，30+ 项测试）：DER 原语编解码、自签名证书生成与验证（Ed25519/ECDSA/SM2/Ed448/RSA）、TLS X.509 集成、证名链验证

#### TLS X.509 集成
- `tls_make_x509_self_signed(cert, days)`：从 `tls_certificate` 生成 X.509 v3 DER 自签名证名（含 SAN、KeyUsage、EKU）
- `tls_sig_alg_to_key_type(sig_alg)`：SignatureAlgorithm → X.509 KeyType 映射
- `tls12_make_certificate(cert)`：实现 TLS 1.2 Certificate 消息构建（此前面声明未实现）
- TLS 1.3 握手 `tls13_make_certificate()`：`cert_data` 为空时自动调用 `tls_make_x509_self_signed()` 生成 X.509 DER

#### 命令行工具
- **`jpssl-cert`** (`src/cmd/jpssl_cert.cpp`, 305 行)：X.509 证名生成（`gen`）、查看（`info`）、证名链验证（`verify`/`chain`）、TLS API 生成（`tlsgen`）
- **`jpssl-crypt`** (`src/cmd/jpssl_crypt.cpp`, 339 行)：AES-256-GCM/ChaCha20-Poly1305 加密解密（`encrypt`/`decrypt`）、哈希（`sha256`/`sha512`/`sha3`/`sm3`）、HMAC、随机数生成
- 支持自定义 IV/AAD/Tag 十六进制传入，加密输出 IV‖密文‖Tag 格式，解密自动提取
- `make install` 安装至 `<prefix>/bin/`

### Changed

#### MUSA 条件编译
- 新增 `-DJP_ENABLE_MUSA=ON` 选项（**默认 OFF**）：MUSA GPU 加速改为可选的实验性功能
- `#include <musa_runtime.h>` 及所有 MUSA 池函数在 `src/chacha20_poly1305.cpp` 中被 `#ifdef JP_MUSA` 守卫
- `musa4096_rsa_batch_modpow` 在 `src/rsa.cpp` 中被 `#ifdef JP_MUSA` 守卫
- `CMakeLists.txt` 中 MUSA 库目标、`jpssl-test`、命令行工具均条件编译

#### 测试结构重组
- 新增 `tests/CMakeLists.txt`（199 行）：所有单元测试与 benchmark 目标从主 `CMakeLists.txt` 中分离
- 主 `CMakeLists.txt` 使用 `add_subdirectory(tests)`
- 测试链接 `MUSA_LIBS` 变量（MUSA 关闭时为空）

#### README 更新
- 新增 X.509 v3 API 章节（4 个子章节：自签名证名生成、DER 解析、证名链验证、TLS 集成）
- 新增命令行工具章节（jpssl-cert 和 jpssl-crypt 的用法与示例）
- 新增条件编译章节：`JP_ENABLE_MUSA` 默认 OFF
- 算法总览表 GPU 加速列标注“实验性”，依赖章节标注 MUSA 为可选

### Fixed
- `tests/test_tls.cpp` 第 371 行 `sf_a.size()` → `sf_b.size()`：SNI 测试中因不同密钥类型的 X.509 DER 大小差异而暴露的旧 bug

---

## [0.9.0] — 2026-07-30

### Added
- 初始版本：AES、ChaCha20-Poly1305、RSA、TLS 1.2/1.3、Ed25519、ECDSA、SM2/3/4 国密算法
- CPU 优化（AES-NI、AVX2、AVX512、Montgomery CIOS）
- MUSA GPU 加速（AES、ChaCha20、RSA、SHA-512 kernel）
- CTest 单元测试集
