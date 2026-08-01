# Changelog

## [0.9.3] — 2026-08-01

### Added

#### Windows (MSVC) 平台支持
- **128 位整数兼容层** `include/jpssl_platform.hpp`：MSVC x64 无 GCC 的 `__uint128_t`，通过 `/FI` 强制包含该头，以 `jp_uint128` 类 + `#define __uint128_t jp_uint128` 提供等价语义（基于 `_umul128`/`_addcarry_u64`/`_subborrow_u64`/`_udiv128`，全部内联）。业务代码零改动；GCC/Clang 继续使用原生类型。
- **系统随机源** `include/rand_os.hpp` + `src/rand_os.cpp`：统一 `jpssl::os_rand_bytes`——Windows 用 `BCryptGenRandom`，Linux 用 `/dev/urandom`；`rsa.cpp`/`tls.cpp`/`ecdsa.cpp`/`sm2.cpp`/`jpssl_crypt` 全部接入（MSVC 的 `std::random_device` 是确定性的，不再用于密钥/签名 nonce）。
- **CPU 特性检测 MSVC 实现**：`cpu_features.hpp` 改用 `__cpuidex`/`_xgetbv`（含 OSXSAVE/XCR0 检查），AES-NI/AVX2/AVX512/SHA-NI 运行时分派在 Windows 同样生效。
- **CMake 平台分支**：MSVC 编译选项（`/utf-8`、`/bigobj`、`/EHsc`、`/FI`、`NOMINMAX`）、按源文件加 `/arch:AVX2|AVX512`、bcrypt 链接、`WINDOWS_EXPORT_ALL_SYMBOLS` DLL 导出、Windows 下静态库改名 `jpssl_cpu_static.lib`（避免与共享库导入库同名冲突）、MUSA 自动禁用、OpenSSL 改为可选（缺失时跳过对比测试）。
- **测试/基准条件化**：OpenSSL 依赖的测试目标在无 OpenSSL 时整体跳过。
- README 新增「Windows 构建（MSVC）」章节。

### Fixed
- **`jp_uint128::operator&=` 高位未清零**：64 位掩码与 128 位值按位与时 `hi` 残留，导致 radix-2^51 域运算（fe51_mul 进位链）在大输入下错误——表现为 X25519 密钥协商结果错误；已改为 `hi = 0`（与 GCC 原生 `__uint128_t` 语义一致）。
- **`_umul128` 参数顺序错误**：低 64 位返回值被误作高 64 位，导致 128 位乘法 lo/hi 颠倒（RSA Miller-Rabin 误判、密钥生成死循环）；已修正。
- **RSA 2048 密钥生成死循环（跨平台既有 bug）**：`keygen_fn_32` 找素数时清除 bit62，使 p/q 被限制在 `[2^1023, 1.25·2^1023)`，n = p·q 恒为 2047 位，`n.bit_length() < 2048` 重试循环永不退出；移除 bit62 清除（与 `find_prime` 一致）。
- **`keygen_with_watchdog` 超时适配**：Windows 上 jp_uint128 模拟层慢约一个数量级，300ms/3s 的 Linux 超时必然触发 abort 重试并失败，超时放大 20 倍。
- **GCC 扩展 → 标准 C++**：`tls.cpp` 两处 VLA（`uint8_t buf[n+size()]`）改 `std::vector`；`tests/test_aes.cpp`、`test_ghash.cpp`、`test_ossl_verify.cpp` 零长度数组 `[0]` 改 `[1]`。
- **`timegm` 平台化**：`x509.cpp` 在 Windows 用 `_mkgmtime`。
- **MUSA GPU 测试守卫**：`src/main.cpp` 的 5 个 GPU 测试函数与 `tests/test_openssl_compare.cpp` 的 GPU 基准加 `#ifdef JP_MUSA`（MUSA 关闭时跳过，修复跨平台既有链接缺陷）；CMake MUSA 分支为 `jpssl-test` 补 `JP_MUSA` 宏定义。

### 验证
- 本机 VS 2026 Build Tools（MSVC 19.51）+ CMake/Ninja 全量构建通过（166 目标，含静态/动态库、3 个命令行工具、38 个测试 exe）。
- CTest 21 项中 19 项通过：AES/CCM/GCM、SHA-3/SHA-512、TLS 1.2/1.3 全握手与 0-RTT、X.509 DER/证书链、Ed25519/Ed448 RFC 向量、X25519/X448 RFC 向量、SM4-GCM、RSA 2048 keygen/sign/verify、OpenSSL 对比。
- 已知遗留（Linux 同样存在，非 Windows 特有）：`x509_cert::verify_signature` 对 DER 重新编码证书的验证（`test_x509.cpp` 已有 TODO 注释），影响 `test_x509` 的 TLS 自签名项与 `test_tls_sm` 的握手项。

---

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
