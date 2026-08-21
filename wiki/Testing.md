# 测试与 CI

## 运行测试

构建后（见 [快速开始](Getting-Started)），通过 CTest 运行全部单元测试：

```bash
# Linux
ctest --test-dir build --output-on-failure

# Windows
ctest --test-dir build-win --output-on-failure
```

未安装 OpenSSL 时，OpenSSL 对比测试自动跳过；安装后自动启用更多交叉验证。

## 单元测试目标

| CTest 名称 | 覆盖内容 |
|------------|----------|
| `test_dtls` | DTLS 1.2/1.3（RFC 6347/9147）单元测试（记录层、cookie、分片/重传、密钥调度、Finished） |
| `test_dtls_openssl_interop` | DTLS 1.2 与 OpenSSL 4 双向互通（ECDHE-ECDSA × AES-128-GCM / ChaCha20-Poly1305） |
| `test_dtls13_openssl_interop` | DTLS 1.3 与 OpenSSL 互通检测（OpenSSL 未实现 DTLS 1.3 时编译期 SKIP） |
| `test_dtls_wolfssl_interop` | DTLS 1.2/1.3 与 wolfSSL 5.9.2 双向互通（4 套件 × 2 方向 = 8 用例，需 `JP_WOLFSSL_PREFIX`） |
| `test_aes` | AES 全覆盖单元测试（OpenSSL 对比） |
| `test_aes_modes` | AES 全模式 × 全密钥长度（单块/ECB/CBC/GCM 软件/auto/AVX2/AVX512/CCM，OpenSSL 交叉验证与篡改检测） |
| `test_aes_ccm` | AES-CCM 单元测试 |
| `test_gcm_simple` | GCM 基础测试 |
| `test_sha1` | SHA-1（NIST 向量、边界长度、增量更新、AVX2/AVX512 多缓冲交叉验证、批量分派、OpenSSL 对比） |
| `test_sha3` / `test_sha512` | SHA-3、SHA-384/512（OpenSSL 对比） |
| `test_tls` | TLS 1.2/1.3 单元测试 |
| `test_tls448` | TLS 1.3 X448/Ed448 握手测试（OpenSSL 对比） |
| `test_tls_sm` | TLS 国密套件（RFC 8998）测试 |
| `test_tls_socket` | TLS socket 封装层回环测试 |
| `test_tls_stability` | TLS 稳定性 / 稳压测试（反复握手 + 数据传输，泄漏启发式检测） |
| `test_tls_large_msg` | TLS 大消息自动分片 / 合并（16KiB 边界、64KiB 长度字段边界、256KiB、TLS 1.2、socket 端到端 128KiB） |
| `test_x509` | X.509 v3 证书单元测试 |
| `test_ct` | 证书透明（国密 + 国际）单元测试 |
| `test_base64` | Base64（RFC 4648 向量、全长度随机往返、SIMD 交叉验证、非法输入，484 断言） |
| `test_ed25519_rfc` / `test_ed448_rfc` | RFC 8032 向量（OpenSSL 对比） |
| `test_ed25519_debug` / `test_ed448_debug` | 调试测试 |
| `test_ed25519_batch` / `test_ed448_batch` | 批量验签测试 |
| `test_x25519_rfc` / `test_x448_rfc` / `test_x448_batch` | RFC 7748 向量与批量测试 |
| `test_x25519_ossl` | X25519 OpenSSL 对比 |
| `test_ecdsa` | ECDSA 单元测试（OpenSSL 对比） |
| `test_sm` | 国密 SM2/SM3/SM4 测试（OpenSSL 对比） |
| `test_ghash` / `test_ghash_debug` | GHASH 测试（OpenSSL 对比） |
| `test_openssl_compare` | OpenSSL 综合比较测试 |
| `test_verify_direct` / `test_ossl_verify` | 验证测试（OpenSSL 对比） |

## DTLS 1.2 / 1.3 合规性测试

`tests/test_dtls_wolfssl_interop.cpp`（CTest 目标 `test_dtls_wolfssl_interop`）使用
wolfSSL 作为独立对端，验证 jpssl DTLS 1.2（RFC 6347）与 DTLS 1.3（RFC 9147）的互通合规性：

- 方向 A：jpssl DTLS 服务器 ↔ wolfSSL DTLS 客户端（wolfSSL 校验 jpssl 证书链）
- 方向 B：wolfSSL DTLS 服务器 ↔ jpssl DTLS 客户端（jpssl 校验 wolfSSL 证书链）
- 套件：DTLS 1.2（ECDHE-ECDSA-AES128-GCM-SHA256、ECDHE-ECDSA-CHACHA20-POLY1305）、
  DTLS 1.3（TLS_AES_128_GCM_SHA256、TLS_CHACHA20_POLY1305_SHA256）
- 每个方向断言：握手成功、协商套件一致、双向应用数据一致（共 8 用例）

构建与运行：
```bash
# 1) 构建 wolfSSL（5.9.2，开启 DTLS1.3；关闭 MLKEM 以使用标准 X25519/P-256 key_share）
cmake -S wolfssl-src -B wolfssl-build -DWOLFSSL_DTLS=yes -DWOLFSSL_TLS13=yes \
      -DWOLFSSL_DTLS13=yes -DWOLFSSL_MLKEM=no -DWOLFSSL_CURVE25519=yes \
      -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no -DBUILD_SHARED_LIBS=OFF
cmake --build wolfssl-build && cmake --install wolfssl-build --prefix wolfssl-install

# 2) 配置 jpssl（注入 wolfSSL 安装前缀与测试证书目录）
cmake -S . -B build-win -DJP_WOLFSSL_PREFIX=$PWD/wolfssl-install \
      -DJP_WOLFSSL_CERT_DIR=$PWD/wolfssl-src/certs

# 3) 运行
./build-win/tests/test_dtls_wolfssl_interop
```

调试时可设置 `WOLF_CASE=<0..7>` 只运行单个方向用例，便于逐用例抓包定位。

## TLS 稳定性测试

`tests/test_tls_stability.cpp`（CTest 目标 `test_tls_stability`）在单次运行内反复执行：

- TLS 1.3（Ed25519 / ECDSA P-256 / RSA-2048 证书轮换）
- TLS 1.2（RSA）
- 0-RTT / PSK 会话恢复
- TLS-over-TCP socket 端到端握手与分块数据传输

并统计各阶段耗时、失败次数与进程内存增长（泄漏启发式检测）。

```bash
# 默认参数（约 10s，适合 CTest）
ctest --test-dir build-win -R test_tls_stability --output-on-failure

# 长稳压测：2000 轮 TLS 1.3 + 4 个并发 worker，每 worker 100 轮 socket 握手
./build-win/tests/test_tls_stability --iters 2000 --socket-iters 100 --threads 4
```

迭代次数可用 `--iters` / `--tls12-iters` / `--psk-iters` / `--socket-iters` / `--threads` / `--leak-mb` 等参数控制，也支持 `JPSSL_STRESS_*` 环境变量。

## 主测试程序

`jpssl-test` 是构建产出的主测试程序（`src/main.cpp`），覆盖各算法模块的冒烟验证：

```bash
LD_LIBRARY_PATH=/usr/local/musa/lib ./jpssl-test
```

## 持续集成

GitHub Actions 共 7 个工作流，覆盖桌面、移动与嵌入式平台；除 Linux / Windows 运行
全量 `ctest` 外，iOS / macOS / Android / HarmonyOS 均为构建 + 产物校验。

| 工作流 | 平台 | 内容 |
|--------|------|------|
| `ci.yml` | x86_64 Linux | Release 构建 + 全量 `ctest`；benchmarks 编译验证 |
| `arm-linux.yml` | ARM64 Linux | `ubuntu-24.04-arm` 原生构建 + 全量 `ctest`；aarch64-linux-gnu 交叉编译 + 产物校验 |
| `windows.yml` | Windows x64 MSVC | Release 构建 + `ctest`（OpenSSL 可选，未安装时对比测试自动跳过）；benchmarks 编译验证 |
| `ios.yml` | macOS + Xcode | `ios/build-xcframework.sh` 构建 `JPSsl.xcframework` + Swift 编译冒烟 |
| `macos.yml` | macOS arm64（Apple Silicon） | `macos/build.sh` 构建 dylib/.so/.a + `JPSslC.framework`，`lipo`/`codesign` 校验 + C 冒烟测试 |
| `android.yml` | ubuntu + Android SDK | JDK 17 + Gradle 8.5 + NDK r26b，`assembleRelease` 产出 AAR，校验 `jni/arm64-v8a/libjpssl.so` |
| `ohos.yml` | ubuntu + OpenHarmony 6.1 SDK | `cmake/toolchains/ohos.cmake` 交叉编译 arm64-v8a，校验 `libjpssl_cpu.a/.so` |

各平台构建命令与产物详见 [平台构建（iOS / macOS / Android / HarmonyOS）](Platform-Builds)。

另有 `.gitlab-ci.yml` 支持 GitLab CI。
