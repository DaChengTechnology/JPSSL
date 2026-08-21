# 构建选项与产物

## CMake 选项

| 选项 | 默认 | 说明 |
|------|------|------|
| `JP_ENABLE_MUSA` | OFF | MUSA GPU 加速（实验性，仅 Linux，需要 MUSA SDK 4.3.0+） |
| `JP_ENABLE_BENCH` | OFF | 构建 `benchmarks/` 基准程序 |
| `JP_ENABLE_OPENMP` | ON | OpenMP 并行（CPU 批量 RSA 模幂，RSA 解密双线程） |
| `JP_ENABLE_AVX2` | ON | AVX2 GCM（4 路并行）+ SHA-512 SIMD 消息调度 + ChaCha20/Poly1305/X448/Ed448/Ed25519 SIMD 路径 |
| `JP_ENABLE_AVX512` | ON | AVX512 VAES GCM（8 路并行）+ Base64 AVX-512 + RSA 批量模幂 |

```bash
# 启用 MUSA GPU 加速（需要 MUSA SDK 4.3.0+）
cmake -B build -DJP_ENABLE_MUSA=ON

# 禁用所有 SIMD 加速（纯标量回退）
cmake -B build -DJP_ENABLE_AVX2=OFF -DJP_ENABLE_AVX512=OFF

# 构建基准程序
cmake -B build -DJP_ENABLE_BENCH=ON
```

## 构建产物

构建默认同时生成静态库与动态库：

| 库文件 | 类型 | 说明 |
|--------|------|------|
| `libjpssl_cpu.a` | 静态库 | CPU 密码学库 |
| `libjpssl_cpu.so` | 动态库 | CPU 密码学库（SOVERSION 1） |
| `libjpssl_musa.a` / `libjpssl_musa.so` | 静态/动态 | GPU 加速库（仅 `JP_ENABLE_MUSA=ON`） |
| `jpssl_cpu_static.lib` | 静态库 | Windows 静态库 |
| `jpssl_cpu.dll` + `jpssl_cpu.lib` | 动态库 | Windows 共享库与导入库 |

命令行工具（`make install` 后安装到 `bin/`）：

| 工具 | 说明 |
|------|------|
| `jpssl-cert` | X.509 v3 证书生成 / 查看 / 验证 |
| `jpssl-crypt` | 加密 / 解密 / 哈希 / HMAC / 随机数 |
| `jpssl-test` | 主测试程序 |

## 平台与编译器注意事项

### Windows（MSVC）

- **UTF-8 源文件**：全局编译选项包含 `/utf-8`，避免中文注释引发的 C4819 警告。
- **128 位整数兼容层**：MSVC 没有 GCC 的 `__uint128_t`，通过 `/FI` 强制包含 `include/jpssl_platform.hpp`，以 `jp_uint128`（基于 `_umul128` / `_addcarry_u64` / `_udiv128`，全部内联）提供等价语义。业务代码无需改动。
- **随机数**：统一走 `include/rand_os.hpp`（`jpssl::os_rand_bytes`）——Windows 用 `BCryptGenRandom`，Linux 用 `/dev/urandom`。MSVC 的 `std::random_device` 是确定性的，不用于密钥 / 签名 nonce。
- **CPU 特性检测**：`include/cpu_features.hpp` 在 MSVC 下使用 `__cpuidex` / `_xgetbv` 做运行时检测（AES-NI / AVX2 / AVX512 / SHA-NI），硬件加速分派在 Windows 上同样生效。
- **RSA Montgomery 汇编**：CIOS Montgomery 乘法走手写 MASM（`src/rsa_mont_asm_win.asm`，MULX 加速）；CRT 私钥解密使用半尺寸汇编路径（`mont_mul_half_asm`）。
- **SM3 汇编**：MSVC x64 下 `sm3_win.asm`（MASM）提供 64 轮全展开压缩函数，`sm3_cf` 自动走汇编。
- **动态库导出**：通过 `WINDOWS_EXPORT_ALL_SYMBOLS` 导出全部公共符号，无需手写 `__declspec(dllexport)`。
- **链接系统库**：Windows 自动链接 `bcrypt`（随机数）与 `ws2_32`（TLS socket）。
- **MUSA**：不支持 Windows，`-DJP_ENABLE_MUSA=ON` 会被自动禁用并提示。

### Linux（GCC / Clang）

- x86_64 下全局编译标志包含 `-maes -mavx2 -madx`。
- RSA Montgomery 汇编走 GCC 内联汇编（`src/rsa_mont_asm.cpp`）；运行时 CPU 不支持 BMI2/ADX 时自动回退到标量 `_umul128` 实现，CPUID 结果进程内缓存。
- MUSA 模块通过 `/usr/local/musa/cmake` 的 `find_package(MUSA)` 集成，`mcc` 编译 `--offload-arch=mp_21 / mp_22 / mp_31`。

## 条件编译与运行时调度

大部分 SIMD / 硬件加速路径都是**运行时按 CPUID 自动分派**，而非编译期硬编码：

- AES-GCM：软件 / AVX2（4 路）/ AVX512 VAES（8 路）自动分派（`aes_gcm_auto.cpp`）
- Base64：标量 / AVX2 / AVX-512（含 BW）自动分派
- SHA-1 批量哈希：标量 / AVX2（8 路）/ AVX-512（16 路）自动分派（`sha1_batch`）
- SM4-GCM：GHASH 按 PCLMULQDQ 支持自动分派（`sm4_gcm_dispatch.cpp`）
- RSA 批量模幂：标量 / AVX2 / AVX-512（`rsa_batch_dispatch.cpp`）
- Ed25519 / Ed448 批量验签：CPU / AVX2 / AVX-512（`ed25519_batch_dispatch.cpp` / `ed448_batch_dispatch.cpp`）
- SHA-512：CPU / SSE4.1 SIMD 消息调度

即使编译时启用了 AVX2/AVX-512，在不支持的 CPU 上也会自动回退到可用路径，不需要运行时检测代码。

## 依赖

- **C++20**（GCC 13+ / Clang 16+ / MSVC）
- **CMake** 3.20+
- **OpenSSL**（可选，仅 OpenSSL 对比测试 / 基准需要；未安装时自动跳过）
- **MUSA SDK** 4.3.0+（可选，实验性 GPU 加速，默认关闭，仅 Linux）
- **x86_64**（AES-NI / AVX2 / AVX512，可选）

## 移动端 / 桌面端平台构建

iOS（XCFramework）、macOS（dylib/.so/framework）、Android（AAR）与
HarmonyOS / OpenHarmony（.a/.so）的一键构建脚本与产物说明见
[平台构建（iOS / macOS / Android / HarmonyOS）](Platform-Builds)。
