# jpssl — C++20 高性能密码学库（CPU + MUSA GPU）



跨平台密码学库，支持 **AES**、**ChaCha20-Poly1305**、**RSA**、**TLS 1.2/1.3**、**Ed25519**、**Ed448**、**ECDSA**、**X.509 v3 证书**（RFC 5280），以及 **SM2/SM3/SM4 国密算法**（GM/T 0002/3/4-2012，RFC 8998 TLS 1.3 国密套件）。提供 CPU 优化（AES-NI/AVX2/VAES/PCLMULQDQ/Montgomery、ARM NEON：AES-GCM / ChaCha20 / SHA-1 / SHA-256 / SHA-512 / SHA-3 / SM3 / SM4）和可选的 MUSA GPU 加速（实验性，默认关闭）。同时提供静态库和动态库两种构建方式。



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

│  ├─ aes_gcm_neon.cpp       ARM NEON GCM (AESE+PMULL) │

│  ├─ chacha20_poly1305.cpp  ChaCha20-Poly1305 AEAD │

│  ├─ chacha20_neon.cpp      ARM NEON ChaCha20 (4 路) │

│  ├─ rsa.cpp (+body.inc)    RSA 2048/4096 Montgomery│

│  ├─ sha1.cpp               SHA-1 哈希            │

│  ├─ sha1_avx2.cpp          SHA-1 8 路多缓冲 (AVX2) │

│  ├─ sha1_avx512.cpp        SHA-1 16 路多缓冲 (AVX512) │

│  ├─ sha1_neon.cpp          ARM NEON SHA-1 (SHA1C/P/M) │

│  ├─ sha256.cpp             SHA-256 哈希           │

│  ├─ sha256_neon.cpp        ARM NEON SHA-256       │

│  ├─ sha3.cpp               SHA3-256/384/512 哈希   │

│  ├─ sha3_neon.cpp          ARM NEON SHA-3 (EOR3/RAX1/XAR) │

│  ├─ sha512_cpu.cpp         SHA-384/512 哈希 (CPU) │

│  ├─ sha512_opt.cpp         SHA-384/512 哈希 (SSE) │

│  ├─ sha512_neon.cpp        ARM NEON SHA-384/512 (SHA-512 扩展) │

│  ├─ hmac.cpp               HMAC-SHA256/SHA384      │

│  ├─ hkdf.cpp               HKDF-SHA256/SHA384      │

│  ├─ x25519.cpp             X25519 ECDH            │

│  ├─ ed25519.cpp            Ed25519 签名/验证      │
│  ├─ ed448.cpp              Ed448 签名/验证        │
│  ├─ ecdsa.cpp              ECDSA P-256/384/521 签名/验证/ECDH (ADX 汇编) │


│  ├─ sm2.cpp                SM2 签名/验证/密钥交换  │

│  ├─ sm3.cpp                SM3 密码杂凑算法        │

│  ├─ sm3_win.asm           SM3 标量汇编 (MSVC x64)       │

│  ├─ sm3_neon.cpp          ARM NEON SM3 (vsm3* 指令)      │

│  ├─ sm4.cpp                SM4 分组密码            │

│  ├─ sm4_neon.cpp          ARM NEON SM4 (vsm4e 指令)      │

│  ├─ sm4_gcm.cpp            SM4-GCM AEAD 模式       │

│  ├─ hmac.cpp               HMAC-SHA256/SHA384/SM3   │

│  ├─ hkdf.cpp               HKDF-SHA256/SHA384/SM3   │

│  ├─ x509.cpp               X.509 v3 证书 DER/PEM、私钥、CSR │

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

| `bench_base64` | base64 编解码：标量 vs AVX2 vs AVX512 vs 自动分发 |

| `bench_sm_ossl` | SM3 吞吐 + SM2 keygen/sign/verify vs OpenSSL |

| `bench_ed25519_ossl` | Ed25519 签名/验证 vs OpenSSL（仅找到 OpenSSL 时构建） |

| `bench_ed448_x448_ossl` | Ed448 / X448 vs OpenSSL（仅找到 OpenSSL 时构建） |

| `bench_x25519_ossl` | X25519 ECDH vs OpenSSL（仅找到 OpenSSL 时构建） |



`bench_cipher_suites` 覆盖 TLS 1.3/1.2 的 11 个密码套件（AES-128/256-GCM、ChaCha20-Poly1305、AES-128-CCM/CCM-8、SHA-256/384），默认按 16 KiB TLS 记录分片计时，支持 `--data-mb / --record / --rounds / --target-ms / --no-ossl` 参数：



```bash

bench_cipher_suites --data-mb 32 --record 16384 --rounds 5

```



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



## Android（arm64-v8a）实现

新增 `android/` Gradle 工程：通过 NDK + CMake 把 jpssl 编译为 **libjpssl.so**（内部静态链接 `jpssl_cpu`），并用 **JNI（`JNI_OnLoad → RegisterNatives`）** 导出 Java 与 Kotlin 可直接调用的 native 符号。

- **ABI**：仅构建 **arm64-v8a（ARMv8/AArch64）**，不构建 x86/x86_64（`ndk.abiFilters`）。
- **最低版本号**：`minSdk` 与 CMake `ANDROID_PLATFORM` **统一卡在 android-21**（arm64-v8a / 64 位 ABI 最低基线，Android 5.0）。
- **导出算法符号**：版本号、CSPRNG、Base64、SHA-1/256/384/512、SHA3-256/384/512、SM3、HMAC-SHA256/SHA384/SM3、AES-GCM、ChaCha20-Poly1305、X25519、Ed25519、SM2、SM4（ECB/CBC）、RSA（2048/4096，PKCS#1 v1.5）。
- **硬件加速**：ARMv8 NEON/crypto 全量启用（AES-GCM、ChaCha20、SHA-1/2/3、SM3、SM4），SHA-512/SHA-3/SM3/SM4 源单独按 `armv8.4-a+crypto` 编译，运行时由 `cpu_features` 自动分派，低版本 CPU 安全回退标量。

```bash

# 1) 在 android/ 下生成 wrapper（一次性；需已安装 Gradle）
cd android && gradle wrapper

# 2) 构建 AAR（自动调用 NDK CMake 编译 libjpssl.so）
#    需 Android SDK + NDK（r23+）+ JDK 17，并配置 local.properties 或 ANDROID_HOME
./gradlew :jpssl:assembleRelease

```

产物：`android/jpssl/build/outputs/aar/jpssl-release.aar`。Java 侧 `io.github.jpssl.Jpssl`（静态 native 方法）与 Kotlin 侧 `io.github.jpssl` 扩展函数（`ByteArray.sha256()`、`aesGcmEncrypt()`、`sm2Sign()` 等）一一对应。



## HarmonyOS / OpenHarmony (鸿蒙) 构建



支持在 HarmonyOS NEXT（鸿蒙）7.0 及兼容 OpenHarmony 版本的应用 native 模块中使用，提供 `libjpssl_cpu.a` 与 `libjpssl_cpu.so`。需要 HarmonyOS NDK（DevEco Studio 自带，或命令行下载的 SDK 的 `native` 目录）。



```bash

# 1) 指定 NDK 路径（HarmonyOS NEXT SDK 的 native 目录）交叉编译

cmake -S . -B build-ohos \

      -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/ohos.cmake \

      -DOHOS_NDK_HOME="/path/to/.../native" \

      -DOHOS_ARCH=arm64-v8a \

      -DCMAKE_BUILD_TYPE=Release

cmake --build build-ohos

```

不传 `-DOHOS_NDK_HOME` 时，toolchain 会依次查找环境变量 `OHOS_NDK_HOME`、`DEVECO_SDK_HOME`（DevEco Studio SDK 下自动取最新版本目录）。



- `OHOS_ARCH`：`arm64-v8a`（默认，真机）/ `armeabi-v7a` / `x86_64`（模拟器）。

- `OHOS_STL`：`c++_shared`（默认）/ `c++_static`。

- arm64-v8a 下 NEON/crypto 硬件加速全量启用（AES-GCM / ChaCha20 / SHA-1/2/3 / SM3 / SM4 等），运行时由 `cpu_features` 自动分派；`include/rand_os.hpp` 的随机源在鸿蒙上优先走 `getrandom()`，失败回退 `/dev/urandom`。

- 鸿蒙 NDK 面向应用 native 模块（`.so`），不提供可执行文件链接运行时，因此该 toolchain 下**只构建库**：`jpssl-test`、命令行工具、测试与示例自动跳过；OpenMP / MUSA GPU 加速（仅 Linux）自动禁用。

- 在鸿蒙工程中集成时，可将构建出的 `libjpssl_cpu.so` 放入 `src/main/cpp/libs/arm64-v8a/`，并在 `CMakeLists.txt`（应用侧）中 `target_link_libraries(... jpssl_cpu)` + `target_include_directories(... include/)`。



## TLS 稳定性测试



`tests/test_tls_stability.cpp`（CTest 目标 `test_tls_stability`）在单次运行内反复执行

TLS 1.3（Ed25519 / ECDSA P-256 / RSA-2048 证书轮换）、TLS 1.2 (RSA)、

0-RTT/PSK 会话恢复、TLS-over-TCP socket 端到端握手与分块数据传输，

并统计各阶段耗时、失败次数与进程内存增长（泄漏启发式检测）。



```bash

# 默认参数（约 10s，适合 CTest）

ctest --test-dir build-win -R test_tls_stability --output-on-failure



# 长稳压测：2000 轮 TLS 1.3 + 4 个并发 worker，每 worker 100 轮 socket 握手

./build-win/tests/test_tls_stability --iters 2000 --socket-iters 100 --threads 4

```



迭代次数可用 `--iters` / `--tls12-iters` / `--psk-iters` / `--socket-iters` /

`--threads` / `--leak-mb` 等参数控制，也支持 `JPSSL_STRESS_*` 环境变量。



## TLS 大消息自动分片与合并



- 记录层（`tls_encrypt` / `tls_decrypt`）：明文 > 16KiB（`TLS_MAX_RECORD_PLAINTEXT`）

  自动拆分为多条 ≤16KiB 的 record（TLS 1.2 / 1.3 均支持），解密时逐条解析并自动

  合并还原，单次调用即可收发任意大小的消息。

- socket 层（`tls_connection::send` / `recv`）：一次 `send(大缓冲)` 自动分片写出；

  `recv()` 会把同一突发到达的多条 record 合并后一次返回，大消息无需循环读取。

  消息边界由应用层协议负责（如 HTTP Content-Length）。

- 测试 `test_tls_large_msg`：覆盖 16KiB 边界、64KiB 长度字段边界、256KiB、

  TLS 1.2 以及 socket 端到端 128KiB 单次 send / 单次 recv。



平台适配说明：



- **128 位整数**：MSVC 不提供 GCC 的 `__uint128_t`，Windows 构建通过 `/FI` 强制包含 `include/jpssl_platform.hpp` 提供等价的 `jp_uint128` 兼容层（基于 `_umul128`/`_addcarry_u64`/`_udiv128`，全部内联）。**不要求**业务代码改动；GCC/Clang 仍使用原生类型。

- **随机数**：统一走 `include/rand_os.hpp`（`jpssl::os_rand_bytes`）——Windows 用 `BCryptGenRandom`，Linux 用 `/dev/urandom`。MSVC 的 `std::random_device` 是确定性的，不用于密钥/签名 nonce。

- **CPU 特性检测**：`include/cpu_features.hpp` 在 MSVC 下改用 `__cpuidex`/`_xgetbv` 运行时检测 AES-NI/AVX2/AVX512/SHA-NI，硬件加速分派在 Windows 上同样生效。

- **ARM NEON / macOS (Apple Silicon)**：aarch64 下提供 NEON 硬件加速路径——AES-GCM（AESE/AESMC + PMULL GHASH，4 块并行）、ChaCha20（4 块并行）、SHA-1（SHA1C/P/M + SHA1SU0/1）、SHA-256（vsha256hq）、SHA-384/512（vsha512hq2）、SHA-3/Keccak（EOR3/RAX1/BCAX/XAR）、SM3（vsm3ss1/tt1a/tt2a/pw1/partw1/partw2）、SM4（vsm4e/vsm4ekey），运行时由 `cpu_features` 自动分派：macOS 用 `sysctlbyname("hw.optional.arm.FEAT_*")`、Linux 用 `getauxval(AT_HWCAP)`、其他 aarch64 平台回退编译期 `__ARM_FEATURE_*` 宏。ARMv8.0 起必选的 NEON + `-march=…+crypto`（AES/PMULL/SHA 扩展）即可启用；SHA-512/SHA-3/SM3/SM4 属于 ARMv8.2/8.4+ 可选扩展（FEAT_SHA512/SHA3/SM3/SM4），默认单独以 `-march=armv8.4-a+crypto` 编译这些源（也可直接 `-DJP_ARM_MARCH=armv8.4-a` 让全部 NEON 源按该等级编译，含 SHA-1/SHA-256），在**不支持这些指令的 CPU（如 Apple M 系列不支持 FEAT_SM3/SM4）上运行时自动回退标量实现，不会触发非法指令**。SM2/ECDSA/Ed25519/Ed448/X25519/X448 没有对应的 ARM 密码学指令，走可移植标量路径：256/448 位域运算在 AArch64 上由 `__uint128_t` 编译为 `umulh`/`adc`/`madd` 序列（SM2 与 ECDSA 的 Montgomery CIOS、fe51 radix-2^51、Goldilocks fe448 均如此），且 SM2 的 ZA/签名杂凑、Ed25519 的 SHA-512、Ed448 的 SHAKE256 分别自动受益于 SM3/SHA-512/SHA-3 的 NEON 路径。`-DJP_ARM_MARCH=armv9-a` 会自动禁用 SVE/SVE2 代码生成（Apple 芯片不支持 SVE），保证构建产物在 Apple Silicon 与 ARMv9 机器上均可运行。

- **Base64 SIMD 加速**：RFC 4648 base64 编解码新增 AVX2（24B→32B/次）与 AVX-512（48B→64B/次）路径（`src/base64_avx2.cpp` / `src/base64_avx512.cpp`），运行时按 AVX-512 > AVX2 > 标量自动分派，尾部与 `=` 填充仍走标量。AVX2 实测编码约 21–22 GB/s、解码约 17 GB/s（i7-13700K，vs 标量编码约 3 GB/s、解码约 0.2 GB/s）。

- **RSA Montgomery 汇编加速**：RSA-2048/4096 的 CIOS Montgomery 乘法在 Windows 走手写 MASM 汇编（`src/rsa_mont_asm_win.asm`，MULX 加速，K=32/64），Linux 走 GCC 内联汇编（`src/rsa_mont_asm.cpp`）。运行时不支持 BMI2/ADX 的 CPU 自动回退到标量 `_umul128` 实现；CPUID 检测结果进程内缓存。

- **CRT 半尺寸汇编加速**：CRT 私钥解密的 p/q 模幂使用半尺寸 Montgomery 乘法 `mont_mul_half_`（只处理前 K/2 个 limb），同样接入汇编快速路径（`mont_mul_half_asm`，HK=16/32，MASM 宏生成双实例 + GCC 动态 HK 单实例），核心吞吐提升约 1.3–1.45×。

- **CRT 解密默认双线程 OpenMP**：`rsa_decrypt`/`rsa_crt_decrypt`（dec_fn + RSADP/RSADP4096）的两路独立模幂 m1/m2 用 `#pragma omp parallel sections num_threads(2)` 并行（`-DJP_ENABLE_OPENMP=OFF` 或非 OpenMP 编译器自动回退串行），2048/4096 解密实测提速 1.5–1.7×；RSADP 与 dec_fn 统一走半尺寸路径。

- **RSA keygen 素数预算兜底**：素数搜索预算 100ms（`rsa_keygen`/`rsa_keygen_crt` 及其 4096 版本统一），超时即从预制素数表（`src/rsa_prebuilt_primes_data.inc`，1024 位×50 对 + 2048 位×50 对，MR 已验证）随机取一组完成 keygen，保证 keygen 永不因素数搜索卡死。预制素数公开、仅作测试/兜底，不用于生产密钥。注：构建规则为 unscanned，`.inc` 通过 `OBJECT_DEPENDS` 显式跟踪，改动后自动触发 `rsa.cpp` 重编。

- **MUSA GPU 加速**：仅支持 Linux，Windows 上 `-DJP_ENABLE_MUSA=ON` 会被自动禁用并提示。

- **HarmonyOS / OpenHarmony（鸿蒙）**：通过 `cmake/toolchains/ohos.cmake` 交叉编译，只产出 `libjpssl_cpu.a` / `libjpssl_cpu.so`（详见上方 "HarmonyOS / OpenHarmony (鸿蒙) 构建"）。arm64-v8a 全量启用 NEON/crypto 加速；随机源优先 `getrandom()`；`cpu_features.hpp` 的 ARM 特性检测识别 `__OHOS_FAMILY__`/`__OHOS__`（同为 Linux 内核，走 `getauxval`），并容错缺失 `<asm/hwcap.h>` 的 sysroot。

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

| `jpssl-crypt` | 加密 / 解密 / 哈希 / HMAC / Base64 | `src/cmd/jpssl_crypt.cpp` |



### jpssl-cert — 证书工具



```bash

# 生成自签名 X.509 v3 证书 + 私钥 (有效期默认 365 天)

# 默认输出到 ~/.ssh/cert.der 与 ~/.ssh/key.bin (目录自动创建, 私钥权限 0600)

jpssl-cert gen --cn example.com --key-type ed25519

# 支持的密钥类型: ed25519 | ecdsa | sm2 | rsa2048 | ed448

# 用 --days 指定有效期 (gen / tlsgen 均支持, 默认 365 天)

# 用 --out / --key-out 指定其他位置 (支持 ~ 展开)

jpssl-cert gen --cn example.com --key-type ed25519 --days 90 --out ~/certs/cert.der --key-out ~/certs/key.bin



# 查看证书信息 (支持 DER 或 PEM)

jpssl-cert info --cert cert.der

jpssl-cert info --cert cert.pem



# 查看私钥 (PKCS#8 / PKCS#1 / SEC1 / RFC 8410 PEM)

jpssl-cert key --key key.pem

# 查看加密私钥 (PBES2, 需 --pass 密码)

jpssl-cert key --key encrypted.pem --pass your-password



# 查看 CSR (PKCS#10 PEM)

jpssl-cert csr --csr request.csr



# 验证证书链 (leaf → root) (支持 DER 或 PEM)

jpssl-cert verify --cert leaf.der --ca root.der

# 多级链: --ca 可多次指定中间 CA

jpssl-cert verify --cert leaf.der --ca intermediate.der --ca root.der



# 通过 TLS API 生成证书 (等价于 tls_make_x509_self_signed)

jpssl-cert tlsgen --cn example.com --key-type ecdsa --out cert.der --key-out key.bin

# 指定有效期 10 年

jpssl-cert tlsgen --cn example.com --key-type ecdsa --days 3650 --out cert.der --key-out key.bin

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

jpssl-crypt hash --algo sha1   --in file.txt     # SHA-1 (20 bytes)

jpssl-crypt hash --algo sha256 --in file.txt

jpssl-crypt hash --algo sm3   --in file.txt     # 国密 SM3



# HMAC

jpssl-crypt hmac --algo sha256 --key <hex-key> --in file.txt



# Base64 编码 / 解码 (RFC 4648)

jpssl-crypt b64encode --in file.bin --out file.b64

jpssl-crypt b64decode --in file.b64 --out file.bin



# 生成随机字节 (十六进制输出)

jpssl-crypt rand 32

```



支持的算法：

- **加密**: `aes256gcm`（AES-256-GCM AEAD）、`chacha20`（ChaCha20-Poly1305 AEAD）

- **哈希**: `sha1`、`sha256`、`sha512`、`sha3-256`、`sha3-512`、`sm3`

- **HMAC**: `sha256`、`sha384`、`sm3`

- **Base64**: `b64encode`（二进制 → RFC 4648 文本）、`b64decode`（文本 → 二进制，容忍空白字符）



密钥、IV、Tag 均以十六进制字符串传入，AAD 认证数据可用 `--aad <hex>` 指定。



## 算法总览



| 算法 | 模式 | CPU 加速 | GPU 加速 |

|------|------|----------|----------|

| **AES-128/256** | ECB, CBC+PKCS7, GCM | AES-NI (~5 GB/s), AVX2/AVX512 GCM, ARM NEON (AESE+PMULL) | ECB kernel (实验性) |

| **GHASH / GF(2^128)** | GCM 认证原语（一次性/增量/GCM 完整哈希） | PCLMULQDQ / ARM PMULL | — |

| **ChaCha20-Poly1305** | 流加密, AEAD | ARM NEON (4 路并行) | Keystream kernel (实验性) |

| **RSA 2048/4096** | PKCS#1 v1.5 | Montgomery CIOS | 批量模幂 (实验性) |

| **SHA-1** | 哈希 (FIPS 180-4) | AVX2 8 路 / AVX-512 16 路多缓冲, ARM NEON (SHA1C/P/M) | — |

| **SHA-256** | 哈希 | ARM NEON (SHA-256 扩展) | — |

| **SHA-384/512** | 哈希 (FIPS 180-4) | SSE4.1 消息调度, ARM NEON (SHA-512 扩展) | GPU kernel (实验性) |

| **SHA3-256/384/512** | 哈希 (FIPS 202, Keccak) | ARM NEON (SHA-3 扩展: EOR3/RAX1/BCAX/XAR) | — |

| **HMAC-SHA256/SHA384/SM3** | MAC | — | — |

| **HKDF-SHA256/SHA384/SM3** | TLS 1.3 密钥派生 | — | — |

| **X25519** | ECDH 密钥交换 | — | — |

| **Ed25519** | 数字签名 (EdDSA) | — | — |



| **X25519** | ECDH 密钥交换 | AVX-512 (x86), AArch64 标量 fe51 (umulh/adc) | — |

| **X448** | ECDH 密钥交换 (RFC 7748) | 标量 Goldilocks fe448 (AArch64 umulh/adc), 批量 x86 AVX2/AVX512 | — |

| **Ed25519** | 数字签名 (EdDSA, RFC 8032) | 标量 radix-2^51 (x86 ADX 汇编 / AArch64 umulh·adc) | — |

| **Ed448** | 数字签名 (EdDSA, RFC 8032) | 标量 Goldilocks fe448 (AArch64 umulh/adc), 批量验证 x86 AVX2/AVX512 | — |

| **ECDSA P-256/P-384/P-521** | 数字签名 (secp256r1/secp384r1/secp521r1) 与 ECDHE | x86 ADX 汇编 + nistz256 特殊归约 + comb 定点表; AArch64 umulh/adc | — |

| **X.509 v3** | 证书 DER/PEM 编解码 (RFC 5280), 私钥读取 (PKCS#8/PKCS#1/SEC1/加密PBES2), CSR (PKCS#10), 自签名/证书链, SAN/KeyUsage/BasicConstraints | — | — |

| **SM2** | 数字签名/密钥交换 (sm2p256v1, GM/T 0003) | 标量 Montgomery CIOS (AArch64 umulh/adc), SM3 杂凑走 NEON | — |

| **SM3** | 密码杂凑 (256-bit, GM/T 0004) | ARM NEON (SM3 扩展: vsm3*), x86 标量汇编 (MSVC) | — |

| **SM4** | 分组密码 (128-bit, GM/T 0002) | ARM NEON (SM4 扩展: vsm4e) | — |

| **SM4-GCM** | SM4 AEAD 认证加密 (NIST SP 800-38D) | AVX2 自动分派 | — |

| **SM4-CCM** | SM4 AEAD 认证加密 (NIST SP 800-38C) | — | — |

| **TLS 1.2/1.3** | 完整握手, 密码套件协商, ECDHE/RSA, AES-GCM/ChaCha20/CCM/SM4-GCM, 0-RTT, RFC 8998 | AVX2/AVX512 GCM, ARM NEON GCM | — |

| **QUIC v1/v2 SSL** | QUIC 所需 TLS 1.3 支持（RFC 9001/9369）：无记录层握手、quic_transport_parameters 扩展、Initial/握手/1-RTT 数据包保护密钥、头部保护掩码 | — | — |

| **DTLS 1.2/1.3** | 标准数据报 TLS（RFC 6347/9147）：记录层（epoch/seq + AEAD）、握手（cookie/分片/重传/ACK）、ECDHE（X25519/P-256/X448）、AES-128/256-GCM、ChaCha20 | — | — |



## API 示例



### AES



```cpp

#include "aes.hpp"

aes_context ctx; ctx.init(std::span<const uint8_t,16>(key));

aes_cbc_encrypt(ctx, iv, plaintext, ciphertext);

aes_gcm_encrypt(ctx, iv, 12, plaintext, aad, ct, tag);

```



GHASH / GF(2^128) 通用接口（GCM 认证核心，可单独使用）：



```cpp

uint8_t H[16], S[16];              // H = AES_encrypt(K, 0^128)



// 一次性 GHASH（末尾块自动补零）

ghash(H, data, S);



// 增量 GHASH（流式，分块喂入）

ghash_ctx g;

ghash_init(&g, H);

ghash_update(&g, aad.data(), aad.size());

ghash_update(&g, ciphertext.data(), ciphertext.size());

ghash_final(&g, S);



// 完整 GCM 认证哈希（含 AAD/密文分段补零与长度块，输出 GCM 的 S 值）

gcm_ghash(H, aad, ciphertext, S);

// 完整 GCM 标签：tag = S ^ AES_encrypt(K, J0)，J0 = IV || 0^31 || 1

```



底层原语 `gf128_mul`（PCLMULQDQ 加速的 GF(2^128) 乘法，NIST 大端序约定）同样公开，可用于自定义认证构造。



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



### SHA-1 / SHA256 / SHA384/512 / SHA3 / HMAC / HKDF



```cpp

#include "sha1.hpp"

sha1_ctx ctx; sha1_init(&ctx);

sha1_update(&ctx, data, len);

uint8_t digest[20]; sha1_final(&ctx, digest);



// 批量哈希（等长消息，运行时按 AVX-512 16 路 > AVX2 8 路 > 标量分派）

const uint8_t* msgs[8] = {m0, m1, m2, m3, m4, m5, m6, m7};

uint8_t outs[8][20];

sha1_multi_avx2(msgs, len, outs);



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

支持 AES-128/256-GCM、ChaCha20-Poly1305、AES-128-CCM 等密码套件，以及 Ed25519、ECDSA P-256/P-384/P-521、RSA-2048/4096（含 RSA-PSS SHA-256/384/512）等多种证书签名算法。



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



#### 1.1 服务端直接加载 PEM / CSR 证书

服务端证书不再需要手工拼 `tls_certificate` 结构体——`tls_certificate` 提供从 PEM 证书、PEM 私钥与 CSR 直接加载的工厂方法：

```cpp
// 从 PEM 证书 + PEM 私钥加载（私钥支持 PKCS#8 / PKCS#1 / SEC1 / RFC 8410 / 加密 PBES2）
std::string err;
auto cert = tls_certificate::from_pem_file("server.crt", "server.key", &err);
if (!cert) { /* err 描述失败原因 */ }

// 也可以直接传 PEM 字符串内容
auto cert2 = tls_certificate::from_pem(cert_pem, key_pem);

// 从 CSR + 私钥加载：subject 与公钥取自 CSR，私钥用于签名
// cert_data 留空，握手时按 CSR 主体自动生成自签名证书
auto cert3 = tls_certificate::from_csr_pem_file("server.csr", "server.key", &err);
```

加载后直接加入 `tls_certificate_manager` 即可用于服务端握手：

```cpp
tls_certificate_manager cert_mgr;
cert_mgr.add_certificate("example.com", std::move(cert));
```

支持密钥类型：RSA-2048、Ed25519、Ed448、ECDSA P-256/P-384/P-521、SM2（RSA-4096 私钥暂不支持 TLS 证书签名）。


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

// 方式 A：cert_manager 按 SNI 查找预期服务器证书（兼容旧行为）

tls13_process_server_flight(client, server_flight.data(), server_flight.size(),

                             client_finished, &cert_mgr);

// 方式 B（推荐）：客户端直接走 x509 链验证——信任库提供 CA 根证书，
// 握手时对服务端证书链执行 x509_verify_chain（含叶子证书主机名匹配），
// 验证失败则握手失败。cert_manager 传 nullptr 即完全依赖信任库。

auto trust = tls_trust_store::from_pem_file("ca.crt"); // 可含多张 CA 根

// 方式 C（默认安全）：不传 trust_store（或 nullptr）→ 只信任系统信任库
// tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
//                              client_finished, nullptr, nullptr);
// tls_connection::connect(host, port) 默认即此行为。

tls13_process_server_flight(client, server_flight.data(), server_flight.size(),

                             client_finished, nullptr, &trust);



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

| `tls13_process_server_flight(s, data, len, out, cert_mgr, trust)` | 客户端处理服务端回包，生成 Client Finished；`trust`（tls_trust_store*）提供时走 x509 链验证 |

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

| `tls_certificate::from_pem(cert_pem, key_pem, err)` | 从 PEM 证书 + PEM 私钥构造服务端证书 |

| `tls_certificate::from_pem_file(cert_path, key_path, err)` | 从证书/私钥 PEM 文件构造 |

| `tls_certificate::from_csr_pem(csr_pem, key_pem, err)` | 从 CSR + 私钥构造（握手时自动生成自签证书） |

| `tls_certificate::from_csr_pem_file(csr_path, key_path, err)` | 从 CSR/私钥 PEM 文件构造 |

| `tls_key_type_to_sig_alg(kt)` | KeyType → TLS 签名方案映射 |

| `tls_trust_store` | 客户端信任库：持有 CA 根证书列表（from_pem / from_pem_file / from_system 系统信任库） |

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



#### 11. QUIC v1 / v2（RFC 9001 / RFC 9369）



QUIC 不使用 TLS 记录层：握手消息直接以原始 TLS Handshake 字节流交付，由 QUIC 封装进

CRYPTO 帧并在 QUIC 数据包保护下传输；应用数据由 QUIC 层（STREAM 帧）加密，不经过 TLS。

jpssl 提供 QUIC 所需的全部 TLS 支持——`quic_transport_parameters` 扩展、无记录层握手、

Initial / 握手 / 1-RTT 数据包保护密钥派生与头部保护掩码。**v1 与 v2 的 TLS 握手完全一致**，

差异仅在初始盐与密钥派生标签（RFC 9369 §3.3）：`tls_quic_*` 函数以 `QuicVersion` 参数区分。



```cpp

#include "tls.hpp"

using namespace jpssl::tls;



// ── 服务端：证书管理器（同 TLS 1.3） ──

tls_certificate_manager cert_mgr;

cert_mgr.add_certificate("example.com", std::move(server_cert));



// ── 客户端：配置 QUIC 传输参数并生成 ClientHello ──

tls_session client;

client.server_name = "example.com";           // SNI

client.quic_version = QuicVersion::V1;        // 或 V2（RFC 9369）

client.quic_transport_params.initial_source_connection_id = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

client.quic_transport_params.initial_max_data = 1048576;      // 流控参数

client.quic_transport_params.initial_max_streams_uni = 100;

std::vector<uint8_t> client_hello;

tls_quic_make_client_hello(client, client_hello);            // 原始握手字节，交给 CRYPTO 帧



// ── 服务端：处理 ClientHello，生成完整回包（SH+EE+Cert+CV+SF，均为原始字节） ──

tls_session server;

server.quic_version = QuicVersion::V1;

server.quic_transport_params.original_destination_connection_id = client.quic_transport_params.initial_source_connection_id;

server.quic_transport_params.initial_source_connection_id = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};

std::vector<uint8_t> server_flight;

tls_quic_make_server_flight(server, client_hello.data(), client_hello.size(), server_flight, cert_mgr);



// ── 客户端：处理回包并生成 Client Finished（trust 提供 CA 根时走 x509 链验证） ──

auto trust = tls_trust_store::from_pem_file("ca.crt");

std::vector<uint8_t> client_finished;

tls_quic_process_server_flight(client, server_flight.data(), server_flight.size(), client_finished, &trust);



// ── 服务端：验证客户端 Finished → 握手完成 ──

tls_quic_process_client_finished(server, client_finished.data(), client_finished.size());



// ── 提取 QUIC 数据包保护密钥（客户端/服务端各自派生，结果逐字节一致） ──

quic_packet_keys cli_hs_key, srv_hs_key, cli_1rtt_key, srv_1rtt_key;

tls_quic_get_handshake_keys(client, client.quic_version, cli_hs_key, srv_hs_key);  // "client in"/"server in"

tls_quic_get_application_keys(client, client.quic_version, cli_1rtt_key, srv_1rtt_key);

// cli_hs_key 用于客户端发送 Handshake 包；srv_hs_key 用于解密服务端 Handshake 包



// ── Initial 密钥（客户端发送第一个 Initial 包前由 DST CID 派生） ──

quic_initial_keys init_keys;

uint8_t dst_cid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};

tls_quic_derive_initial_secrets(client.quic_version, dst_cid, 8, init_keys);



// ── 头部保护掩码（sample 为受保护载荷按 RFC 9001 §5.4 采样的 16 字节） ──

uint8_t mask[5];

tls_quic_header_protection_mask(client.cipher_suite, init_keys.client.hp, 16,

                                sample, 16, mask, 5);

```

服务端在 `tls_quic_make_server_flight` 前必须为 `server.quic_transport_params` 设置

`original_destination_connection_id`（与客户端首包 DST CID 一致）与 `initial_source_connection_id`；

客户端必须设置 `initial_source_connection_id`（RFC 9000 §7.2/§18.2）。

`tls_session.quic_peer_transport_params` 在握手解析后保存对端传输参数（`quic_peer_params_valid`）。

QUIC 模式也可用 `tls13_make_quic_client_hello` / `tls13_make_quic_server_flight` /

`tls13_process_quic_server_flight` / `tls13_process_quic_client_finished` 便捷包装。

> QUIC v1 与 v2 的线格式、版本号（v1=`0x00000001`，v2=`0x6b3343cf`）与包类型位由 QUIC 层负责；

> 本模块仅提供 TLS 部分。Initial 数据包恒用 AEAD_AES_128_GCM + SHA-256，握手/1-RTT 套件

> 由 TLS 协商（AES-128/256-GCM、ChaCha20-Poly1305 等，对应 16/32 字节密钥）。



#### 12. DTLS 1.2 / 1.3（RFC 6347 / RFC 9147）



DTLS 在不可靠的数据报传输（UDP）上提供与 TLS 同等的安全保证。jpssl 提供标准 DTLS

记录层与握手（`include/dtls.hpp` / `src/dtls.cpp`）。



```cpp

#include "dtls.hpp"

using namespace jpssl::dtls;



// ── 服务端：证书管理器（同 TLS 1.3） ──

tls_certificate_manager cert_mgr;

cert_mgr.add_certificate("example.com", std::move(server_cert));



// ── 客户端：配置并完成握手 ──

dtls_session client;

client.ver = DTLSVersion::V13;                 // 或 V12（RFC 6347）

client.server_name = "example.com";

dtls_handshake_input in;                        // datagram=nullptr → 客户端首步

auto step = dtls_handshake_step(client, in);    // 生成 ClientHello 数据报

// 与服务端交换数据报，直到双方 handshake_done：

//   server: dtls_handshake_step(server, in{datagram, cert_manager=&cert_mgr})

//   client: dtls_handshake_step(client, in{datagram, trust_store=&trust})



// ── 应用数据（握手完成后） ──

std::vector<uint8_t> enc = dtls_protect_application(client, (const uint8_t*)"hello", 5);

std::vector<uint8_t> dec;

dtls_unprotect_application(server, enc.data(), enc.size(), dec);

```

`dtls_handshake_step` 是纯数据报状态机（datagram in → datagram out），可嵌入任意传输

（内存、UDP、回调式事件循环）；内部处理记录层加解密、握手消息分片重组、cookie 交换

（DTLS 1.2）、message_seq、Finished 校验与 DTLS 1.3 ACK。



UDP socket 封装（含握手超时重传）：



```cpp

dtls_connection server, client;

server.set_version(DTLSVersion::V13);

server.bind(0, "127.0.0.1");                 // 绑本地端口

uint16_t port = server.local_port();

// 服务端线程：server.server_handshake(cert_mgr);

client.set_version(DTLSVersion::V13);

client.set_server_name("example.com");

client.connect("127.0.0.1", port, &trust);   // 客户端连接并完成握手

client.send((const uint8_t*)"hi", 2);        // 发送应用数据

std::vector<uint8_t> resp; server.recv(resp); // 接收

```

支持：DTLS 1.2（ECDHE-X25519/P-256 + AES-128-GCM/ChaCha20，cookie 可选）与

DTLS 1.3（X25519/P-256/X448 + AES-128/256-GCM/ChaCha20，Ed25519/ECDSA/RSA-PSS 证书）。

> 说明：DTLS 1.3 未实现 HelloRetryRequest 与 Connection ID（RFC 9146）；DTLS 1.2
> cookie 交换默认关闭（`dtls_session::require_cookie = true` 开启）。



### Ed25519



```cpp

#include "ed25519.hpp"



uint8_t pub[32], priv[64];

ed25519_keygen(pub, priv);



uint8_t sig[64];

ed25519_sign(priv, (const uint8_t*)"message", 7, sig);



bool ok = ed25519_verify(pub, (const uint8_t*)"message", 7, sig);

```



批量验证多条签名（共享倍点链 + 128 位随机盲化，任一无效即返回 false）：



```cpp

#include "ed25519_batch.hpp"



bool ok = jpssl::ed25519_batch_verify(

    pub_ptrs,   // const uint8_t*[]，每条 32 字节

    msg_ptrs,   // const uint8_t*[]

    msg_lens,   // size_t[]

    sig_ptrs,   // const uint8_t*[]，每条 64 字节

    count);

```



批量验证按 128 条/块分块，256 条约 10–12 ms（逐条验证约 25 ms），单签名摊销约 41–47 µs。



### ECDSA P-256



```cpp

#include "ecdsa.hpp"



uint8_t pub[64], priv[32];

ecdsa_p256_keygen(pub, priv);



uint8_t sig[64];

ecdsa_p256_sign(priv, (const uint8_t*)"message", 7, sig);



bool ok = ecdsa_p256_verify(pub, (const uint8_t*)"message", 7, sig);

```



ECDSA P-384（SHA-384）与 P-521（SHA-512，即通常所称 "P512"）接口相同，

密钥/公钥/签名为 48/96/96 与 66/132/132 字节：



```cpp

uint8_t pub[132], priv[66], sig[132];

ecdsa_p521_keygen(pub, priv);

ecdsa_p521_sign(priv, (const uint8_t*)"message", 7, sig);

bool ok = ecdsa_p521_verify(pub, (const uint8_t*)"message", 7, sig);

```



### X.509 v3 证书 (RFC 5280)



`x509.hpp` 提供完整的 X.509 v3 证书 DER 编解码、自签名证书生成和证书链验证。支持 RSA-2048/4096、Ed25519、Ed448、ECDSA P-256/P-384/P-521、SM2 七种密钥类型。



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



#### 2. 解析 DER / PEM 证书



```cpp

// 从 DER 字节解析

auto parsed = x509_cert::from_der(der);

// 从 PEM 文本解析 (-----BEGIN CERTIFICATE-----)

auto parsed = x509_cert::from_pem(pem_string);

// 证书编码为 PEM

std::string pem = parsed->to_pem();

if (parsed) {

    std::string cn = parsed->common_name();        // 获取 subject CN

    std::string issuer = parsed->issuer_name();    // 获取 issuer CN

    bool is_ca = parsed->is_ca();                  // 是否 CA 证书

    bool valid = parsed->is_valid_now();           // 是否在有效期内

    auto dns = parsed->dns_names();                // SAN DNS 名称列表

    KeyType kt = parsed->key_type;                 // 密钥类型

}

```



#### 3. 读取私钥 / CSR (PEM)



```cpp

// 私钥读取: 自动识别 PKCS#8 / PKCS#1 RSA / SEC1 EC / RFC 8410 (Ed25519/Ed448)

//   -----BEGIN PRIVATE KEY----- / RSA PRIVATE KEY / EC PRIVATE KEY

//   -----BEGIN ED25519 PRIVATE KEY----- / ED448 PRIVATE KEY-----

auto key = private_key::from_pem(key_pem);

if (key) {

    KeyType kt = key->key_type;       // 密钥类型

    auto& priv = key->priv;           // 私钥原始字节 (与 x509_builder::build_and_sign 兼容)

    auto& pub  = key->pub;            // 公钥原始字节 (解析时从密钥中恢复)

}

// 支持 DER 输入: private_key::from_der(...)

// 加密私钥读取 (PBES2, -----BEGIN ENCRYPTED PRIVATE KEY-----)

//   PBKDF2-HMAC-SHA256 + AES-128/256-CBC (RFC 8018)

auto enc_key = private_key::from_pem_encrypted(enc_pem, "password");

// CSR 读取 (PKCS#10, -----BEGIN CERTIFICATE REQUEST-----)

auto req = csr::from_pem(csr_pem);

if (req) {

    auto& subject = req->subject;     // DistinguishedName

    KeyType kt = req->key_type;       // 公钥类型

    auto& pub = req->public_key;      // 公钥原始字节

    auto& sig = req->signature;       // 签名原始字节

    auto& tbs = req->tbs_raw;         // CertificationRequestInfo 原始字节 (供验签)

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

服务端证书可直接从 PEM / CSR 加载（见上文 [1.1 服务端直接加载 PEM / CSR 证书](#11-服务端直接加载-pem--csr-证书)）；客户端可通过 `tls_trust_store` 对服务端证书链执行 `x509_verify_chain` 验证（含叶子主机名匹配）。



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

│   ├── sha1.hpp                 SHA-1

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

│   ├── aes_gcm_avx2.cpp / aes_gcm_avx512.cpp / aes_gcm_auto.cpp / aes_gcm_neon.cpp

│   ├── chacha20_poly1305.cpp / chacha20_neon.cpp / chacha20_gpu.mu

│   ├── rsa.cpp / rsa_body.inc / rsa_musa.cpp / rsa_gpu.mu

│   ├── sha1.cpp / sha1_avx2.cpp / sha1_avx512.cpp / sha1_neon.cpp

│   ├── sha256.cpp / sha256_neon.cpp / sha3.cpp

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

| `JP_ENABLE_NEON` | ON | ARM NEON/crypto 加速（aarch64：AES-GCM / ChaCha20 / SHA-1 / SHA-256 / SHA-512 / SHA-3 / SM3 / SM4） |

| `JP_ARM_MARCH` | `armv8.2-a` | ARM 架构等级：`armv8-a` / `armv8.1-a` / `armv8.2-a` / `armv8.4-a` / `armv9-a`（仅影响 NEON 源；SHA-512/SHA-3/SM3/SM4 扩展源默认以 `armv8.4-a+crypto` 编译，运行时按 FEAT_* 检测回退标量） |



```bash

# 启用 MUSA GPU 加速 (需要 MUSA SDK 4.3.0+)

cmake -B build -DJP_ENABLE_MUSA=ON



# ARM (macOS Apple Silicon / Linux aarch64)：启用 NEON 加速并指定架构等级

cmake -B build -DJP_ENABLE_NEON=ON -DJP_ARM_MARCH=armv9-a



# ARM Linux 交叉编译（在 x86 宿主机上构建 ARM64 目标）

#   Ubuntu/Debian 宿主机先安装交叉工具链：

#     sudo apt-get install g++-aarch64-linux-gnu

cmake -B build-arm64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake



# 在 ARM Linux 机器上原生构建（aarch64 自动启用 NEON，无需 toolchain）

cmake -B build -DCMAKE_BUILD_TYPE=Release



# 禁用所有 SIMD 加速（纯标量回退）

cmake -B build -DJP_ENABLE_AVX2=OFF -DJP_ENABLE_AVX512=OFF -DJP_ENABLE_NEON=OFF

```



## 依赖



- **C++20** (GCC 13+ / Clang 16+)

- **CMake** 3.20+

- **OpenSSL** (仅部分测试目标需要，用于与 OpenSSL 结果对比)

- **MUSA SDK** 4.3.0+ (可选，实验性 GPU 加速，默认关闭，通过 `-DJP_ENABLE_MUSA=ON` 启用)

- **x86_64** (AES-NI / AVX2 / AVX512, 可选)

- **aarch64** (macOS Apple Silicon / Linux ARM64, NEON 可选)



## 国密证书透明 (SM2 CT)



`include/ct.hpp` / `src/ct.cpp` 提供基于 RFC 6962 框架、以 SM2/SM3 替代

ECDSA/SHA-256 的国密证书透明实现（参考 GM/T《证书透明规范》草案）：



- SM3 默克尔树：根哈希 / 审计路径 / 一致性证明（`verify_consistency` 按

  RFC 9162 §2.1.4.2 实现）；

- SM2 标准签名（GB/T 32918，默认 ID `1234567812345678` 计算 ZA）；

- PreCert / MerkleTreeLeaf / SCT / STH 的 TLS 风格编解码；

- X.509 集成：LogID、precert poison / SCT list 扩展、`finalize_precert`；

- 内存日志 `sm2_ct_log`：add-pre-chain / add-chain / get-sth /

  get-proof-by-hash / get-entries / get-sth-consistency。



`include/base64.hpp` / `src/base64.cpp` 提供 RFC 4648 base64 编解码。



> 注：`DigitallySigned` 中的算法字节当前为占位值

> （`CT_HASH_ALG_SM3 = 0x04`、`CT_SIG_ALG_SM2 = 0x04`），草案未定稿，

> 与外部国密 CT 日志互操作前需核对字节值。



## TLS socket 封装层



`include/tls_socket.hpp` / `src/tls_socket.cpp` 在消息级 TLS API 之上提供

跨平台（Windows Winsock / Linux POSIX）的 TLS-over-TCP 封装：



- `tls::tls_connection`：客户端 `connect(host, port, trust_store)` 或服务端

  `server_handshake(cert_manager)` 完成 TLS 1.3 握手；`send` / `recv` 收发加密应用数据。

  客户端默认**只信任系统信任库**中的 CA 根证书：不传 trust_store（或传 nullptr）时，

  自动通过 `tls_trust_store::from_system()` 加载系统 CA bundle

  （`SSL_CERT_FILE` 环境变量 → `/etc/ssl/certs/ca-certificates.crt` 等常见路径），

  对服务端证书链执行 x509 验证（含主机名匹配），验证失败或系统信任库不可用则握手失败。

  也可显式传 `tls_certificate_manager*`（按 SNI 查找预期证书的旧行为）或

  `tls_trust_store&`（自定义 CA 根）。

- `tls::tls_listener`：`listen(port)` + `accept(conn, cert_manager)`，

  接受连接并自动完成服务端握手。

- record 层自动处理半包/粘包、握手消息封装与加密 record 透传。

### 外部 fd 托管

`tls_connection` / `tls_listener` 均可托管调用方已创建的外部 socket 句柄
（事件循环 / epoll / 自建连接等场景），并可选择是否持有句柄所有权：

```cpp
// 客户端：手动建立 TCP 连接后托管，再在已有 socket 上做 TLS 握手
int fd = socket(AF_INET, SOCK_STREAM, 0);
connect(fd, ...);                       // 调用方自己建连
tls::tls_connection conn;
conn.attach(fd, /*take_ownership=*/true, &err);
conn.client_handshake("example.com", &trust, &err);  // 不重建 TCP
conn.send("GET / HTTP/1.1\r\n\r\n", &err);

// 借用模式：close() 不关闭外部 fd，生命周期由调用方管理
tls::tls_connection borrowed;
borrowed.attach(fd, false, &err);       // owns_socket() == false
borrowed.server_handshake(cert_mgr, &err);
borrowed.close();                        // fd 仍有效，调用方自行释放
```

- `attach(fd, take_ownership=true)`：接管已 connect 的 TCP / accept 出的连接 /
  已 connect 或已 bind 的 UDP socket；对 `SOCK_DGRAM` 句柄自动启用数据报模式。
- `client_handshake(host, ...)`：在已托管的 socket 上执行客户端握手
  （原 `connect()` 会自行建立 TCP 连接，不适用于外部 fd）。
- `tls_listener::attach(fd, ...)`：托管外部监听 socket（TCP 已 listen / UDP 已 bind）。

### UDP 链接（数据报模式）— ⚠️ 非标准，存在缺陷，仅限自研两端互通

`tls_connection` 支持在 UDP 上承载 TLS（数据报模式）：每条 TLS record
（含握手消息）封装为一个 UDP 数据报发送——UDP 发送是原子的，整包成功或失败，
单条 record 上限 16KiB+256 远小于 64KiB 数据报上限；`send()` 对大消息自动分片
为多个数据报，`recv()` 自动合并还原，握手与 TCP 模式共用同一套 record 逻辑。

```cpp
// 服务端：绑定 UDP 端口，接收首个 ClientHello 后固定对端并完成握手
tls::tls_listener udp_listener;
udp_listener.listen_udp(8443, "0.0.0.0", &err);
tls::tls_connection conn;
udp_listener.accept_udp(conn, cert_mgr, &err);   // 监听 socket 转交给 conn
conn.send("hello over udp", &err);

// 客户端：手动创建已 connect 的 UDP socket 后托管
int ufd = socket(AF_INET, SOCK_DGRAM, 0);
connect(ufd, ...);                      // 固定服务端地址
tls::tls_connection client;
client.attach(ufd, true, &err);         // 自动检测 SOCK_DGRAM -> 数据报模式
client.client_handshake("example.com", &trust, &err);
std::vector<uint8_t> resp;
client.recv(resp, &err);
```

- `is_datagram()`：是否数据报模式（`attach` 对 UDP 自动启用，也可用
  `set_datagram_mode(true)` 显式覆盖，仅接受 `SOCK_DGRAM` 句柄）。
- `tls_listener::listen_udp(port, addr)` + `accept_udp(conn, cert_mgr)`：
  UDP 服务端入口。`accept_udp` 用监听 socket 本身 `connect` 固定对端
  （保持源端口不变，客户端才能收到回复），随后把 socket 转交给 `conn`，
  一个 UDP listener 同一时刻服务一个客户端。
#### ⚠️ 已知缺陷（与标准 DTLS / QUIC 不互通）

本数据报模式是**自研的简化封装，不是标准 DTLS，也不是 QUIC**：

- **非标准协议，无互操作性**：报文格式与 `DTLS`（RFC 6347/9147）和
  `QUIC`（RFC 9000）完全不同，无法与 OpenSSL、Wireshark、浏览器等标准
  实现互通，仅限本库客户端与服务端之间使用。
- **无抗 DoS 机制**：缺少 DTLS 的 `HelloVerifyRequest` 无状态 cookie，
  服务端对任意伪造源地址的 ClientHello 都会建立会话状态。
- **无握手分片 / 重传 / 乱序重组**：握手消息不按 `message_seq` 分片编号，
  无 flight 超时重传；UDP 丢包（尤其大证书链跨多个数据报时）直接导致
  握手失败（受 `set_handshake_timeout` 约束），由调用方重试整个握手。
- **无防重放**：应用数据记录不带 epoch/sequence 滑动窗口，重放的旧数据报
  会被当作新数据接受。

**标准 DTLS 1.2/1.3 已在本次发布提供**（见「TLS 1.2/1.3」小节第 12 点「DTLS 1.2/1.3」），
建议新代码直接使用标准 DTLS。`QUIC` 传输层（CRYPTO/STREAM 帧、连接迁移、
拥塞控制）与 `HTTP/3`（RFC 9000/9114）仍列入后续版本计划。
QUIC 所需的 TLS 层支持已提供（见「TLS 1.2/1.3」小节第 11 点「QUIC v1/v2」）。
在此之前，UDP 场景请评估上述缺陷，
并优先考虑使用 TCP + TLS 或标准 DTLS 实现。
### 非阻塞模式（事件循环）

`tls_connection` / `tls_listener` 支持非阻塞模式，便于在单线程事件循环中复用同一线程服务大量连接：

```cpp
tls_listener listener;
listener.listen(443, "0.0.0.0");
listener.set_nonblocking(true);          // 无连接时 accept 返回 would-block

for (;;) {
    tls_connection conn;
    if (!listener.accept(conn, cert_mgr)) {
        if (listener.would_block()) { listener.wait_readable(100); continue; }
        break;                           // 真实错误
    }
    // accept 出的连接继承非阻塞状态
    std::vector<uint8_t> msg;
    if (!conn.recv(msg)) {
        if (conn.would_block()) { conn.wait_readable(100); continue; } // 暂无数据
        break;
    }
    if (!conn.send("HTTP/1.1 200 OK\r\n\r\n")) {
        if (conn.would_block()) conn.wait_writable(100);
    }
}
```

- `set_nonblocking(true)` 可在 `connect` / `listen` 之前调用，socket 创建时自动应用；非阻塞 `connect` 走 `EINPROGRESS` + poll 等待可写 + `SO_ERROR` 检查。
- `send()` / `recv()` 遇 `EAGAIN/EWOULDBLOCK` 立即返回 `false`，经 `would_block()` 判定后连接保持打开，配合 `wait_readable()` / `wait_writable()` 重试。
- 握手阶段为有界等待（`set_handshake_timeout`，默认 30 秒），不会永久阻塞。
- 可运行示例：`examples/tls_socket/nonblocking_echo`（非阻塞监听 + 收发事件循环回环）。

### 协程 I/O（C++20）

应用数据收发可写成协程：`co_send` / `co_recv` 在 socket 暂不可用时挂起，由执行器 `tls_co_executor` 在可读/可写时恢复，不阻塞任何线程：

```cpp
tls_co_executor ex;                      // 单线程 poll 驱动执行器，多连接共享

tls_connection conn;
conn.set_nonblocking(true);
conn.attach_co_executor(&ex);

tls_co_task<void> session() {            // 顶层协程任务（由持有者析构清理）
    bool ok = co_await conn.co_send("GET / HTTP/1.1\r\n\r\n");
    std::vector<uint8_t> resp;
    co_await conn.co_recv(resp);
}
auto task = session();
ex.run();                                // 驱动：poll 就绪并恢复挂起协程
```

- `tls_co_task<T>`：泛型协程任务（热启动 + 对称转换，零外部依赖）。
- `tls_co_executor`：单线程 poll 驱动执行器，多个连接共享；`run_once()` / `run()` 在 socket 就绪时恢复挂起协程。
- `co_send` / `co_recv` 语义与 `send` / `recv` 一致（自动分片/合并 record、跳过 NewSessionTicket）；使用前需 `set_nonblocking(true)` 并 `attach_co_executor(&ex)`。
- 可运行示例：`examples/tls_socket/coroutine_echo`（双端协程回环）。





## 国际证书透明（RFC 6962）+ HTTPS 示例



`ct_log` 支持两种算法组合：



- 国密：`sm2_ct_log(priv, pub)`（SM3 默克尔树 + SM2 签名，GM/T 草案）；

- 国际标准：`ct_log(CtHashAlg::SHA256, CtSigAlg::ECDSA_P256, priv, pub)`

  （SHA-256 默克尔树 + ECDSA P-256 签名，LogID = SHA-256(SPKI)，RFC 6962）。

- RSA：`ct_log(rsa_crt_key, rsa_public_key)`（SHA-256 + RSA-2048 PKCS#1 v1.5，

  signature_algorithm = rsa），或直接使用 `issue_sct_rsa` / `verify_sct_rsa` /

  `sign_sth_rsa` / `verify_sth_rsa`。



`examples/https/` 提供 HTTPS 服务器与客户端示例：



```bash

# 终端 1：启动 HTTPS + CT 服务器（默认 8443）

./https_server 8443



# 终端 2：客户端执行证书链 / SCT / STH / 包含性证明审计

./https_client 127.0.0.1 8443

```



服务器内嵌内存 CT 日志，为 ECDSA 服务器证书签发 SCT 并暴露

`/ct/cert`、`/ct/precert`、`/ct/ca`、`/ct/log-key`、`/ct/sth`、`/ct/proof`

等审计端点；客户端通过 TLS 1.3 连接完成全部 CT 校验。



### 修复的缺陷



- `tls13_make_new_session_ticket`：`rand32` 固定写 32 字节，原代码写入

  4 字节局部变量导致栈溢出（MSVC C4789 已静态证明），改为 32 字节缓冲。

- `rsa_bignum::from_bytes`：无边界检查，RSA-4096 路径传入 512 字节会写穿

  256 字节的 `rsa_bignum`，现按类型容量钳制长度。

- `encode_tlv` / `encode_bit_string`：空数据时对 `nullptr` 做 `+0` 指针

  运算（UB），增加长度守卫。

- `sha256_sha_ni.cpp`：实现整体被 `#ifdef __x86_64__` 保护，MSVC 不定义

  该宏导致静态库缺失 `sha256_sha_ni` 符号（bench_hardware_accel 链接失败），

  改为 `__x86_64__ || _M_X64`。


