# 新手引导

本页是 JPSSL 的入门地图：从零开始，带你完成「获取代码 → 构建 → 运行第一个程序 → 找到需要的文档」全流程。如果你是第一次接触这个项目，建议按顺序阅读；如果只是查某个具体问题，可以直接跳到[常见问题](#常见问题)。

## JPSSL 是什么？

JPSSL 是一个用 C++ 编写的高性能跨平台密码学库（要求 C++20），提供对称加密、哈希 / MAC / KDF、非对称加密、X.509 证书、TLS / DTLS 等能力，并内置国密（SM2 / SM3 / SM4）支持。它面向的是**开发者**：你通过 `#include` 头文件、链接库来使用它，而不是把它当作一个现成的加密工具。

快速了解它的定位与能力，见[首页](Home)的「特性一览」与[算法支持总览](Algorithm-Support)。

> 只想临时加密文件 / 生成证书？可以跳过 C++ 部分，直接使用附带的命令行工具 `jpssl-cert` 与 `jpssl-crypt`（见[命令行工具](Command-Line-Tools)）。

## 学习路线

| 阶段 | 目标 | 文档 |
|------|------|------|
| 1 | 了解功能与算法支持 | [首页](Home)、[算法支持总览](Algorithm-Support) |
| 2 | 准备环境、构建库 | 本页 + [快速开始](Getting-Started) |
| 3 | 运行第一个程序 | 本页「第一个程序」 |
| 4 | 用命令行工具快速体验 | [命令行工具](Command-Line-Tools) |
| 5 | 在自己的项目里使用 API | [对称加密 API](API-Symmetric)、[哈希 / MAC / KDF API](API-Hash-MAC-KDF)、[非对称加密 API](API-Asymmetric)、[X.509 证书 API](API-X509)、[TLS API](API-TLS)、[TLS socket 封装层](API-TLS-Socket) |
| 6 | 进阶：性能、测试、GPU | [性能基准](Benchmarks)、[测试与 CI](Testing)、[MUSA GPU 加速](MUSA-GPU)、[ECDSA 性能与 SIMD 可行性](ECDSA-SIMD-Feasibility) |

## 环境要求

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| C++ 编译器 | 支持 C++20：GCC 13+ / Clang 16+ / MSVC（VS 2019 16.10+ 或 VS 2022+） | 库与公共头文件基于 C++20（`std::span`、`consteval` 等） |
| CMake | 3.20+ | 构建系统 |
| OpenSSL | 可选 | 仅部分测试 / 基准的对比目标需要，库本身不依赖 |
| MUSA SDK | 4.3.0+（可选） | 实验性 GPU 加速，默认关闭，仅 Linux |
| 平台 | Linux / Windows / macOS / iOS / Android / HarmonyOS | 各平台构建见[平台构建](Platform-Builds) |

## 第 1 步：获取代码

```bash
git clone https://github.com/DaChengTechnology/JPSSL.git
cd JPSSL
```

## 第 2 步：构建

### Linux / macOS

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```

### Windows（MSVC）

在 **x64 Native Tools Command Prompt** 或 **Developer PowerShell** 中执行：

```powershell
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
```

没有 Ninja 时可以直接生成 VS 工程：

```powershell
cmake -S . -B build-win -G "Visual Studio 17 2022" -A x64
cmake --build build-win --config Release
```

构建产物与更多 CMake 选项见[构建选项与产物](Build-Options)。

## 第 3 步：运行测试（可选但推荐）

```bash
ctest --test-dir build --output-on-failure          # Linux / macOS
ctest --test-dir build-win --output-on-failure      # Windows
```

全部通过说明环境与构建没有问题。

## 第 4 步：运行你的第一个程序

把下面的代码保存为 `hello.cpp`。它演示两件最常见的事：计算 SHA-256 哈希，以及用 AES-256-GCM 加密并解密一段数据（GCM 是带认证的 AEAD 模式，适合绝大多数场景）。

```cpp
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "aes.hpp"
#include "rand_os.hpp"
#include "sha256.hpp"

int main() {
    // 1) SHA-256 哈希
    const char* msg = "hello jpssl";
    uint8_t digest[32];
    jpssl::sha256(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg), digest);
    std::printf("sha256(\"%s\") = %s\n", msg, jpssl::sha256_hex(digest).c_str());

    // 2) AES-256-GCM 认证加密 / 解密
    uint8_t key[32], iv[12], tag[16];
    if (!jpssl::os_rand_bytes(key, sizeof key) ||
        !jpssl::os_rand_bytes(iv, sizeof iv)) {
        std::fprintf(stderr, "os_rand_bytes failed\n");
        return 1;
    }

    jpssl::aes_context ctx;
    ctx.init(std::span<const uint8_t, 32>(key));

    const char* plaintext = "Hello, JPSSL!";
    std::vector<uint8_t> plain(plaintext, plaintext + std::strlen(plaintext));
    std::vector<uint8_t> ct, recovered;

    jpssl::aes_gcm_encrypt(ctx, iv, sizeof iv, plain, {}, ct, tag);
    bool ok = jpssl::aes_gcm_decrypt(ctx, iv, sizeof iv, ct, {},
                                     tag, sizeof tag, recovered);

    std::printf("aes-256-gcm decrypt: %s\n",
                ok && recovered == plain ? "OK" : "FAILED");
    return ok && recovered == plain ? 0 : 1;
}
```

### 编译运行

Linux / macOS（动态链接）：

```bash
g++ -std=c++20 -O2 hello.cpp -Iinclude -Lbuild -ljpssl_cpu -o hello
LD_LIBRARY_PATH=build ./hello
```

Windows（x64 Native Tools / Developer PowerShell，静态链接）：

```powershell
cl /std:c++20 /utf-8 /EHsc /O2 /MD /Iinclude hello.cpp build-win\jpssl_cpu_static.lib bcrypt.lib
.\hello.exe
```

Windows 动态链接（运行前把 `build-win` 加入 PATH，或把 `jpssl_cpu.dll` 复制到 exe 旁边）：

```powershell
cl /std:c++20 /utf-8 /EHsc /O2 /MD /Iinclude hello.cpp build-win\jpssl_cpu.lib
.\hello.exe
```

预期输出（哈希值固定，可用来确认结果正确）：

```
sha256("hello jpssl") = 59970df8f7466760058b3eb217af6db67abb9a7d95c30213ce150c8e84b0af3e
aes-256-gcm decrypt: OK
```

### 集成到 CMake 项目（推荐）

用 `add_subdirectory` 或 `FetchContent` 引入后，头文件目录与系统库（Windows 上的 `bcrypt` / `ws2_32` / `crypt32`）会自动传播，不需要手动配置：

```cmake
add_subdirectory(JPSSL)
target_link_libraries(your_app PRIVATE jpssl_cpu)           # 静态库
# target_link_libraries(your_app PRIVATE jpssl_cpu_shared)  # 动态库
```

## 第 5 步：用命令行工具快速体验

不想写代码时，可以直接使用构建出的两个工具：

```bash
# 生成自签名证书（ed25519）
jpssl-cert gen --cn example.com --key-type ed25519

# AES-256-GCM 加密文件（密钥以十六进制传入）
jpssl-crypt encrypt --algo aes256gcm --key <hex-key> --in plain.txt --out cipher.bin

# 计算 SHA-256
jpssl-crypt hash --algo sha256 --in file.txt
```

完整用法见[命令行工具](Command-Line-Tools)。

## 常见问题

**Q：报错说找不到 `std::span` 或 `consteval`？**
A：库要求 C++20。用 CMake 构建时项目已自动设置；手动编译请加 `-std=c++20`（GCC / Clang）或 `/std:c++20`（MSVC）。

**Q：MSVC 编译时出现 C4819 警告（中文注释乱码）？**
A：源文件按 UTF-8 处理即可，手动用 `cl` 编译时加 `/utf-8`。通过 CMake 构建时项目已全局添加该选项。

**Q：Windows 静态链接报 LNK2038 RuntimeLibrary 不匹配？**
A：库是用 `/MD`（动态 CRT）构建的，手动编译时请加 `/MD` 保持一致。

**Q：链接报找不到 `BCryptGenRandom` 等符号？**
A：Windows 需要链接 `bcrypt.lib`（TLS socket 还需要 `ws2_32.lib`，X.509 还需要 `crypt32.lib`）。用 CMake target 引入时这些会自动处理。

**Q：密钥 / IV 应该从哪里来？**
A：用 `jpssl::os_rand_bytes()`（Windows 走 `BCryptGenRandom`，Linux 走 `/dev/urandom`）。不要用 `std::random_device` 生成密钥——MSVC 上的实现是确定性的。

**Q：需要自己写 CPUID 检测来启用硬件加速吗？**
A：不需要。库在运行时自动按 CPU 特性分派（AES-NI / AVX2 / AVX-512 / SHA-NI 等），不支持的 CPU 会自动回退，见[构建选项与产物](Build-Options)。

**Q：MUSA GPU 加速怎么用？**
A：实验性功能，默认关闭、仅 Linux、需要 MUSA SDK 4.3.0+，构建时加 `-DJP_ENABLE_MUSA=ON`。详见[MUSA GPU 加速](MUSA-GPU)。

**Q：链接时用哪个库？**
A：`jpssl_cpu`（静态）或 `jpssl_cpu_shared`（动态）。命令行工具 `jpssl-cert` / `jpssl-crypt` 在 `make install` 后位于 `bin/`。

**Q：使用密码学时要注意什么？**
A：几条基本建议：优先使用 AEAD 模式（如 AES-GCM / ChaCha20-Poly1305 / SM4-GCM）；**永远不要用同一个 nonce / IV 加密两条不同的消息**；不要用无认证的 ECB 模式加密多块数据；密钥与 IV 用随机源生成。库的接口已经尽量降低误用风险，但正确使用仍是调用方的责任。

## 下一步

- 想了解所有 API 与示例：从[对称加密 API](API-Symmetric)和[哈希 / MAC / KDF API](API-Hash-MAC-KDF)开始，再到[非对称加密 API](API-Asymmetric)
- 想跑 HTTPS / TLS：先看[TLS API](API-TLS)与[TLS socket 封装层](API-TLS-Socket)，以及 `examples/` 目录下的完整示例
- 想了解性能与正确性保证：[性能基准](Benchmarks)、[测试与 CI](Testing)
- 想了解国密支持：[算法支持总览](Algorithm-Support)与 [RFC 8998 国密套件](API-TLS)
