# 快速开始

## 环境要求

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| C++ 编译器 | GCC 13+ / Clang 16+ / MSVC（VS 2019 16.10+ 或 VS 2022+） | C++20 标准，`CMAKE_CXX_STANDARD=20` |
| CMake | 3.20+ | 构建系统 |
| OpenSSL | 可选 | 仅部分测试 / 基准的对比目标需要，库本身不依赖 |
| MUSA SDK | 4.3.0+（可选） | 实验性 GPU 加速，默认关闭，仅 Linux |
| 硬件 | x86_64（桌面） | AES-NI / AVX2 / AVX-512 / SHA-NI / BMI2+ADX 可选；ARM64 走 NEON/crypto 路径 |
| 平台 | Linux / Windows / macOS / iOS / Android / HarmonyOS | 各平台构建见 [平台构建](Platform-Builds) |

## Linux / macOS 构建

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

启用 MUSA GPU 加速（实验性，仅 Linux，需要 MUSA SDK 4.3.0+）：

```bash
cmake .. -DCMAKE_BUILD_TYPE=Release -DJP_ENABLE_MUSA=ON
```

运行主测试程序与全部单元测试：

```bash
# 运行主测试程序
LD_LIBRARY_PATH=/usr/local/musa/lib ./jpssl-test

# 运行全部单元测试（CTest，目标定义在 tests/CMakeLists.txt）
LD_LIBRARY_PATH=/usr/local/musa/lib ctest --output-on-failure
```

安装到系统（可选，安装命令行工具 `jpssl-cert` / `jpssl-crypt` 到 `bin/`）：

```bash
sudo make install
```

## Windows 构建（MSVC）

支持 Windows x64 + MSVC（VS 2019 16.10+ / VS 2022+ / Build Tools），通过 CMake + Ninja 或 VS 解决方案构建。请在 **"x64 Native Tools Command Prompt"** 或 **Developer PowerShell** 中执行：

```powershell
# Ninja 生成器
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win

# 或直接生成 VS 工程
# cmake -S . -B build-win -G "Visual Studio 17 2022" -A x64

# 运行测试
ctest --test-dir build-win --output-on-failure
```

## 链接到你的项目

构建默认同时生成静态库和动态库：

| 库文件 | 类型 | 说明 |
|--------|------|------|
| `libjpssl_cpu.a` | 静态库 | CPU 密码学库（Linux） |
| `libjpssl_cpu.so` | 动态库 | CPU 密码学库（Linux 共享） |
| `libjpssl_musa.a` / `libjpssl_musa.so` | GPU 库 | MUSA GPU 加速库（仅启用 `JP_ENABLE_MUSA`） |
| `jpssl_cpu_static.lib` | 静态库 | Windows 静态库（避免与导入库同名冲突） |
| `jpssl_cpu.dll` / `jpssl_cpu.lib` | 动态库 | Windows 共享库及导入库 |

命令行链接动态库：

```bash
g++ -std=c++20 your_app.cpp -I./include -L./build -ljpssl_cpu -o your_app
LD_LIBRARY_PATH=./build ./your_app
```

使用 CMake 的 `FetchContent` 或 `add_subdirectory` 引入时，链接目标为 `jpssl_cpu`（静态）或 `jpssl_cpu_shared`（动态），头文件目录 `include/` 已通过 `target_include_directories(... PUBLIC ...)` 传播。

## 下一步

- 查看 [构建选项与产物](Build-Options) 了解所有 CMake 开关
- 查看 [算法支持总览](Algorithm-Support) 了解支持的算法
- 查看 [命令行工具](Command-Line-Tools) 快速体验 `jpssl-cert` / `jpssl-crypt`
