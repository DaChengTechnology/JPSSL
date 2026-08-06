# aarch64-linux-gnu.cmake — 交叉编译 toolchain：ARM64 (AArch64) Linux
#
# 用法（Ubuntu/Debian 宿主机）：
#   sudo apt-get install g++-aarch64-linux-gnu
#   cmake -B build-arm64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake
#
# 目标：64 位 ARM Linux（ARMv8+，NEON 必选，AES/PMULL/SHA 等 crypto 扩展可选）。
# NEON 加速源默认按 -march=armv8.2-a+crypto 编译，可通过 -DJP_ARM_MARCH 调整。

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

# 32 位 __int128 依赖的底层类型在 AArch64 上原生支持，无需额外兼容层
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
