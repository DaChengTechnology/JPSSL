# ios-arm64.cmake — Apple iOS 交叉编译 toolchain：仅 arm64（ARMv8），最低 iOS 13.0
#
# 用法（macOS + Xcode，需有命令行工具，可用 clang 交叉编译）：
#
#   # 真机（iPhone/iPad, arm64）：
#   cmake -B build-ios-device -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/ios-arm64.cmake \
#         -DIOS_SDK=iphoneos
#   cmake --build build-ios-device
#
#   # 模拟器（Apple Silicon Mac 的 arm64 模拟器）：
#   cmake -B build-ios-sim -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/ios-arm64.cmake \
#         -DIOS_SDK=iphonesimulator
#   cmake --build build-ios-sim
#
# 特性：
#   - 架构锁定 arm64（ARMv8，64 位），不含 armv7 / x86_64 slice；
#   - 最低部署版本 iOS 13.0（首版只支持 64 位设备的系统，天然 ≥ ARMv8）；
#   - NEON 源按 -march=armv8-a+crypto 编译（可用 -DJP_ARM_MARCH 覆盖），
#     最低卡在纯 ARMv8.0，SHA-512/SHA-3/SM3/SM4 扩展源单独 armv8.4-a
#     + 运行时 cpu_features 分派，低版本芯片安全回退标量；
#   - OpenMP / MUSA 默认关闭（Apple Clang 无内置 libomp，iOS 无 GPU 后端）。

set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_SYSTEM_VERSION 13.0)
set(CMAKE_SYSTEM_PROCESSOR arm64)

if(NOT DEFINED IOS_SDK)
    set(IOS_SDK iphoneos)
endif()

# 定位指定 iOS SDK 的路径（xcrun --sdk <sdk> --show-sdk-path）
execute_process(
    COMMAND xcrun --sdk ${IOS_SDK} --show-sdk-path
    OUTPUT_VARIABLE IOS_SDK_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE IOS_SDK_ERR
)
if(NOT IOS_SDK_PATH)
    message(FATAL_ERROR "无法定位 iOS SDK '${IOS_SDK}'，请确认已安装 Xcode：${IOS_SDK_ERR}")
endif()

# 使用 Apple Clang（Darwin.cmake 会根据下面的 CMAKE_OSX_* 自动加
# -arch arm64 -isysroot <sdk> -mios-version-min=13.0）
set(CMAKE_C_COMPILER   /usr/bin/clang)
set(CMAKE_CXX_COMPILER /usr/bin/clang++)
set(CMAKE_ASM_COMPILER /usr/bin/clang)

set(CMAKE_OSX_SYSROOT          ${IOS_SDK_PATH})
set(CMAKE_OSX_ARCHITECTURES    "arm64")
set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0")

# 禁止 CMake 尝试在宿主机上找系统库/头文件（交叉编译必需）
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# iOS 无 MUSA/OpenMP 后端
set(JP_ENABLE_MUSA OFF CACHE BOOL "" FORCE)
set(JP_ENABLE_OPENMP OFF CACHE BOOL "" FORCE)

# 最低卡 ARMv8（默认），可用 -DJP_ARM_MARCH=armv8.2-a/armv8.4-a/armv9-a 覆盖
if(NOT DEFINED JP_ARM_MARCH)
    set(JP_ARM_MARCH "armv8-a" CACHE STRING "ARM architecture level for NEON sources")
endif()
