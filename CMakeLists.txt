cmake_minimum_required(VERSION 3.20)

project(jpssl VERSION 1.1.0 LANGUAGES CXX)

# 汇编源需要 GNU/Apple 汇编器支持：
#   ARMv8：src/ecp_nistz256_arm.S
#   x86-64：src/ecdsa_p256_adx.S（GNU as，GCC/Clang）
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" OR
   (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64" AND NOT MSVC))
    enable_language(ASM)
endif()

# ── HarmonyOS / OpenHarmony (鸿蒙) ────────────────────────────────────────
# 由 cmake/toolchains/ohos.cmake（或 NDK 自带 ohos.toolchain.cmake）注入，
# CMAKE_SYSTEM_NAME 为 "OHOS"。鸿蒙 native 模块只产出 .so/.a：
#   - 只构建 libjpssl_cpu(.a/.so)，测试/命令行工具/示例/基准全部跳过
#     （OpenHarmony NDK 不提供可执行文件链接运行时）
#   - MUSA GPU 加速仅支持 Linux，鸿蒙上自动禁用
#   - NEON/crypto 硬件加速按 arm64-v8a / x86_64 走既有 aarch64/x86_64 分支
if(CMAKE_SYSTEM_NAME STREQUAL "OHOS")
    set(JP_OHOS TRUE)
    # NDK toolchain 未设置处理器时按 OHOS_ARCH 归一化，保证下方匹配分支生效
    if(OHOS_ARCH STREQUAL "arm64-v8a" AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(CMAKE_SYSTEM_PROCESSOR aarch64)
    elseif(OHOS_ARCH STREQUAL "x86_64" AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        set(CMAKE_SYSTEM_PROCESSOR x86_64)
    endif()
    message(STATUS "目标平台: HarmonyOS/OpenHarmony (OHOS), ABI=${OHOS_ARCH}, STL=${OHOS_STL}")
endif()

# ── CTest ───────────────────────────────────────────────────────────────
include(CTest)
enable_testing()

# ── C++20 ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    # Windows (MSVC) 全局编译选项：
    #   /utf-8  源文件为 UTF-8（中文注释），避免 C4819 警告与字符串字面量错乱
    #   /bigobj 大翻译单元（tls.cpp 等）避免 C1128 对象文件段溢出
    #   /EHsc   C++ 异常
    #   /FI     强制包含 Windows 平台兼容层（jp_uint128 / __builtin_bswap32 等）
    #           注意：文件名无空格，不加引号（Ninja 下 /FI"x" 会转义成字面 \"x\"）
    add_compile_options(/utf-8 /bigobj /EHsc /FIjpssl_platform.hpp)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
    # RSA Montgomery 手写汇编 (rsa_mont_asm_win.asm, MULX 快速路径)
    enable_language(ASM_MASM)
endif()

# ── 条件编译选项 ─────────────────────────────────────────────────────
option(JP_ENABLE_AVX2   "Enable AVX2 acceleration"   ON)
option(JP_ENABLE_AVX512 "Enable AVX512 acceleration" ON)
option(JP_ENABLE_VAES   "Enable VAES-accelerated AES-GCM backend (needs -mvaes)" ON)
option(JP_ENABLE_NEON   "Enable ARM NEON/crypto acceleration (aarch64)" ON)
# ARMv8 / v8.1 / v8.2 / v9 架构等级（仅作用于 NEON 源文件）：
#   空 = 默认 (armv8.2-a)；可设为 armv8-a / armv8.1-a / armv8.2-a / armv9-a
set(JP_ARM_MARCH "" CACHE STRING "ARM architecture level for NEON sources (armv8-a/armv8.1-a/armv8.2-a/armv9-a)")

# ── VAES 编译能力检测 ─────────────────────────────────────────────────
# aes_gcm_vaes.cpp / aes_gcm_avx512.cpp 的 GNU/Clang 实现包含 VAES 汇编
# （vaesenc/vpclmulqdq），要求编译器支持 -mvaes（GCC 10+/Clang 12+）。
# 老工具链不支持时自动排除这两个源文件并禁用 JP_VAES/JP_AVX512，
# 运行时（auto 分派）回退 AVX2/PCLMUL 路径——"有 AVX2 无 VAES"构建兼容。
include(CheckCXXCompilerFlag)
if(MSVC OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(JP_CXX_HAS_VAES FALSE)   # MSVC：VAES 后端为 GNU 汇编，无实现
else()
    check_cxx_compiler_flag("-mvaes" JP_CXX_HAS_VAES)
endif()

# ── x86 硬件加速 ──────────────────────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    if(NOT MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -mavx2 -madx")
    endif()
endif()

# ── OpenSSL (可选: 仅测试/基准的 OpenSSL 对比用) ───────────────────────
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL: 找到 (${OPENSSL_VERSION})")
else()
    message(STATUS "OpenSSL: 未找到 — 跳过 OpenSSL 对比测试/基准")
endif()

# OpenMP (CPU 批量模幂并行化, 可用 -DJP_ENABLE_OPENMP=OFF 关闭)
# 鸿蒙 NDK 不提供 libomp，自动禁用（串行回退）。
if(JP_ENABLE_OPENMP AND NOT JP_OHOS)
    find_package(OpenMP)
endif()

# ── MUSA (实验性 GPU 加速, 默认关闭) ─────────────────────────────────
option(JP_ENABLE_MUSA "Enable MUSA GPU acceleration (experimental)" OFF)
option(JP_ENABLE_BENCH "Build benchmark executables (benchmarks/)" OFF)
option(JP_ENABLE_OPENMP "Enable OpenMP parallelism for CPU batch RSA (default ON)" ON)

if(JP_ENABLE_MUSA AND NOT WIN32 AND NOT JP_OHOS)
    list(APPEND CMAKE_MODULE_PATH /usr/local/musa/cmake)
    find_package(MUSA REQUIRED)
    set(MUSA_VERBOSE_BUILD ON)

    set(MUSA_MCC_FLAGS
        --offload-arch=mp_21
        --offload-arch=mp_22
        --offload-arch=mp_31
        -Werror
        -std=c++20
        -maes
        -mavx2
    )
    message(STATUS "MUSA GPU 加速: 已启用 (实验性)")
else()
    set(MUSA_FOUND FALSE)
    set(MUSA_LIBRARIES "")
    set(MUSA_INCLUDE_DIRS "")
    if((WIN32 OR JP_OHOS) AND JP_ENABLE_MUSA)
        message(WARNING "MUSA GPU 加速不支持 Windows/鸿蒙，已自动禁用")
    else()
        message(STATUS "MUSA GPU 加速: 已禁用 (使用 -DJP_ENABLE_MUSA=ON 启用)")
    endif()
endif()

# ═══════════════════════════════════════════════════════════════════════
#  libjpssl_cpu — 纯 CPU 密码学库 (AES, ChaCha20, RSA, AVX/AES-NI)
# ═══════════════════════════════════════════════════════════════════════
# 跨平台可移植源（x86 与 ARM 均编译）
set(CPU_SOURCES
    src/aes_cpu.cpp
    src/rand_os.cpp
    src/aes_gcm_auto.cpp
    src/chacha20_poly1305.cpp
    src/rsa.cpp
    src/sha256.cpp
    src/sha3.cpp
    src/sha1.cpp
    src/sha512_cpu.cpp
    src/hmac.cpp
    src/hkdf.cpp
    src/x25519.cpp
    src/x448.cpp
    src/dh.cpp
    src/ed448.cpp
    src/ed448_batch_cpu.cpp
    src/ed448_batch_dispatch.cpp
    src/tls_router.cpp
    src/tls12_server.cpp
    src/tls13_server.cpp
    src/tls12_client.cpp
    src/tls13_client.cpp
    src/tls_quic.cpp
    src/dtls.cpp
    src/x509.cpp
    src/ed25519.cpp
    src/ed25519_r51.cpp
    src/ed25519_batch_cpu.cpp
    src/ed25519_batch_dispatch.cpp
    src/aes_ccm.cpp
    src/ecdsa.cpp
    src/sm2.cpp
    src/sm2_mont_asm.cpp
    src/sm3.cpp
    src/sm4.cpp
    src/base64.cpp
    src/ct.cpp
    src/tls_socket.cpp
    src/sm4_gcm.cpp
    src/sm4_ccm.cpp
    src/sm4_gcm_dispatch.cpp
    src/rsa_batch_dispatch.cpp
    src/rsa_prim.cpp
    src/rsa_oaep.cpp
    src/rsa_pss.cpp
    src/rsa_schemes.cpp
)

# x86-64 专属 SIMD 源（AVX2/AVX512/VAES/SHA-NI/ADX 汇编等）
set(X86_SOURCES
    src/aes_gcm_avx2.cpp
    src/chacha20_avx2.cpp
    src/chacha20_avx512.cpp
    src/poly1305_avx2.cpp
    src/sha256_sha_ni.cpp
    src/sha1_avx2.cpp
    src/sha1_avx512.cpp
    src/sha512_opt.cpp
    src/base64_avx2.cpp
    src/base64_avx512.cpp
    src/rsa_batch_avx2.cpp
    src/rsa_batch_avx512.cpp
    src/rsa_mont_asm.cpp
    src/ed25519_avx512.cpp
    src/x25519_avx512.cpp
    src/ed448_avx2.cpp
    src/ed448_avx512.cpp
    src/x448_avx2.cpp
    src/x448_avx512.cpp
)
# VAES/AVX512 GCM 后端依赖 -mvaes 编译能力，按检测结果条件加入
if(JP_CXX_HAS_VAES)
    if(JP_ENABLE_AVX512)
        list(APPEND X86_SOURCES src/aes_gcm_avx512.cpp)
    endif()
    if(JP_ENABLE_VAES)
        list(APPEND X86_SOURCES src/aes_gcm_vaes.cpp)
    endif()
endif()

# ARM (aarch64) NEON/crypto 加速源
set(ARM_SOURCES
    src/aes_gcm_neon.cpp
    src/chacha20_neon.cpp
    src/sha1_neon.cpp
    src/sha256_neon.cpp
    src/sha512_neon.cpp
    src/sha3_neon.cpp
    src/sm4_neon.cpp
    src/sm3_neon.cpp
)
# SHA-512 / SHA-3 / SM4 / SM3 扩展 (FEAT_SHA512/FEAT_SHA3/FEAT_SM4/FEAT_SM3)
# 是 ARMv8.2 可选特性；Apple Clang 的 intrinsic 需 -march=armv8.4-a+crypto
# 才定义（armv9-a 也会定义）。这些文件单独用更高的 -march，运行时按
# cpu_has_arm_sha512()/cpu_has_arm_sha3()/cpu_has_arm_sm4()/cpu_has_arm_sm3()
# 分派，
# 低版本机器安全回退到标量实现。
set(ARM_CRYPTO_EXT_SOURCES
    src/sha512_neon.cpp
    src/sha3_neon.cpp
    src/sm4_neon.cpp
    src/sm3_neon.cpp)
# 被 rsa.cpp include 的 .inc (宏模板/预制素数表): 构建规则为 unscanned
# (无 /showIncludes 自动依赖), 必须用 OBJECT_DEPENDS 显式声明,
# 否则修改 .inc 不会触发 rsa.cpp 重编。
set_property(SOURCE src/rsa.cpp APPEND PROPERTY OBJECT_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa_body.inc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa_prebuilt_primes_data.inc)
if(MSVC)
    # Windows: MULX 手写汇编 Montgomery 乘法 (K=32/64)
    list(APPEND CPU_SOURCES src/rsa_mont_asm_win.asm)
    list(APPEND CPU_SOURCES src/fe51_mul_adx.asm)
    list(APPEND CPU_SOURCES src/fe51_sq_adx.asm)
    list(APPEND CPU_SOURCES src/ecdsa_p256_adx.asm)
    list(APPEND CPU_SOURCES src/ecp_nistz256_x64.asm)
    list(APPEND CPU_SOURCES src/sm2_mont_asm_win.asm)
    # SM3 标量压缩汇编
    list(APPEND CPU_SOURCES src/sm3_win.asm)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    list(APPEND CPU_SOURCES ${X86_SOURCES})
    # P-256 ECDSA ADX 快速路径（内联汇编版，GCC/Clang 跨平台；MSVC 用同目录 .asm）
    if(NOT MSVC)
        list(APPEND CPU_SOURCES src/ecdsa_p256_adx_inline.cpp)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    if(JP_ENABLE_NEON)
        list(APPEND CPU_SOURCES ${ARM_SOURCES})
    endif()
    # NIST P-256 ARMv8 汇编（域乘/平方/点运算，移植自 OpenSSL nistz256，
    # 仅用基础 ARMv8 标量指令，不依赖 NEON/crypto 扩展）
    # Apple (iOS/macOS): assembler rejects GNU ADR/ADRP relocations; use C++ path
    if(NOT APPLE)
        list(APPEND CPU_SOURCES src/ecp_nistz256_arm.S)
    endif()
endif()

# ── iOS ────────────────────────────────────────────────────────────────
# 导出 Swift 符号的 extern "C" 桥接层（ios/bridge/jpssl_bridge.cpp + jpssl.h）
# 仅在 iOS 构建时编入静态库，配合 module.modulemap /
# XCFramework / Package.swift 供 Swift 侧 import 使用（最低 iOS 13.0 / arm64）。
# 注意：桥接源依赖 ios/bridge 头文件，对应 target_include_directories
# 在 add_library 之后的既有 include 块中补充（见下方 jpssl_cpu 的 include 设置）。
if(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND CPU_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/ios/bridge/jpssl_bridge.cpp)
    message(STATUS "iOS: 已包含 Swift 桥接层 (ios/bridge/jpssl_bridge.cpp)")
endif()

add_library(jpssl_cpu STATIC ${CPU_SOURCES})
add_library(jpssl_cpu_shared SHARED ${CPU_SOURCES})
if(WIN32)
    # Windows: 共享库的导入库 (jpssl_cpu.lib) 与静态库同名冲突，静态库改名
    set_target_properties(jpssl_cpu PROPERTIES OUTPUT_NAME jpssl_cpu_static)
endif()
if(MSVC)
    target_compile_definitions(jpssl_cpu PRIVATE JP_HAVE_ADX_ASM)
    target_compile_definitions(jpssl_cpu_shared PRIVATE JP_HAVE_ADX_ASM)
    target_compile_definitions(jpssl_cpu PRIVATE JP_HAVE_SM3_ASM)
    target_compile_definitions(jpssl_cpu_shared PRIVATE JP_HAVE_SM3_ASM)
endif()
target_include_directories(jpssl_cpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(jpssl_cpu_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Swift 桥接头文件目录（jpssl.h）
    target_include_directories(jpssl_cpu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ios/bridge)
    target_include_directories(jpssl_cpu_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ios/bridge)
endif()
set_target_properties(jpssl_cpu_shared PROPERTIES
    OUTPUT_NAME jpssl_cpu
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)
if(WIN32)
    # BCrypt (rand_os.cpp 的 BCryptGenRandom)；DLL 导出所有公共符号
    target_link_libraries(jpssl_cpu PUBLIC bcrypt)
    target_link_libraries(jpssl_cpu_shared PUBLIC bcrypt)
    # 系统证书库（from_system 的 Windows ROOT store 加载）
    target_link_libraries(jpssl_cpu PUBLIC crypt32)
    target_link_libraries(jpssl_cpu_shared PUBLIC crypt32)
    # Winsock (tls_socket.cpp)
    target_link_libraries(jpssl_cpu PUBLIC ws2_32)
    target_link_libraries(jpssl_cpu_shared PUBLIC ws2_32)
    set_target_properties(jpssl_cpu_shared PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
endif()
if(JP_ENABLE_OPENMP AND OpenMP_CXX_FOUND)
    target_link_libraries(jpssl_cpu PUBLIC OpenMP::OpenMP_CXX)
    target_link_libraries(jpssl_cpu_shared PUBLIC OpenMP::OpenMP_CXX)
    target_compile_definitions(jpssl_cpu PUBLIC JP_ENABLE_OPENMP)
    message(STATUS "OpenMP: enabled")
else()
    message(STATUS "OpenMP: disabled")
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    if(MSVC)
        # ── MSVC: intrinsics 头 (<wmmintrin.h>/<immintrin.h>) 自带声明，
        #    按源文件单独启用所需指令集；AES-NI/PCLMULQDQ intrinsics 无需 /arch
        # AES-CPU: AES-NI + PCLMULQDQ（默认 /arch 可用，无需额外标志）
        # AVX2 GCM: 需要 PCLMULQDQ + AVX2
        set_source_files_properties(src/aes_gcm_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        # AVX512 GCM: AVX512F + VAES + VPCLMULQDQ
        set_source_files_properties(src/aes_gcm_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        # SHA-NI (sha512_opt/sha256_sha_ni): SHA intrinsics 要求 /arch:AVX2
        set_source_files_properties(src/sha512_opt.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/sha256_sha_ni.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        # SHA-1 multi-buffer SIMD
        set_source_files_properties(src/sha1_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/sha1_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        # RSA batch AVX2/AVX512: 批量 Montgomery
        set_source_files_properties(src/rsa_batch_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/rsa_batch_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        # ChaCha20 SIMD
        set_source_files_properties(src/chacha20_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/chacha20_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        # Poly1305 AVX2
        set_source_files_properties(src/poly1305_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        # RSA Montgomery MULX/ADCX/ADOX intrinsics (K=32/64 快速路径)
        set_source_files_properties(src/rsa_mont_asm.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        # X25519 / Ed25519 AVX-512
        set_source_files_properties(src/x25519_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        set_source_files_properties(src/ed25519_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        # Ed448/X448 AVX2 与 AVX-512
        set_source_files_properties(src/ed448_avx2.cpp src/x448_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/ed448_avx512.cpp src/x448_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        # Base64 SIMD
        set_source_files_properties(src/base64_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/base64_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
    else()
        target_compile_options(jpssl_cpu PRIVATE -maes -mavx2 -madx)
        target_compile_options(jpssl_cpu_shared PRIVATE -maes -mavx2 -madx)
        # AES-CPU: 需要 PCLMULQDQ 指令（用于 GCM GHASH 加速）
        set_source_files_properties(src/aes_cpu.cpp PROPERTIES
            COMPILE_FLAGS "-mpclmul")
        # SM4-GCM: GHASH 同样需要 PCLMULQDQ
        set_source_files_properties(src/sm4_gcm.cpp PROPERTIES
            COMPILE_FLAGS "-mpclmul")
        # AVX2 GCM: 需要 PCLMULQDQ 指令
        set_source_files_properties(src/aes_gcm_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mpclmul")
        # AVX512 GCM: 需要 AVX512F + AVX512VL + VAES + VPCLMULQDQ + PCLMUL
        set_source_files_properties(src/aes_gcm_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512vl -mvaes -mvpclmulqdq -mpclmul")
        # VAES GCM: VEX.256 VAES + VPCLMULQDQ（均不引入 AVX512）；
        # 另需 AVX2（YMM 操作）、AES-NI 与 128-bit PCLMULQDQ（GHASH 尾部）
        set_source_files_properties(src/aes_gcm_vaes.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2 -maes -mpclmul -mvaes -mvpclmulqdq")
        # SHA-512 OPT: SHA-NI + SSE4.1 for message schedule acceleration
        set_source_files_properties(src/sha512_opt.cpp PROPERTIES
            COMPILE_FLAGS "-msse4.1 -msha")
        # SHA-256 SHA-NI: Intel SHA Extensions accelerated implementation
        set_source_files_properties(src/sha256_sha_ni.cpp PROPERTIES
            COMPILE_FLAGS "-msha")
        # SHA-1 multi-buffer SIMD
        set_source_files_properties(src/sha1_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2")
        set_source_files_properties(src/sha1_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512bw")
        # RSA Montgomery asm: 内联 asm 模板为 Intel 语法且含 "m" 内存操作数，
        # 需 -masm=intel 使 GCC 生成与模板一致的 Intel 形式操作数文本
        set_source_files_properties(src/rsa_mont_asm.cpp PROPERTIES
            COMPILE_FLAGS "-masm=intel")
        # SM2 Montgomery asm: 同上（GCC/Clang 内联汇编）
        set_source_files_properties(src/sm2_mont_asm.cpp PROPERTIES
            COMPILE_FLAGS "-masm=intel")
        # RSA batch AVX2: 4-wide Montgomery multiplication
        set_source_files_properties(src/rsa_batch_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2")
        # RSA batch AVX-512: 8-wide Montgomery multiplication
        set_source_files_properties(src/rsa_batch_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512vl")
        # X25519/Ed25519: 域乘/平方的 C++ 回退（fe51_mul_portable）在 -madx 下
        # 生成的 __uint128_t MULX 序列实测慢 ~5%，故回退代码用 -mno-adx 编译。
        # BMI2+ADX 快速路径是 fe_25519_r51.hpp 中的手写内联汇编（MULX/ADCX/ADOX
        # 双进位链），运行时检测 CPU 特性后分派，不受 -mno-adx 影响。
        set_source_files_properties(
            src/x25519.cpp src/ed25519_r51.cpp PROPERTIES
            COMPILE_FLAGS "-mno-adx")
        # ChaCha20 SIMD: 独立编译单元分别启用 AVX2 / AVX512F
        set_source_files_properties(
            src/chacha20_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2")
        set_source_files_properties(
            src/chacha20_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f")
        # X25519 AVX-512: auto-vectorized fe25519 field ops
        set_source_files_properties(
            src/x25519_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512dq -mno-adx")
        # Ed448/X448 AVX-512: auto-vectorized fe448 field ops
        set_source_files_properties(
            src/ed448_avx512.cpp src/x448_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512dq")
        # Base64 SIMD
        set_source_files_properties(
            src/base64_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2")
        set_source_files_properties(
            src/base64_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512bw")
    endif()
endif()

if(JP_ENABLE_AVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    # PUBLIC：让测试/示例代码知道该构建提供 AVX2 路径（aes.hpp 据此声明/不声明接口）
    target_compile_definitions(jpssl_cpu PUBLIC JP_AVX2)
    target_compile_definitions(jpssl_cpu_shared PUBLIC JP_AVX2)
endif()
if(JP_ENABLE_AVX512 AND JP_CXX_HAS_VAES AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    target_compile_definitions(jpssl_cpu PUBLIC JP_AVX512)
    target_compile_definitions(jpssl_cpu_shared PUBLIC JP_AVX512)
endif()
if(JP_ENABLE_VAES AND JP_CXX_HAS_VAES AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    # PUBLIC：测试/示例代码据此声明 VAES GCM 接口（aes.hpp）
    target_compile_definitions(jpssl_cpu PUBLIC JP_VAES)
    target_compile_definitions(jpssl_cpu_shared PUBLIC JP_VAES)
endif()

# ── ARM NEON / crypto 硬件加速 (aarch64: NEON 必选, AES/PMULL/SHA 扩展可选) ──
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    if(JP_ENABLE_NEON AND ARM_SOURCES)
        target_compile_definitions(jpssl_cpu PUBLIC JP_NEON)
        target_compile_definitions(jpssl_cpu_shared PUBLIC JP_NEON)

        # 用户可通过 -DJP_ARM_MARCH=armv8-a / armv8.1-a / armv8.2-a / armv8.4-a / armv9-a
        # 选择目标架构等级；默认 armv8.2-a+crypto（Apple Silicon 与主流 ARMv8.2 均支持）。
        # armv8.4-a 直接覆盖 SHA-512/SHA-3/SM3/SM4 所需的 crypto 扩展（FEAT_*），
        # 全部 NEON 源（含 SHA-1/SHA-256）按该等级编译。
        # 仅对 NEON 源文件启用，避免抬高整个库的最低架构要求。
        if(JP_ARM_MARCH)
            string(REGEX MATCH "^(armv8-a|armv8\\.1-a|armv8\\.2-a|armv8\\.4-a|armv9-a)$" JP_ARM_MARCH_OK "${JP_ARM_MARCH}")
            if(NOT JP_ARM_MARCH_OK)
                message(FATAL_ERROR "JP_ARM_MARCH 必须是 armv8-a / armv8.1-a / armv8.2-a / armv8.4-a / armv9-a 之一（当前: ${JP_ARM_MARCH}）")
            endif()
            set(JP_NEON_ARCH_FLAGS "-march=${JP_ARM_MARCH}+crypto")
            if(JP_ARM_MARCH STREQUAL "armv9-a")
                # armv9-a 会开启 SVE/SVE2，而 Apple Silicon（M 系列，ARMv8.4-8.6）
                # 不支持 SVE；NEON 源只用 AES/PMULL/SHA2 扩展，禁用 SVE 代码生成
                # 以保证 armv9-a 构建在 Apple 芯片与 ARMv9 机器上都能运行。
                if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
                    list(APPEND JP_NEON_ARCH_FLAGS
                        -Xclang -target-feature -Xclang -sve
                        -Xclang -target-feature -Xclang -sve2)
                elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
                    list(APPEND JP_NEON_ARCH_FLAGS -mno-sve -mno-sve2)
                endif()
            endif()
            set_source_files_properties(${ARM_SOURCES} PROPERTIES
                COMPILE_OPTIONS "${JP_NEON_ARCH_FLAGS}")
            if(JP_ARM_MARCH STREQUAL "armv8-a" OR JP_ARM_MARCH STREQUAL "armv8.1-a" OR JP_ARM_MARCH STREQUAL "armv8.2-a")
                # SHA-512/SHA-3/SM4/SM3 intrinsic 需要至少 armv8.4-a（覆盖上方较低等级）
                set_source_files_properties(${ARM_CRYPTO_EXT_SOURCES} PROPERTIES
                    COMPILE_OPTIONS "-march=armv8.4-a+crypto")
            endif()
            message(STATUS "ARM NEON: 启用, -march=${JP_ARM_MARCH}+crypto (可用 -DJP_ARM_MARCH=armv8-a/armv8.1-a/armv8.4-a/armv9-a 调整)")
        else()
            set_source_files_properties(${ARM_SOURCES} PROPERTIES
                COMPILE_FLAGS "-march=armv8.2-a+crypto")
            # 覆盖：SHA-512/SHA-3/SM4/SM3 源用 armv8.4-a+crypto（COMPILE_FLAGS 整体替换）
            set_source_files_properties(${ARM_CRYPTO_EXT_SOURCES} PROPERTIES
                COMPILE_FLAGS "-march=armv8.4-a+crypto")
            message(STATUS "ARM NEON: 启用, -march=armv8.2-a+crypto (可用 -DJP_ARM_MARCH=armv8-a/armv8.1-a/armv8.4-a/armv9-a 调整)")
        endif()
    else()
        message(STATUS "ARM NEON: 已禁用 (使用 -DJP_ENABLE_NEON=ON 启用)")
    endif()
endif()
if(JP_ENABLE_MUSA)
    target_compile_definitions(jpssl_cpu PRIVATE JP_MUSA)
    target_compile_definitions(jpssl_cpu_shared PRIVATE JP_MUSA)
endif()
if(JP_OHOS)
    # 公开给依赖方：库用户可用 JP_OHOS 感知平台差异
    target_compile_definitions(jpssl_cpu PUBLIC JP_OHOS)
    target_compile_definitions(jpssl_cpu_shared PUBLIC JP_OHOS)
endif()

# Link OpenSSL was removed — Ed25519, X25519, SHA-512 are all pure C++20 now
# OpenSSL::Crypto kept only on individual test targets that compare vs OpenSSL

# ═══════════════════════════════════════════════════════════════════════
#  libjpssl_musa — MUSA GPU 加速库 (AES, ChaCha20, RSA GPU kernels)
# ═══════════════════════════════════════════════════════════════════════
if(JP_ENABLE_MUSA)
    set(MUSA_SOURCES
        src/aes_musa.cpp
        src/rsa_musa.cpp
        src/sha512_musa.cpp
    )

    set(MUSA_KERNELS
        src/aes_gpu.mu
        src/chacha20_gpu.mu
        src/rsa_gpu.mu
        src/sha512_gpu.mu
    )

    musa_add_library(jpssl_musa STATIC ${MUSA_SOURCES} ${MUSA_KERNELS})
    musa_add_library(jpssl_musa_shared SHARED ${MUSA_SOURCES} ${MUSA_KERNELS})
    target_include_directories(jpssl_musa PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${MUSA_INCLUDE_DIRS}
    )
    target_include_directories(jpssl_musa_shared PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${MUSA_INCLUDE_DIRS}
    )
    set_target_properties(jpssl_musa_shared PROPERTIES
        OUTPUT_NAME jpssl_musa
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
    )
    target_link_libraries(jpssl_musa jpssl_cpu ${MUSA_LIBRARIES})
    target_link_libraries(jpssl_musa_shared jpssl_cpu_shared ${MUSA_LIBRARIES})
endif()

# ═══════════════════════════════════════════════════════════════════════
#  jpssl-test — 测试 & Benchmark 可执行文件（鸿蒙 NDK 不构建可执行文件）
# ═══════════════════════════════════════════════════════════════════════
if(NOT JPSSL_AS_SUBPROJECT AND JP_ENABLE_MUSA AND NOT WIN32 AND NOT JP_OHOS)
    musa_add_executable(jpssl-test src/main.cpp)
    target_include_directories(jpssl-test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${MUSA_INCLUDE_DIRS}
    )
    # GPU 测试函数由 #ifdef JP_MUSA 守卫，须对 main.cpp 可见
    target_compile_definitions(jpssl-test PRIVATE JP_MUSA)
    target_link_libraries(jpssl-test jpssl_cpu jpssl_musa ${MUSA_LIBRARIES})
elseif(NOT JPSSL_AS_SUBPROJECT AND NOT JP_OHOS AND NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_executable(jpssl-test src/main.cpp)
    target_include_directories(jpssl-test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(jpssl-test jpssl_cpu)
endif()

# ═══════════════════════════════════════════════════════════════════════
#  命令行工具（鸿蒙 NDK 不构建可执行文件，跳过）
# ═══════════════════════════════════════════════════════════════════════
if(NOT JPSSL_AS_SUBPROJECT AND NOT JP_OHOS AND NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_executable(jpssl-cert src/cmd/jpssl_cert.cpp)
    add_executable(jpssl-crypt src/cmd/jpssl_crypt.cpp)
    target_include_directories(jpssl-cert PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${MUSA_INCLUDE_DIRS}
    )
    target_include_directories(jpssl-crypt PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${MUSA_INCLUDE_DIRS}
    )
    if(JP_ENABLE_MUSA)
        target_link_libraries(jpssl-cert PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES})
        target_link_libraries(jpssl-crypt PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES})
    else()
        target_link_libraries(jpssl-cert PRIVATE jpssl_cpu)
        target_link_libraries(jpssl-crypt PRIVATE jpssl_cpu)
    endif()

    # ── 安装 ────────────────────────────────────────────────────────────────
    include(GNUInstallDirs)
    install(TARGETS jpssl-cert jpssl-crypt
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
# ═══════════════════════════════════════════════════════════════════════
#  单元测试 (CTest) / 示例 —— 子项目模式（JPSSL_AS_SUBPROJECT=ON）下跳过
# ═══════════════════════════════════════════════════════════════════════
if(NOT JPSSL_AS_SUBPROJECT AND NOT JP_OHOS AND NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_subdirectory(tests)
    add_subdirectory(examples)
endif()

if(JP_ENABLE_BENCH AND NOT JPSSL_AS_SUBPROJECT AND NOT JP_OHOS)
    add_subdirectory(benchmarks)
endif()
