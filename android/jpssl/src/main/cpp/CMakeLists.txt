# jpssl Android (arm64-v8a) 构建脚本
#
# 仅支持 arm64-v8a (ARMv8/AArch64)。源文件直接复用仓库根目录 src/ 与 include/，
# 源列表与顶层 CMakeLists.txt 的 CPU_SOURCES + ARM_SOURCES 保持一致（x86 专属
# SIMD 源、MSVC 汇编、MUSA GPU 均不参与 Android 构建）。
cmake_minimum_required(VERSION 3.22)
project(jpssl_android LANGUAGES CXX ASM)

if(NOT (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64"))
    message(FATAL_ERROR
        "jpssl Android 仅支持 arm64-v8a (ARMv8); 当前处理器: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# src/main/cpp -> src/main -> src -> jpssl -> android -> 仓库根
set(JPSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../..")

# ── jpssl_cpu 静态库（与顶层 CMakeLists 的 CPU_SOURCES + ARM_SOURCES 对齐）──
set(JPSSL_CPU_SOURCES
    ${JPSSL_ROOT}/src/aes_cpu.cpp
    ${JPSSL_ROOT}/src/rand_os.cpp
    ${JPSSL_ROOT}/src/aes_gcm_auto.cpp
    ${JPSSL_ROOT}/src/chacha20_poly1305.cpp
    ${JPSSL_ROOT}/src/rsa.cpp
    ${JPSSL_ROOT}/src/sha256.cpp
    ${JPSSL_ROOT}/src/sha3.cpp
    ${JPSSL_ROOT}/src/sha1.cpp
    ${JPSSL_ROOT}/src/sha512_cpu.cpp
    ${JPSSL_ROOT}/src/hmac.cpp
    ${JPSSL_ROOT}/src/hkdf.cpp
    ${JPSSL_ROOT}/src/x25519.cpp
    ${JPSSL_ROOT}/src/x448.cpp
    ${JPSSL_ROOT}/src/ed448.cpp
    ${JPSSL_ROOT}/src/ed448_batch_cpu.cpp
    ${JPSSL_ROOT}/src/ed448_batch_dispatch.cpp
    ${JPSSL_ROOT}/src/dh.cpp
    ${JPSSL_ROOT}/src/tls_router.cpp
    ${JPSSL_ROOT}/src/tls12_server.cpp
    ${JPSSL_ROOT}/src/tls13_server.cpp
    ${JPSSL_ROOT}/src/tls12_client.cpp
    ${JPSSL_ROOT}/src/tls13_client.cpp
    ${JPSSL_ROOT}/src/tls_quic.cpp
    ${JPSSL_ROOT}/src/dtls.cpp
    ${JPSSL_ROOT}/src/x509.cpp
    ${JPSSL_ROOT}/src/ed25519.cpp
    ${JPSSL_ROOT}/src/ed25519_r51.cpp
    ${JPSSL_ROOT}/src/ed25519_batch_cpu.cpp
    ${JPSSL_ROOT}/src/ed25519_batch_dispatch.cpp
    ${JPSSL_ROOT}/src/aes_ccm.cpp
    ${JPSSL_ROOT}/src/ecdsa.cpp
    ${JPSSL_ROOT}/src/sm2.cpp
    ${JPSSL_ROOT}/src/sm2_mont_asm.cpp
    ${JPSSL_ROOT}/src/sm3.cpp
    ${JPSSL_ROOT}/src/sm4.cpp
    ${JPSSL_ROOT}/src/base64.cpp
    ${JPSSL_ROOT}/src/ct.cpp
    ${JPSSL_ROOT}/src/tls_socket.cpp
    ${JPSSL_ROOT}/src/sm4_gcm.cpp
    ${JPSSL_ROOT}/src/sm4_ccm.cpp
    ${JPSSL_ROOT}/src/sm4_gcm_dispatch.cpp
    ${JPSSL_ROOT}/src/rsa_batch_dispatch.cpp
    ${JPSSL_ROOT}/src/rsa_prim.cpp
    ${JPSSL_ROOT}/src/rsa_oaep.cpp
    ${JPSSL_ROOT}/src/rsa_pss.cpp
    ${JPSSL_ROOT}/src/rsa_schemes.cpp
    # ── ARMv8 NEON/crypto 加速源 ──
    ${JPSSL_ROOT}/src/aes_gcm_neon.cpp
    ${JPSSL_ROOT}/src/chacha20_neon.cpp
    ${JPSSL_ROOT}/src/sha1_neon.cpp
    ${JPSSL_ROOT}/src/sha256_neon.cpp
    ${JPSSL_ROOT}/src/sha512_neon.cpp
    ${JPSSL_ROOT}/src/sha3_neon.cpp
    ${JPSSL_ROOT}/src/sm4_neon.cpp
    ${JPSSL_ROOT}/src/sm3_neon.cpp
    # NIST P-256 ARMv8 汇编（ELF 别名已补齐，Android arm64 可直接链接）
    ${JPSSL_ROOT}/src/ecp_nistz256_arm.S
)

add_library(jpssl_cpu STATIC ${JPSSL_CPU_SOURCES})
target_include_directories(jpssl_cpu PUBLIC ${JPSSL_ROOT}/include)
target_compile_definitions(jpssl_cpu PUBLIC JP_NEON)

# NEON 源按 ARMv8.2-A + crypto 编译（与顶层 CMakeLists 默认一致）
set_source_files_properties(
    ${JPSSL_ROOT}/src/aes_gcm_neon.cpp
    ${JPSSL_ROOT}/src/chacha20_neon.cpp
    ${JPSSL_ROOT}/src/sha1_neon.cpp
    ${JPSSL_ROOT}/src/sha256_neon.cpp
    PROPERTIES COMPILE_FLAGS "-march=armv8.2-a+crypto")
# SHA-512 / SHA-3 / SM4 / SM3 扩展 (FEAT_SHA512/SHA3/SM4/SM3) 单独按 armv8.4-a+crypto，
# 运行时由 cpu_has_arm_*() 分派，低版本 CPU 安全回退标量实现
set_source_files_properties(
    ${JPSSL_ROOT}/src/sha512_neon.cpp
    ${JPSSL_ROOT}/src/sha3_neon.cpp
    ${JPSSL_ROOT}/src/sm4_neon.cpp
    ${JPSSL_ROOT}/src/sm3_neon.cpp
    PROPERTIES COMPILE_FLAGS "-march=armv8.4-a+crypto")

# rsa.cpp include 的 .inc（unscanned 依赖，必须显式声明）
set_property(SOURCE ${JPSSL_ROOT}/src/rsa.cpp APPEND PROPERTY OBJECT_DEPENDS
    ${JPSSL_ROOT}/src/rsa_body.inc
    ${JPSSL_ROOT}/src/rsa_prebuilt_primes_data.inc)

# ── JNI 桥：libjpssl.so（导出 Java/Kotlin 可调用的 native 符号） ──
add_library(jpssl SHARED jpssl_jni.cpp)
target_include_directories(jpssl PRIVATE ${JPSSL_ROOT}/include)
target_link_libraries(jpssl PRIVATE jpssl_cpu)

set_target_properties(jpssl PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
