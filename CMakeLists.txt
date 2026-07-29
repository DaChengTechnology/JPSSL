cmake_minimum_required(VERSION 3.20)

project(jpssl VERSION 1.0.0 LANGUAGES CXX)

# ── C++20 ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── 条件编译选项 ─────────────────────────────────────────────────────
option(JP_ENABLE_AVX2   "Enable AVX2 acceleration"   ON)
option(JP_ENABLE_AVX512 "Enable AVX512 acceleration" ON)

# ── x86 硬件加速 ──────────────────────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -mavx2")
endif()

# ── OpenSSL (Ed25519, SHA-512, TLS interop) ───────────────────────────
find_package(OpenSSL REQUIRED)

# ── MUSA ───────────────────────────────────────────────────────────────
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

# ═══════════════════════════════════════════════════════════════════════
#  libjpssl_cpu — 纯 CPU 密码学库 (AES, ChaCha20, RSA, AVX/AES-NI)
# ═══════════════════════════════════════════════════════════════════════
set(CPU_SOURCES
    src/aes_cpu.cpp
    src/aes_gcm_avx2.cpp
    src/aes_gcm_avx512.cpp
    src/aes_gcm_auto.cpp
    src/chacha20_poly1305.cpp
    src/rsa.cpp
    src/sha256.cpp
    src/sha256_sha_ni.cpp
    src/sha3.cpp
    src/sha512_cpu.cpp
    src/sha512_opt.cpp
    src/hmac.cpp
    src/hkdf.cpp
    src/x25519.cpp
    src/x448.cpp
    src/x448_avx2.cpp
    src/x448_avx512.cpp
    src/ed448.cpp
    src/ed448_avx2.cpp
    src/ed448_avx512.cpp
    src/ed448_batch_cpu.cpp
    src/ed448_batch_dispatch.cpp
    src/tls.cpp
    src/ed25519.cpp
    src/ed25519_avx2.cpp
    src/ed25519_avx512.cpp
    src/ed25519_batch_cpu.cpp
    src/ed25519_batch_dispatch.cpp
    src/aes_ccm.cpp
    src/ecdsa.cpp
    src/rsa_batch_avx2.cpp
    src/rsa_batch_avx512.cpp
    src/rsa_batch_dispatch.cpp
)

add_library(jpssl_cpu STATIC ${CPU_SOURCES})
add_library(jpssl_cpu_shared SHARED ${CPU_SOURCES})
target_include_directories(jpssl_cpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(jpssl_cpu_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
set_target_properties(jpssl_cpu_shared PROPERTIES
    OUTPUT_NAME jpssl_cpu
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    target_compile_options(jpssl_cpu PRIVATE -maes -mavx2)
    target_compile_options(jpssl_cpu_shared PRIVATE -maes -mavx2)
    # AES-CPU: 需要 PCLMULQDQ 指令（用于 GCM GHASH 加速）
    set_source_files_properties(src/aes_cpu.cpp PROPERTIES
        COMPILE_FLAGS "-mpclmul")
    # AVX2 GCM: 需要 PCLMULQDQ 指令
    set_source_files_properties(src/aes_gcm_avx2.cpp PROPERTIES
        COMPILE_FLAGS "-mpclmul")
    # AVX512 GCM: 需要 AVX512F + AVX512VL + VAES + VPCLMULQDQ + PCLMUL
    set_source_files_properties(src/aes_gcm_avx512.cpp PROPERTIES
        COMPILE_FLAGS "-mavx512f -mavx512vl -mvaes -mvpclmulqdq -mpclmul")
    # SHA-512 OPT: SHA-NI + SSE4.1 for message schedule acceleration
    set_source_files_properties(src/sha512_opt.cpp PROPERTIES
        COMPILE_FLAGS "-msse4.1 -msha")
    # SHA-256 SHA-NI: Intel SHA Extensions accelerated implementation
    set_source_files_properties(src/sha256_sha_ni.cpp PROPERTIES
        COMPILE_FLAGS "-msha")
    # RSA batch AVX2: 4-wide Montgomery multiplication
    set_source_files_properties(src/rsa_batch_avx2.cpp PROPERTIES
        COMPILE_FLAGS "-mavx2")
    # RSA batch AVX-512: 8-wide Montgomery multiplication
    set_source_files_properties(src/rsa_batch_avx512.cpp PROPERTIES
        COMPILE_FLAGS "-mavx512f -mavx512vl")
    # Ed448/X448 AVX-512: auto-vectorized fe448 field ops
    set_source_files_properties(
        src/ed448_avx512.cpp src/x448_avx512.cpp PROPERTIES
        COMPILE_FLAGS "-mavx512f -mavx512dq")
endif()

if(JP_ENABLE_AVX2)
    target_compile_definitions(jpssl_cpu PRIVATE JP_AVX2)
    target_compile_definitions(jpssl_cpu_shared PRIVATE JP_AVX2)
endif()
if(JP_ENABLE_AVX512)
    target_compile_definitions(jpssl_cpu PRIVATE JP_AVX512)
    target_compile_definitions(jpssl_cpu_shared PRIVATE JP_AVX512)
endif()

# Link OpenSSL was removed — Ed25519, X25519, SHA-512 are all pure C++20 now
# OpenSSL::Crypto kept only on individual test targets that compare vs OpenSSL

# ═══════════════════════════════════════════════════════════════════════
#  libjpssl_musa — MUSA GPU 加速库 (AES, ChaCha20, RSA GPU kernels)
# ═══════════════════════════════════════════════════════════════════════
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

# ═══════════════════════════════════════════════════════════════════════
#  jpssl-test — 测试 & Benchmark 可执行文件
# ═══════════════════════════════════════════════════════════════════════
musa_add_executable(jpssl-test src/main.cpp)
target_include_directories(jpssl-test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(jpssl-test jpssl_cpu jpssl_musa ${MUSA_LIBRARIES})

# ═══════════════════════════════════════════════════════════════════════
#  JPTest 单元测试
# ═══════════════════════════════════════════════════════════════════════
add_subdirectory(tests/jptest)

# AES 全覆盖单元测试
add_executable(test_aes tests/test_aes.cpp)
target_include_directories(test_aes PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_aes PRIVATE jpssl_cpu OpenSSL::Crypto)

# SHA3 单元测试
add_executable(test_sha3 tests/test_sha3.cpp)
target_include_directories(test_sha3 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_sha3 PRIVATE jpssl_cpu JPTEST::jptest OpenSSL::Crypto)

# SHA-512/SHA-384 单元测试
add_executable(test_sha512 tests/test_sha512.cpp)
target_include_directories(test_sha512 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_sha512 PRIVATE jpssl_cpu OpenSSL::Crypto)
target_include_directories(test_sha3 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_sha3 PRIVATE jpssl_cpu JPTEST::jptest OpenSSL::Crypto)

# TLS 单元测试
add_executable(test_tls tests/test_tls.cpp)
target_include_directories(test_tls PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_tls PRIVATE jpssl_cpu JPTEST::jptest)

# TLS 1.3 X448/Ed448 handshake test
add_executable(test_tls448 tests/test_tls448.cpp)
target_include_directories(test_tls448 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${JPTEST_INCLUDE_DIRS}
)
target_link_libraries(test_tls448 PRIVATE jpssl_cpu JPTEST::jptest OpenSSL::Crypto)

# X448 RFC 7748 test
add_executable(test_x448_rfc tests/test_x448_rfc.cpp)
target_include_directories(test_x448_rfc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_x448_rfc PRIVATE jpssl_cpu)

add_executable(test_ed448_rfc tests/test_ed448_rfc.cpp)
target_include_directories(test_ed448_rfc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_ed448_rfc PRIVATE jpssl_cpu OpenSSL::Crypto)

add_executable(test_ed448_trace tests/test_ed448_trace.cpp)
target_include_directories(test_ed448_trace PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_ed448_trace PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ed448 batch verify test
add_executable(test_ed448_batch tests/test_ed448_batch.cpp)
target_include_directories(test_ed448_batch PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_ed448_batch PRIVATE jpssl_cpu)

# SHAKE XOF 单元测试 (FIPS 202 KAT, Ed448 依赖)
add_executable(test_shake tests/test_shake.cpp)
target_include_directories(test_shake PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_shake PRIVATE jpssl_cpu)

# GHash 单元测试（NIST SP 800-38D）
add_executable(test_ghash tests/test_ghash.cpp)
target_include_directories(test_ghash PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_ghash PRIVATE jpssl_cpu)

# X25519 RFC 7748 test
add_executable(test_x25519_rfc tests/test_x25519_rfc.cpp)
target_include_directories(test_x25519_rfc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_x25519_rfc PRIVATE jpssl_cpu)

# X25519 vs OpenSSL comparison
add_executable(test_x25519_ossl tests/test_x25519_ossl.cpp)
target_include_directories(test_x25519_ossl PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_x25519_ossl PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ed25519 RFC 8032 test
add_executable(test_ed25519_rfc tests/test_ed25519_rfc.cpp)
target_include_directories(test_ed25519_rfc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_ed25519_rfc PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ed25519 debug test
add_executable(test_ed25519_debug tests/test_ed25519_debug.cpp)
target_include_directories(test_ed25519_debug PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_ed25519_debug PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ed25519 verify direct test
add_executable(test_verify_direct tests/test_verify_direct.cpp)
target_include_directories(test_verify_direct PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_verify_direct PRIVATE jpssl_cpu)

# Ed25519 keygen debug test
add_executable(test_debug_keygen tests/test_debug_keygen.cpp)
target_include_directories(test_debug_keygen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_debug_keygen PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ed25519 GE diagnostics
add_executable(diag_ge tests/diag_ge.cpp)
target_include_directories(diag_ge PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(diag_ge PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ed25519 trace test
add_executable(test_trace_ed tests/test_trace_ed.cpp)
target_include_directories(test_trace_ed PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_trace_ed PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ed25519 scalar mult test
add_executable(test_get_limbs tests/test_get_limbs.cpp)
target_include_directories(test_get_limbs PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_get_limbs PRIVATE jpssl_cpu OpenSSL::Crypto)

# Ladder debug test
add_executable(test_ladder_debug tests/test_ladder_debug.cpp)
target_include_directories(test_ladder_debug PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_ladder_debug PRIVATE jpssl_cpu OpenSSL::Crypto)

# OpenSSL 对比测试
add_executable(test_openssl_compare tests/test_openssl_compare.cpp)
target_include_directories(test_openssl_compare PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_openssl_compare PRIVATE jpssl_cpu jpssl_musa JPTEST::jptest OpenSSL::SSL OpenSSL::Crypto)

# AES-CCM 单元测试 (NIST SP 800-38C)
add_executable(test_aes_ccm tests/test_aes_ccm.cpp)
target_include_directories(test_aes_ccm PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_aes_ccm PRIVATE jpssl_cpu)

# ECDSA P-256 单元测试 (与 OpenSSL 互验)
add_executable(test_ecdsa tests/test_ecdsa.cpp)
target_include_directories(test_ecdsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_ecdsa PRIVATE jpssl_cpu OpenSSL::Crypto)

add_executable(test_ghash_debug tests/test_ghash_debug.cpp)
target_include_directories(test_ghash_debug PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_ghash_debug PRIVATE jpssl_cpu OpenSSL::Crypto)

# 密码套件吞吐量对比测试（jpssl vs OpenSSL，11 个套件）
add_executable(bench_cipher_suites tests/bench_cipher_suites.cpp)
target_include_directories(bench_cipher_suites PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(bench_cipher_suites PRIVATE jpssl_cpu jpssl_musa JPTEST::jptest OpenSSL::SSL OpenSSL::Crypto)

# 硬件加速路径性能对比
add_executable(bench_hardware_accel tests/bench_hardware_accel.cpp)
target_include_directories(bench_hardware_accel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(bench_hardware_accel PRIVATE jpssl_cpu jpssl_musa JPTEST::jptest OpenSSL::SSL OpenSSL::Crypto)
if(JP_ENABLE_AVX2)
    target_compile_definitions(bench_hardware_accel PRIVATE JP_AVX2)
endif()
target_include_directories(bench_cipher_suites PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(bench_cipher_suites PRIVATE jpssl_cpu jpssl_musa JPTEST::jptest OpenSSL::SSL OpenSSL::Crypto)

# SHA-512 三种实现效率对比
add_executable(bench_sha512 tests/bench_sha512.cpp)
target_include_directories(bench_sha512 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(bench_sha512 PRIVATE jpssl_cpu jpssl_musa OpenSSL::Crypto)
if(JP_ENABLE_AVX2)
    target_compile_definitions(bench_sha512 PRIVATE JP_AVX2)
endif()

# ═══════════════════════════════════════════════════════════════════════
#  安装规则
# ═══════════════════════════════════════════════════════════════════════
install(TARGETS jpssl_cpu jpssl_cpu_shared jpssl_musa jpssl_musa_shared
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/ DESTINATION include/jpssl
    FILES_MATCHING PATTERN "*.hpp"
)