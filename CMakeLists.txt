cmake_minimum_required(VERSION 3.20)

project(jpssl VERSION 1.0.0 LANGUAGES CXX)

# ── CTest ───────────────────────────────────────────────────────────────
include(CTest)
enable_testing()

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

# ── MUSA (实验性 GPU 加速, 默认关闭) ─────────────────────────────────
option(JP_ENABLE_MUSA "Enable MUSA GPU acceleration (experimental)" OFF)

if(JP_ENABLE_MUSA)
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
    message(STATUS "MUSA GPU 加速: 已禁用 (使用 -DJP_ENABLE_MUSA=ON 启用)")
endif()

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
    src/x509.cpp
    src/ed25519.cpp
    src/ed25519_avx2.cpp
    src/ed25519_avx512.cpp
    src/ed25519_batch_cpu.cpp
    src/ed25519_batch_dispatch.cpp
    src/aes_ccm.cpp
    src/ecdsa.cpp
    src/sm2.cpp
    src/sm3.cpp
    src/sm4.cpp
    src/sm4_gcm.cpp
    src/sm4_ccm.cpp
    src/sm4_gcm_dispatch.cpp
    src/rsa_batch_avx2.cpp
    src/rsa_batch_avx512.cpp
    src/rsa_batch_dispatch.cpp
    src/rsa_prim.cpp
    src/rsa_oaep.cpp
    src/rsa_pss.cpp
    src/rsa_schemes.cpp
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
if(JP_ENABLE_MUSA)
    target_compile_definitions(jpssl_cpu PRIVATE JP_MUSA)
    target_compile_definitions(jpssl_cpu_shared PRIVATE JP_MUSA)
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
#  jpssl-test — 测试 & Benchmark 可执行文件
# ═══════════════════════════════════════════════════════════════════════
if(JP_ENABLE_MUSA)
    musa_add_executable(jpssl-test src/main.cpp)
    target_include_directories(jpssl-test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${MUSA_INCLUDE_DIRS}
    )
    target_link_libraries(jpssl-test jpssl_cpu jpssl_musa ${MUSA_LIBRARIES})
else()
    add_executable(jpssl-test src/main.cpp)
    target_include_directories(jpssl-test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(jpssl-test jpssl_cpu)
endif()

# ═══════════════════════════════════════════════════════════════════════
#  命令行工具
# ═══════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════
#  单元测试 (CTest)
add_subdirectory(tests)
