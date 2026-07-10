cmake_minimum_required(VERSION 3.20)

project(jpssl VERSION 1.0.0 LANGUAGES CXX)

# ── C++20 ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── x86 硬件加速 ──────────────────────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -mavx2")
endif()

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
    src/hmac.cpp
    src/hkdf.cpp
    src/x25519.cpp
    src/tls.cpp
    src/ed25519.cpp
    src/ecdsa.cpp
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
endif()

# ═══════════════════════════════════════════════════════════════════════
#  libjpssl_musa — MUSA GPU 加速库 (AES, ChaCha20, RSA GPU kernels)
# ═══════════════════════════════════════════════════════════════════════
set(MUSA_SOURCES
    src/aes_musa.cpp
    src/rsa_musa.cpp
)

set(MUSA_KERNELS
    src/aes_gpu.mu
    src/chacha20_gpu.mu
    src/rsa_gpu.mu
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

# TLS 单元测试
add_executable(test_tls tests/test_tls.cpp)
target_include_directories(test_tls PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_tls PRIVATE jpssl_cpu JPTEST::jptest)

# OpenSSL 对比测试
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
add_executable(test_openssl_compare tests/test_openssl_compare.cpp)
target_include_directories(test_openssl_compare PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(test_openssl_compare PRIVATE jpssl_cpu jpssl_musa JPTEST::jptest OpenSSL::SSL OpenSSL::Crypto)
else()
    message(STATUS "OpenSSL not found — skipping test_openssl_compare")
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