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
    src/chacha20_poly1305.cpp
    src/rsa.cpp
    src/sha256.cpp
    src/hmac.cpp
    src/hkdf.cpp
    src/x25519.cpp
    src/tls.cpp
)

add_library(jpssl_cpu STATIC ${CPU_SOURCES})
target_include_directories(jpssl_cpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    target_compile_options(jpssl_cpu PRIVATE -maes -mavx2)
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
target_include_directories(jpssl_musa PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(jpssl_musa jpssl_cpu ${MUSA_LIBRARIES})

# ═══════════════════════════════════════════════════════════════════════
#  jpssl-test — 测试 & Benchmark 可执行文件
# ═══════════════════════════════════════════════════════════════════════
musa_add_executable(jpssl-test src/main.cpp)
target_include_directories(jpssl-test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MUSA_INCLUDE_DIRS}
)
target_link_libraries(jpssl-test jpssl_cpu jpssl_musa ${MUSA_LIBRARIES})
