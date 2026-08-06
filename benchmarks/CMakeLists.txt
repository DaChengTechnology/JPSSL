# ═══════════════════════════════════════════════════════════════════════
#  jpssl benchmarks
#  由根 CMakeLists 的 JP_ENABLE_BENCH 开关控制 (默认 OFF)
#  启用: cmake -DJP_ENABLE_BENCH=ON ..
# ═══════════════════════════════════════════════════════════════════════

set(BENCH_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(BENCH_SRC_DIR     ${CMAKE_SOURCE_DIR}/src)

# ── RSA CPU vs GPU vs OpenSSL 综合基准 ──────────────────────────────────
add_executable(bench_rsa_cpu_gpu bench_rsa_cpu_gpu.cpp)
target_include_directories(bench_rsa_cpu_gpu PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
if(JP_ENABLE_MUSA)
    target_compile_definitions(bench_rsa_cpu_gpu PRIVATE JP_MUSA)
    target_link_libraries(bench_rsa_cpu_gpu PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES} OpenSSL::Crypto)
else()
    target_link_libraries(bench_rsa_cpu_gpu PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── RSA GPU 批量基准 (2048/4096 CPU vs MUSA GPU, 仅 MUSA 构建) ──────────
if(JP_ENABLE_MUSA)
    add_executable(bench_rsa_gpu bench_rsa_gpu.cpp)
    target_include_directories(bench_rsa_gpu PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_rsa_gpu PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES})
endif()

# ── SHA-512 CPU vs OpenSSL 基准 ─────────────────────────────────────────
add_executable(bench_sha512 bench_sha512.cpp)
target_include_directories(bench_sha512 PRIVATE ${BENCH_INCLUDE_DIR})
target_compile_definitions(bench_sha512 PRIVATE JP_AVX2)
if(JP_ENABLE_MUSA)
    target_compile_definitions(bench_sha512 PRIVATE JP_MUSA)
    target_link_libraries(bench_sha512 PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES} OpenSSL::Crypto)
else()
    target_link_libraries(bench_sha512 PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── 硬件加速 (AES-NI/AVX2/AVX512) 基准 ─────────────────────────────────
add_executable(bench_hardware_accel bench_hardware_accel.cpp)
target_include_directories(bench_hardware_accel PRIVATE ${BENCH_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/tests)
if(JP_ENABLE_MUSA)
    target_compile_definitions(bench_hardware_accel PRIVATE JP_MUSA)
    target_link_libraries(bench_hardware_accel PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES} OpenSSL::Crypto)
else()
    target_link_libraries(bench_hardware_accel PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── 密码套件基准 ────────────────────────────────────────────────────────
add_executable(bench_cipher_suites bench_cipher_suites.cpp)
target_include_directories(bench_cipher_suites PRIVATE ${BENCH_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/tests)
if(JP_ENABLE_MUSA)
    target_link_libraries(bench_cipher_suites PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES} OpenSSL::Crypto)
else()
    target_link_libraries(bench_cipher_suites PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# SM4 vs OpenSSL benchmark
add_executable(bench_sm4 bench_sm4.cpp)
target_include_directories(bench_sm4 PRIVATE ${BENCH_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/tests)
if(JP_ENABLE_MUSA)
    target_link_libraries(bench_sm4 PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES} OpenSSL::Crypto)
else()
    target_link_libraries(bench_sm4 PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# base64 scalar vs AVX2 vs AVX-512 benchmark
add_executable(bench_base64 bench_base64.cpp)
target_include_directories(bench_base64 PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
target_link_libraries(bench_base64 PRIVATE jpssl_cpu)

if(OpenSSL_FOUND)
    add_executable(bench_ed25519_ossl bench_ed25519_ossl.cpp)
    target_include_directories(bench_ed25519_ossl PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_ed25519_ossl PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_ecdsa_ossl bench_ecdsa_ossl.cpp)
    target_include_directories(bench_ecdsa_ossl PRIVATE ${BENCH_INCLUDE_DIR})
    target_link_libraries(bench_ecdsa_ossl PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_ecdh_batch bench_ecdh_batch.cpp)
    target_include_directories(bench_ecdh_batch PRIVATE ${BENCH_INCLUDE_DIR})
    target_link_libraries(bench_ecdh_batch PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_sm_ossl bench_sm_ossl.cpp)
    target_include_directories(bench_sm_ossl PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_sm_ossl PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_ed448_x448_ossl bench_ed448_x448_ossl.cpp)
    target_include_directories(bench_ed448_x448_ossl PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_ed448_x448_ossl PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_x25519_ossl bench_x25519_ossl.cpp)
    target_include_directories(bench_x25519_ossl PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_x25519_ossl PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── CTest 注册 ──────────────────────────────────────────────────────────
add_test(NAME bench_rsa_cpu_gpu    COMMAND bench_rsa_cpu_gpu)
if(TARGET bench_rsa_gpu)
    add_test(NAME bench_rsa_gpu    COMMAND bench_rsa_gpu)
endif()
add_test(NAME bench_sha512         COMMAND bench_sha512)
add_test(NAME bench_hardware_accel COMMAND bench_hardware_accel)
add_test(NAME bench_cipher_suites  COMMAND bench_cipher_suites)
add_test(NAME bench_sm4            COMMAND bench_sm4)
add_test(NAME bench_base64         COMMAND bench_base64)
if(TARGET bench_ed25519_ossl)
    add_test(NAME bench_ed25519_ossl COMMAND bench_ed25519_ossl)
endif()
if(TARGET bench_ecdsa_ossl)
    add_test(NAME bench_ecdsa_ossl COMMAND bench_ecdsa_ossl)
endif()
if(TARGET bench_sm_ossl)
    add_test(NAME bench_sm_ossl COMMAND bench_sm_ossl)
endif()
if(TARGET bench_ed448_x448_ossl)
    add_test(NAME bench_ed448_x448_ossl COMMAND bench_ed448_x448_ossl)
endif()
if(TARGET bench_x25519_ossl)
    add_test(NAME bench_x25519_ossl COMMAND bench_x25519_ossl)
endif()
