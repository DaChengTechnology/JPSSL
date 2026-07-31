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
    target_link_libraries(bench_sha512 PRIVATE jpssl_cpu jpssl_musa ${MUSA_LIBRARIES} OpenSSL::Crypto)
else()
    target_link_libraries(bench_sha512 PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── 硬件加速 (AES-NI/AVX2/AVX512) 基准 ─────────────────────────────────
add_executable(bench_hardware_accel bench_hardware_accel.cpp)
target_include_directories(bench_hardware_accel PRIVATE ${BENCH_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/tests)
if(JP_ENABLE_MUSA)
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

# ── CTest 注册 ──────────────────────────────────────────────────────────
add_test(NAME bench_rsa_cpu_gpu    COMMAND bench_rsa_cpu_gpu)
add_test(NAME bench_rsa_gpu        COMMAND bench_rsa_gpu)
add_test(NAME bench_sha512         COMMAND bench_sha512)
add_test(NAME bench_hardware_accel COMMAND bench_hardware_accel)
add_test(NAME bench_cipher_suites  COMMAND bench_cipher_suites)
