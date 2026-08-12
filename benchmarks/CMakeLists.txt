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

    # ── 多长度 × 多实现 × OpenSSL 对比基准（非国密算法族）────────────
    add_executable(bench_sym_multi bench_sym_multi.cpp)
    target_include_directories(bench_sym_multi PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_sym_multi PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_hash_multi bench_hash_multi.cpp)
    target_include_directories(bench_hash_multi PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_hash_multi PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_sig_multi bench_sig_multi.cpp)
    target_include_directories(bench_sig_multi PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_sig_multi PRIVATE jpssl_cpu OpenSSL::Crypto)

    add_executable(bench_ecdh_multi bench_ecdh_multi.cpp)
    target_include_directories(bench_ecdh_multi PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
    target_link_libraries(bench_ecdh_multi PRIVATE jpssl_cpu OpenSSL::Crypto)

    # ── 按算法拆分的全量测试：每算法一程序（多实现 × 多长度 × OpenSSL）─
    set(BENCH_PER_ALGO
        bench_aes_ecb bench_aes_cbc bench_aes_gcm bench_chacha20
        bench_sha1 bench_sha256 bench_sha512_full bench_sha3 bench_hmac bench_hkdf
        bench_rsa bench_ecdsa bench_ed25519 bench_ed448
        bench_x25519 bench_x448 bench_ecdh_nist)
    foreach(bench_src ${BENCH_PER_ALGO})
        add_executable(${bench_src} ${bench_src}.cpp)
        target_include_directories(${bench_src} PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
        target_link_libraries(${bench_src} PRIVATE jpssl_cpu OpenSSL::Crypto)
    endforeach()

    # ── 非对齐（unaligned）测试对比组：非对齐长度 × 非对齐指针 × OpenSSL ─
    set(BENCH_UNALIGN
        bench_aes_ecb_unalign bench_aes_cbc_unalign bench_aes_gcm_unalign bench_chacha20_unalign
        bench_sha1_unalign bench_sha256_unalign bench_sha512_unalign bench_sha3_unalign
        bench_hmac_unalign bench_hkdf_unalign
        bench_rsa_unalign bench_ecdsa_unalign bench_ed25519_unalign bench_ed448_unalign
        bench_x25519_unalign bench_x448_unalign bench_ecdh_nist_unalign)
    foreach(bench_src ${BENCH_UNALIGN})
        add_executable(${bench_src} ${bench_src}.cpp)
        target_include_directories(${bench_src} PRIVATE ${BENCH_INCLUDE_DIR} ${BENCH_SRC_DIR})
        target_link_libraries(${bench_src} PRIVATE jpssl_cpu OpenSSL::Crypto)
    endforeach()
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
if(TARGET bench_sym_multi)
    add_test(NAME bench_sym_multi COMMAND bench_sym_multi)
endif()
if(TARGET bench_hash_multi)
    add_test(NAME bench_hash_multi COMMAND bench_hash_multi)
endif()
if(TARGET bench_sig_multi)
    add_test(NAME bench_sig_multi COMMAND bench_sig_multi)
endif()
if(TARGET bench_ecdh_multi)
    add_test(NAME bench_ecdh_multi COMMAND bench_ecdh_multi)
endif()
foreach(bench_src ${BENCH_PER_ALGO})
    if(TARGET ${bench_src})
        add_test(NAME ${bench_src} COMMAND ${bench_src})
    endif()
endforeach()
foreach(bench_src ${BENCH_UNALIGN})
    if(TARGET ${bench_src})
        add_test(NAME ${bench_src} COMMAND ${bench_src})
    endif()
endforeach()
