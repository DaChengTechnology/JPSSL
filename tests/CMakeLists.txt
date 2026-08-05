# ═══════════════════════════════════════════════════════════════════════
#  jpssl 单元测试
# ═══════════════════════════════════════════════════════════════════════

# ── 公共配置 ──────────────────────────────────────────────────────────────
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SRC_DIR     ${CMAKE_SOURCE_DIR}/src)

# OpenSSL 对比测试（源码 include <openssl/...>）：无 OpenSSL 时整块跳过
if(OpenSSL_FOUND)
    message(STATUS "tests: 构建 OpenSSL 对比测试")
else()
    message(STATUS "tests: OpenSSL 未找到，跳过 OpenSSL 对比测试")
endif()

# MUSA 库链接变量 (MUSA 关闭时为空)
# jpssl_cpu 在 JP_ENABLE_MUSA 下会编译进 chacha20 等的 MUSA 主机封装,
# 因此测试目标必须同时链接 jpssl_musa + MUSA 运行时
if(JP_ENABLE_MUSA)
    set(MUSA_LIBS jpssl_musa ${MUSA_LIBRARIES})
else()
    set(MUSA_LIBS)
endif()

# ── AES 全覆盖单元测试 (OpenSSL 对比) ────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_aes test_aes.cpp)
target_include_directories(test_aes PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_aes PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── AES 全模式 × 全密钥长度加解密验证 (OpenSSL 对比) ─────────────────────
# 覆盖：单块(hw/sw)、ECB、CBC、GCM(软件/auto/AVX2/AVX512)、CCM，
# 每个 AES-128/192/256，含 OpenSSL 交叉验证与篡改检测
if(OpenSSL_FOUND)
add_executable(test_aes_modes test_aes_modes.cpp)
target_include_directories(test_aes_modes PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_aes_modes PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── SHA3 单元测试 (OpenSSL 对比) ─────────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_sha3 test_sha3.cpp)
target_include_directories(test_sha3 PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_sha3 PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── SHA-512 单元测试 (OpenSSL 对比) ──────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_sha512 test_sha512.cpp)
target_include_directories(test_sha512 PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_sha512 PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── TLS 单元测试 ─────────────────────────────────────────────────────────
add_executable(test_tls test_tls.cpp)
target_include_directories(test_tls PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_tls PRIVATE jpssl_cpu ${MUSA_LIBS})

# ── TLS 1.3 X448/Ed448 握手测试 (OpenSSL 对比) ───────────────────────────
if(OpenSSL_FOUND)
add_executable(test_tls448 test_tls448.cpp)
target_include_directories(test_tls448 PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_tls448 PRIVATE jpssl_cpu ${MUSA_LIBS} OpenSSL::Crypto)
endif()

# ── TLS SM 国密套件测试 ─────────────────────────────────────────────────
add_executable(test_tls_sm test_tls_sm.cpp)
target_include_directories(test_tls_sm PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_tls_sm PRIVATE jpssl_cpu ${MUSA_LIBS})

# ── X.509 v3 证书测试 ────────────────────────────────────────────────────
add_executable(test_x509 test_x509.cpp)
target_include_directories(test_x509 PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_x509 PRIVATE jpssl_cpu ${MUSA_LIBS})

add_executable(test_ct test_ct.cpp)
target_include_directories(test_ct PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_ct PRIVATE jpssl_cpu ${MUSA_LIBS})

# Base64 (scalar vs AVX2 vs AVX512) 单测
add_executable(test_base64 test_base64.cpp)
target_include_directories(test_base64 PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_base64 PRIVATE jpssl_cpu ${MUSA_LIBS})

add_executable(test_tls_socket test_tls_socket.cpp)
target_include_directories(test_tls_socket PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_tls_socket PRIVATE jpssl_cpu ${MUSA_LIBS})

# ---- TLS stability / soak test (repeated handshakes + data transfer) ----
add_executable(test_tls_stability test_tls_stability.cpp)
target_include_directories(test_tls_stability PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_tls_stability PRIVATE jpssl_cpu ${MUSA_LIBS})

# ---- TLS large message auto-split / merge test ----
add_executable(test_tls_large_msg test_tls_large_msg.cpp)
target_include_directories(test_tls_large_msg PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_tls_large_msg PRIVATE jpssl_cpu ${MUSA_LIBS})

# ── ECDSA 单元测试 (OpenSSL 对比) ────────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_ecdsa test_ecdsa.cpp)
target_include_directories(test_ecdsa PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_ecdsa PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── SM 国密测试 (OpenSSL 对比) ───────────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_sm test_sm.cpp)
target_include_directories(test_sm PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_sm PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── AES-CCM 单元测试 ─────────────────────────────────────────────────────
add_executable(test_aes_ccm test_aes_ccm.cpp)
target_include_directories(test_aes_ccm PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_aes_ccm PRIVATE jpssl_cpu)

# ── GCM 测试 ─────────────────────────────────────────────────────────────
add_executable(test_gcm_simple test_gcm_simple.cpp)
target_include_directories(test_gcm_simple PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_gcm_simple PRIVATE jpssl_cpu)

# ── GHASH 调试测试 (OpenSSL 对比) ────────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_ghash    test_ghash.cpp)
add_executable(test_ghash_debug test_ghash_debug.cpp)
target_include_directories(test_ghash PRIVATE ${INCLUDE_DIR})
target_include_directories(test_ghash_debug PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_ghash PRIVATE jpssl_cpu OpenSSL::Crypto)
target_link_libraries(test_ghash_debug PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── Ed25519 测试 ─────────────────────────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_ed25519_rfc test_ed25519_rfc.cpp)
target_include_directories(test_ed25519_rfc PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed25519_rfc PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

add_executable(test_ed25519_debug test_ed25519_debug.cpp)
target_include_directories(test_ed25519_debug PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed25519_debug PRIVATE jpssl_cpu)

# ── Ed448 测试 ───────────────────────────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_ed448_rfc test_ed448_rfc.cpp)
target_include_directories(test_ed448_rfc PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed448_rfc PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

if(OpenSSL_FOUND)
add_executable(test_ed448_trace test_ed448_trace.cpp)
target_include_directories(test_ed448_trace PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed448_trace PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

add_executable(test_ed448_debug test_ed448_debug.cpp)
target_include_directories(test_ed448_debug PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed448_debug PRIVATE jpssl_cpu)

# ── Batch 测试 ───────────────────────────────────────────────────────────
add_executable(test_ed25519_batch test_ed25519_batch.cpp)
target_include_directories(test_ed25519_batch PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed25519_batch PRIVATE jpssl_cpu)

add_executable(test_ed448_batch test_ed448_batch.cpp)
target_include_directories(test_ed448_batch PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed448_batch PRIVATE jpssl_cpu)

# ── X25519 / X448 测试 ───────────────────────────────────────────────────
add_executable(test_x25519_rfc test_x25519_rfc.cpp)
target_include_directories(test_x25519_rfc PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_x25519_rfc PRIVATE jpssl_cpu)

add_executable(test_x448_rfc test_x448_rfc.cpp)
target_include_directories(test_x448_rfc PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_x448_rfc PRIVATE jpssl_cpu)

add_executable(test_x448_batch test_x448_batch.cpp)
target_include_directories(test_x448_batch PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_x448_batch PRIVATE jpssl_cpu)

# ── X25519 OpenSSL 对比 (OpenSSL 对比) ───────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_x25519_ossl test_x25519_ossl.cpp)
target_include_directories(test_x25519_ossl PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_x25519_ossl PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── OpenSSL 比较测试 (OpenSSL 对比) ─────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_openssl_compare test_openssl_compare.cpp)
target_include_directories(test_openssl_compare PRIVATE ${INCLUDE_DIR})
target_link_libraries(test_openssl_compare PRIVATE jpssl_cpu ${MUSA_LIBS} OpenSSL::Crypto OpenSSL::SSL)
endif()

# ── 验证测试 ─────────────────────────────────────────────────────────────
if(OpenSSL_FOUND)
add_executable(test_verify_direct test_verify_direct.cpp)
target_include_directories(test_verify_direct PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_verify_direct PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

if(OpenSSL_FOUND)
add_executable(test_ossl_verify test_ossl_verify.cpp)
target_include_directories(test_ossl_verify PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ossl_verify PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── 诊断测试 ─────────────────────────────────────────────────────────────
add_executable(diag_ge diag_ge.cpp)
target_include_directories(diag_ge PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(diag_ge PRIVATE jpssl_cpu)

if(OpenSSL_FOUND)
add_executable(test_ed_mini test_ed_mini.cpp)
target_include_directories(test_ed_mini PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_ed_mini PRIVATE jpssl_cpu OpenSSL::Crypto)
endif()

# ── Debug 测试 ───────────────────────────────────────────────────────────
add_executable(test_debug_keygen test_debug_keygen.cpp)
target_include_directories(test_debug_keygen PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_debug_keygen PRIVATE jpssl_cpu)

add_executable(test_trace_ed test_trace_ed.cpp)
target_include_directories(test_trace_ed PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_trace_ed PRIVATE jpssl_cpu)

# ── Field element 测试 ───────────────────────────────────────────────────
add_executable(test_fe448 test_fe448.cpp)
target_include_directories(test_fe448 PRIVATE ${INCLUDE_DIR} ${SRC_DIR})
target_link_libraries(test_fe448 PRIVATE jpssl_cpu)

# ── Benchmark ────────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════════
#  CTest 注册
# ═══════════════════════════════════════════════════════════════════════
add_test(NAME test_aes           COMMAND test_aes)
add_test(NAME test_aes_ccm       COMMAND test_aes_ccm)
add_test(NAME test_aes_modes     COMMAND test_aes_modes)
add_test(NAME test_gcm_simple    COMMAND test_gcm_simple)
if(OpenSSL_FOUND)
add_test(NAME test_sha3          COMMAND test_sha3)
add_test(NAME test_sha512        COMMAND test_sha512)
endif()
add_test(NAME test_tls           COMMAND test_tls)
if(OpenSSL_FOUND)
add_test(NAME test_tls448        COMMAND test_tls448)
endif()
add_test(NAME test_tls_sm        COMMAND test_tls_sm)
add_test(NAME test_x509          COMMAND test_x509)
add_test(NAME test_ct            COMMAND test_ct)
add_test(NAME test_base64        COMMAND test_base64)
add_test(NAME test_tls_socket    COMMAND test_tls_socket)
add_test(NAME test_tls_stability COMMAND test_tls_stability)
add_test(NAME test_tls_large_msg COMMAND test_tls_large_msg)
if(OpenSSL_FOUND)
add_test(NAME test_ed25519_rfc   COMMAND test_ed25519_rfc)
add_test(NAME test_ed448_rfc     COMMAND test_ed448_rfc)
add_test(NAME test_ed448_trace   COMMAND test_ed448_trace)
add_test(NAME test_x25519_ossl   COMMAND test_x25519_ossl)
add_test(NAME test_ecdsa         COMMAND test_ecdsa)
add_test(NAME test_sm            COMMAND test_sm)
add_test(NAME test_ghash_debug   COMMAND test_ghash_debug)
endif()
add_test(NAME test_ed25519_debug COMMAND test_ed25519_debug)
add_test(NAME test_ed448_debug   COMMAND test_ed448_debug)
add_test(NAME test_ed448_batch   COMMAND test_ed448_batch)
add_test(NAME test_x25519_rfc    COMMAND test_x25519_rfc)
add_test(NAME test_x448_rfc      COMMAND test_x448_rfc)
add_test(NAME test_x448_batch    COMMAND test_x448_batch)
