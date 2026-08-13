# HTTPS + 国际 CT 示例（依赖 tls_socket 封装层）

add_executable(https_server https/https_server.cpp)
target_include_directories(https_server PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(https_server PRIVATE jpssl_cpu)

add_executable(https_client https/https_client.cpp)
target_include_directories(https_client PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(https_client PRIVATE jpssl_cpu)

# ── TLS socket 非阻塞 / 协程示例 ──────────────────────────────────────
add_executable(nonblocking_echo tls_socket/nonblocking_echo.cpp)
target_include_directories(nonblocking_echo PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(nonblocking_echo PRIVATE jpssl_cpu)

add_executable(coroutine_echo tls_socket/coroutine_echo.cpp)
target_include_directories(coroutine_echo PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(coroutine_echo PRIVATE jpssl_cpu)

# ── DTLS 服务器 / 客户端示例（dtls_connection，UDP）──────────────────
add_executable(dtls_server dtls/dtls_server.cpp)
target_include_directories(dtls_server PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dtls_server PRIVATE jpssl_cpu)

add_executable(dtls_client dtls/dtls_client.cpp)
target_include_directories(dtls_client PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dtls_client PRIVATE jpssl_cpu)
