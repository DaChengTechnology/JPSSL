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

# coroutine_echo 依赖 C++20 coroutine，仅在标准 >= C++20 时构建
if(CMAKE_CXX_STANDARD GREATER_EQUAL 20)
    add_executable(coroutine_echo tls_socket/coroutine_echo.cpp)
    target_include_directories(coroutine_echo PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(coroutine_echo PRIVATE jpssl_cpu)
endif()
