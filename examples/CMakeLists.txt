# HTTPS + 国际 CT 示例（依赖 tls_socket 封装层）

add_executable(https_server https/https_server.cpp)
target_include_directories(https_server PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(https_server PRIVATE jpssl_cpu)

add_executable(https_client https/https_client.cpp)
target_include_directories(https_client PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(https_client PRIVATE jpssl_cpu)
