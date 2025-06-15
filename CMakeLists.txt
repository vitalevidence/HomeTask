cmake_minimum_required(VERSION 3.20)
project(Task)

set(CMAKE_CXX_STANDARD 23)

enable_testing()

find_package(OpenSSL REQUIRED)


set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -Werror")

set(TARGET_send stx_send)
set(TARGET_receive stx_recv)

if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL development files.")
endif()

add_library(server STATIC
    server_ctx.cpp server_ctx.h
    server.cpp server.h    
)

add_library(crypto STATIC
    cipher.cpp cipher.h
    common.cpp common.h
)

add_library(command STATIC
    command.cpp command.h
)

target_link_libraries(crypto PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(${TARGET_send} send.cpp client.cpp client.h)
target_link_libraries(${TARGET_send} PRIVATE crypto command)

add_executable(${TARGET_receive} receive.cpp)
target_link_libraries(${TARGET_receive} PRIVATE server crypto command)

add_subdirectory(tests)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/private.pem ${CMAKE_CURRENT_BINARY_DIR}/public.pem
    COMMAND ${CMAKE_COMMAND} -E echo "Generating RSA keys..."
    COMMAND openssl genpkey -algorithm RSA -out ${CMAKE_CURRENT_BINARY_DIR}/private.pem -pkeyopt rsa_keygen_bits:2048
    COMMAND openssl rsa -pubout -in ${CMAKE_CURRENT_BINARY_DIR}/private.pem -out ${CMAKE_CURRENT_BINARY_DIR}/public.pem
    COMMENT "Generating RSA private and public keys"
    VERBATIM
)

add_custom_target(generate_keys ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/private.pem ${CMAKE_CURRENT_BINARY_DIR}/public.pem
)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/demo.sh
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)

add_custom_target(demoScipt ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/demo.sh
)
