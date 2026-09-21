# Host (native) build of the SmartKey protocol unit tests.
#
# The smartkey_proto component is deliberately free of ESP-IDF dependencies so it
# can be compiled straight against upstream mbedTLS on the development machine:
#
#   ./run_tests.sh
#
cmake_minimum_required(VERSION 3.16)
project(smartkey_host_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror -Wno-unused-parameter)

if(NOT DEFINED MBEDTLS_DIR)
    message(FATAL_ERROR "Pass -DMBEDTLS_DIR=<path to mbedtls source> (run_tests.sh does this)")
endif()

# Build only what we need from mbedTLS: no tests, no programs.
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
add_subdirectory(${MBEDTLS_DIR} ${CMAKE_BINARY_DIR}/mbedtls EXCLUDE_FROM_ALL)

set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../components/smartkey_proto)

add_executable(test_smartkey_proto
    test_smartkey_proto.c
    ${PROTO_DIR}/smartkey_proto.c
    ${PROTO_DIR}/smartkey_crypto.c
    ${PROTO_DIR}/smartkey_rearm.c
    ${PROTO_DIR}/smartkey_proximity.c
)
target_include_directories(test_smartkey_proto PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROTO_DIR}/include
)
target_link_libraries(test_smartkey_proto PRIVATE mbedcrypto)

enable_testing()
add_test(NAME smartkey_proto COMMAND test_smartkey_proto)
